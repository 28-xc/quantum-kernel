"""Schedule specialization for the hash-bound, already-expanded Cortex-M4 production kernel."""
import re

PARAMS = {44:(4,4,32,576,2420,608),65:(6,5,48,640,3309,640),87:(8,7,64,640,4627,640)}
# K, L, challenge octets, encoded z octets, signature octets, stored low-bit row octets

def once(s, a, b):
    if s.count(a) != 1:
        raise ValueError(f"expected one match for {a[:100]!r}, got {s.count(a)}")
    return s.replace(a,b)

def body(s, name):
    m = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", s)
    if not m:
        raise ValueError("function missing: "+name)
    start = m.end()
    depth = 1
    for i in range(start,len(s)):
        if s[i] == "{": depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0: return start,i
    raise ValueError(name)

def replace_body(s,name,new):
    a,b=body(s,name)
    return s[:a]+"\n"+new.strip()+"\n"+s[b:]

def cache_rows(p, retained):
    k,l,cb,zb,sn,row = PARAMS[p]
    sig_cols=sn//768
    assert sig_cols==l-1
    # The hash state and compact high-bit flags share working space only after squeezing.
    # Low-bit rows begin after this state/bitmap overlay; the last missing mask uses 768 arena bytes.
    fixed=1280
    return fixed+768+retained*row

def low_kernel(s,p,retained):
    k,l,cb,zb,sn,row = PARAMS[p]
    assert 1 <= retained <= k
    size=cache_rows(p,retained)
    s=once(s,"bytes[sizeof(mld_poly)+256]","bytes["+str(size)+"]")
    s=once(s,"uint16_t kappa;\n} mld_yvec_lazy"+str(p), "uint16_t kappa;\n  uint8_t *sig_columns, *arena_column;\n} mld_yvec_lazy"+str(p))
    a,b=body(s,"lc_stream_y_row")
    s=s[:a]+f"""
  uint8_t seed[34];
  memcpy(seed,mat->rho,32);
  seed[33]=(uint8_t)row;
  for(unsigned col=0;col<{l};col++){{
    const uint8_t *v=col<{l-1}?y->sig_columns+768*col:y->arena_column;
    seed[32]=(uint8_t)col;
    lc_fused_matrix_v(out,v,seed,col==0);
  }}
  lcbase_poly_reduce(out);lcbase_poly_invntt_tomont(out);lcbase_poly_caddq(out);
  mld_zeroize(seed,sizeof(seed));
  (void)scratch;
"""+s[b:]
    name="mld_attempt_signature_generation"+str(p)
    a,b=body(s,name)
    f=s[a:b]
    f=once(f,"lc_stream_hash(challenge_bytes,mu,w0_storage,mat,y,scratch_w);",f"""
  y->sig_columns=sig;
  y->arena_column=w0_storage->bytes+1280;
  for(unsigned col=0;col<{l};col++){{
    mld_yvec_get_poly_lazy{p}(scratch_w,y,col);
    lcbase_poly_ntt(scratch_w);
    lc_pack_matrix_ntt24(col<{l-1}?sig+768*col:y->arena_column,scratch_w);
  }}
  lc_stream_hash(challenge_bytes,mu,w0_storage,mat,y,scratch_w);""")
    f=once(f,"mld_compute_pack_z"+str(p)+"(sig,", "mld_compute_pack_z"+str(p)+"(((void*)0),")
    old=f"lc_stream_y_row(t,mat,y,scratch_w,k);lcbase{p}_poly_decompose(scratch_w,t);"
    keep=f"if(k<{retained}){{\n      lc_unpack_w0_row(t,w0+2048+k*{row});\n    }}else{{\n      "+old
    pat=r"lc_stream_y_row\(t,mat,y,scratch_w,k\);lcbase\d+_poly_decompose\(scratch_w,t\);\s*memset\(flags,0,32\);\s*for\(unsigned j=0;j<256;j\+\+\)flags\[j/8\]\|=.*?;"
    m=re.search(pat,f)
    if m is None:raise ValueError("low reconstruction boundary missing")
    f=f[:m.start()]+keep+f[m.start()+len(old):m.end()]+"\n    }"+f[m.end():]
    marker=f"lcbase{p}_pack_sig_c(sig, challenge_bytes);"
    f=once(f,marker,f"""
  ret=mld_compute_pack_z{p}(sig,cp,s1hat,y,t,scratch_w,lc_canonical_secret);
  if(ret)goto cleanup;
  """+marker)
    s=s[:a]+f+s[b:]
    mark=f"lcbase{p}_pack_sig_z(sig, z, column);"
    s=once(s,mark,"if(sig) "+mark)
    # Save flags for retained rows into separate spare bytes at the end of each stored row?
    # Flags must survive the 208-byte hash state until finalize. Place them next to the low row
    # during the hash, then transfer to the 256-byte hint bitmap once the state is retired.
    # The low row and flags are jointly stored; layout returned by geometry accounts for both.
    newsize=size+retained*32
    s=once(s,"bytes["+str(size)+"]","bytes["+str(newsize)+"]")
    s=once(s,f"lc_unpack_w0_row(t,w0+2048+k*{row});",f"lc_unpack_w0_row(t,w0+2048+k*{row+32});\n      memcpy(flags,w0+2048+k*{row+32}+{row},32);")
    a,b=body(s,"lc_stream_hash")
    f=s[a:b]
    anchor=f"lc_stream_y_row(w,mat,y,scratch,k);lcbase{p}_poly_decompose(scratch,w);"
    f=once(f,anchor,anchor+f"""
    if(k<{retained}){{
      uint8_t *low=store->bytes+2048+k*{row+32};
      uint8_t *flags=low+{row};
      lc_pack_w0_row(low,w);memset(flags,0,32);
      for(unsigned j=0;j<256;j++) flags[j/8]|=(uint8_t)((uint32_t)(scratch->coeffs[j]!=0)<<(j%8));
    }}""")
    return s[:a]+f+s[b:]

def fast_kernel(s,p,future,matrix,secret_cache=0):
    k,l,cb,zb,sn,row = PARAMS[p]
    alias=min(future,sn//768)
    # Split at complete rows. The serialized signature cannot be overwritten by failed attempts.
    a,b=body(s,"lc_pair_product")
    f=s[a:b]
    base_f=int(re.search(r"row_bytes=(\d+)\*",f)[1])
    partial=future<k
    tail=f"""
    uint8_t seed[34];
    memcpy(seed,mat->rho,32);
    for(unsigned col=0;col<{l};col++){{
      mld_yvec_get_poly_lazy{p}(current,y,col);lcbase_poly_ntt(current);
      lc_stream_transform_order(current); seed[32]=(uint8_t)col;
      for(unsigned r={future};r<{k};r++){{
        seed[33]=(uint8_t)r;
        lc_fused_matrix_y(rows+768*r,current,seed,col==0);
      }}
    }}
    mld_zeroize(seed,sizeof(seed));
""" if partial else ""
    lo=f.index("  _Static_assert")
    hi=f.index("  const unsigned ahead=")
    prefix=f"""
  _Static_assert({alias}*768<={sn},"signature scratch exceeded");
  if(look->pending_nonce==y->kappa){{
    memcpy(rows,look->output,768*{alias});
"""
    if future>alias:prefix+=f"    memcpy(rows+768*{alias},look->pending,768*{future-alias});\n"
    prefix+="    look->pending_nonce=4294967295U;\n"+tail+"    return;\n  }\n"
    f=f[:lo]+prefix+f[hi:]
    f=once(f,f"unsigned saved=ahead && k<{base_f};",f"unsigned saved=ahead && k<{future};")
    f=once(f,"saved ? look->pending+k*(3*256) : ((void*)0)",f"saved ? (k<{alias}?look->output+768*k:look->pending+768*(k-{alias})) : ((void*)0)")
    s=s[:a]+f+s[b:]
    s,n=re.subn(r"(uint8_t \*pending;\s*uint32_t pending_nonce;\s*unsigned can_look_ahead;)",r"\1\n    uint8_t *output;",s)
    assert n==1
    # Single scope in the common sign driver supplies the output address and next nonce guard.
    old=re.search(r"sizeof\(mld_polymat"+str(p)+r"\),(\d+)\*768,(\d+)\*768",s)
    assert old and int(old[2])==base_f
    base_matrix=int(old[1])
    s=once(s,old[0],f"sizeof(mld_polymat{p}),{matrix}*768,{future-alias}*768")
    if secret_cache:
        assert secret_cache<=l
        s=once(s,f"sizeof(mld_polymat{p}),{matrix}*768,",f"sizeof(mld_polymat{p}),{matrix+secret_cache}*768,")
        a,b=body(s,"shared_route_matrix")
        f=s[a:b]+f"""
    mld_poly *scratch=&mat->cur;
    uint8_t *key_ntt=(uint8_t*)s->slot[D_ACACHE]+{matrix*768};
    for(unsigned i=0;i<{secret_cache};i++){{
      mld_sk_s1hat_get_poly_lazy{p}(scratch,s->slot[D_S1],i);
      lc_pack_ntt24(key_ntt+768*i,scratch);
    }}
"""
        s=s[:a]+f+s[b:]
        a,b=body(s,"shared_route_attempt")
        f=s[a:b]
        f="    s->look.key_ntt=(uint8_t*)s->slot[D_ACACHE]+"+str(matrix*768)+";\n"+f
        s=s[:a]+f+s[b:]
        s=once(s,"uint8_t *output;","uint8_t *output;\n    const uint8_t *key_ntt;")
        sig=re.search(r"(static int mld_compute_pack_z"+str(p)+r"\()uint8_t",s)
        assert sig;s=s[:sig.end()-7]+"const uint8_t *key_ntt,uint8_t"+s[sig.end():]
        line=f"mld_sk_s1hat_get_poly_lazy{p}(z, s1hat, column);"
        s=once(s,line,f"""
      if(column<{secret_cache}){{
        const uint8_t *packed=key_ntt+768*column;
        for(unsigned j=0;j<256;j++) z->coeffs[j]=lc_load_signed24(packed+3*j);
      }}else {line}""")
    if matrix!=base_matrix:
        oldexpr=f"(({base_matrix} < {k}*{l}) ? {base_matrix} : {k}*{l})"
        assert oldexpr in s and base_matrix
        s=s.replace(oldexpr,f"(({matrix} < {k}*{l}) ? {matrix} : {k}*{l})")
    z=f"lcbase{p}_pack_sig_z(sig, z, column);"
    s=once(s,z,"if(sig) "+z)
    a,b=body(s,"mld_attempt_signature_generation"+str(p))
    f=s[a:b]
    f=once(f,"mld_compute_pack_z"+str(p)+"(sig,", "mld_compute_pack_z"+str(p)+"(((void*)0),")
    marker=f"lcbase{p}_pack_sig_c(sig, challenge_bytes);"
    f=once(f,marker,f"ret=mld_compute_pack_z{p}(sig,cp,s1hat,y,t,scratch_w,lc_canonical_secret);\n  if(ret)goto cleanup;\n  "+marker)
    if secret_cache:f=f.replace(f"mld_compute_pack_z{p}(",f"mld_compute_pack_z{p}(look->key_ntt,")
    return s[:a]+f+s[b:]

def key_verify_columns(s,p,compact_stack=False):
    """Within the signing envelope, retain independent keygen/verification transform prefixes."""
    k,l,_,_,_,_=PARAMS[p]
    key_cols=min(l,6);ver_cols=min(l,5 if compact_stack else 4) if p==87 else l
    declaration=f"""
static void dsa_prepare_column(void *storage,void *temp,const uint8_t *seed,unsigned col,uint8_t *packed){{
  mld_poly *t=temp;
  lcbase{p}_poly_uniform_eta(t,seed,(uint8_t)col);
  lcbase{p}_polyeta_pack(packed,t);
  if(col<{key_cols}){{
    lcbase_poly_ntt(t);
    lc_pack_matrix_ntt24((uint8_t*)storage+768*col,t);
  }}
}}
"""
    at=s.index("static void dsa_key_row(")
    s=s[:at]+declaration+s[at:]
    keytail=f"""
    else{{
      lcbase{p}_polyeta_unpack(t,sk+128+col*{96 if p!=65 else 128});
      lcbase_poly_ntt(t);lc_fused_matrix_dense(row,t,seed,col==0);
    }}""" if key_cols<l else ""
    s=replace_body(s,"dsa_key_row",f"""
    mld_polymat{p} *matrix=mat; uint8_t seed[34];
    memcpy(seed,matrix->rho,32);seed[33]=(uint8_t)i;
    for(unsigned col=0;col<{l};col++){{
      seed[32]=(uint8_t)col;
      if(col<{key_cols})lc_fused_matrix_v(row,(uint8_t*)s+768*col,seed,col==0);
      {keytail}
    }}
    lcbase_poly_reduce(row);mld_zeroize(seed,sizeof(seed));(void)rho;
""")
    a,b=body(s,"dsa_z")
    f=once(s[a:b],"(void)z;(void)i;return 0;",f"if(i<{ver_cols}){{lcbase_poly_ntt(t);lc_pack_matrix_ntt24((uint8_t*)z+768*i,t);}}return 0;")
    s=s[:a]+f+s[b:]
    tail=f"""
      else{{
        lcbase{p}_polyz_unpack(t,sig+{PARAMS[p][2]}+col*{PARAMS[p][3]});
        lcbase_poly_ntt(t);lc_fused_matrix_dense(w,t,seed,col==0);
      }}""" if ver_cols<l else ""
    s=once(s,"lc_stream_z_row(w,mat,sig,t,i);(void)z;",f"""
    mld_polymat{p} *matrix=mat; uint8_t seed[34];
    memcpy(seed,matrix->rho,32);seed[33]=(uint8_t)i;
    for(unsigned col=0;col<{l};col++){{
      seed[32]=(uint8_t)col;
      if(col<{ver_cols})lc_fused_matrix_v(w,(uint8_t*)z+768*col,seed,col==0);
      {tail}
    }}
    lcbase_poly_reduce(w);mld_zeroize(seed,sizeof(seed));""")
    s=once(s,"{128,34,64,1,sizeof(mld_polymat",f"{{128,34,64,{768*key_cols},sizeof(mld_polymat")
    s=once(s,"{sizeof(mld_shake256ctx),64,1,sizeof(mld_poly)",f"{{sizeof(mld_shake256ctx),64,{768*ver_cols},sizeof(mld_poly)")
    return once(s,"lcbase_shake256,dsa_init_mat,0,dsa_key_row","lcbase_shake256,dsa_init_mat,dsa_prepare_column,dsa_key_row")
