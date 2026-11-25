"""Three- and two-candidate row groups with separate public counter phases, and a matrix control."""
from schedule import body, once, replace_body

def group_prefix(s,r):
    if r not in (3,4):raise ValueError("3 or 4 triple rows")
    sig="unsigned can_look_ahead;"
    s=once(s,"uint8_t *output;","uint8_t *output;\n    uint8_t *extra;")
    s=once(s,"sizeof(mld_polymat87),0*768,2*768",f"sizeof(mld_polymat87),{r*768+1024},2*768")
    a,b=body(s,"shared_route_attempt")
    s=s[:a]+"\n    s->look.extra=s->slot[D_ACACHE];\n"+s[a:]
    return replace_body(s,"lc_pair_product",f"""
    /* The public row partitions consume independently; every created future row is read
       before its slot is reclaimed. Rejection predicates and commitment order are unchanged. */
    const unsigned trial=y->kappa/7u,phase3=trial%3u,phase2=trial%2u;
    const unsigned limit=(65535u-7u)/7u;
    const unsigned ahead=look->can_look_ahead;
    const unsigned three=phase3==0 && ahead && trial+2u<limit &&
                         (uint32_t)y->kappa+3u*7u-1u<=65535u;
    for(unsigned k=0;k<8;k++){{
        unsigned phase=k<{r}?phase3:phase2;
        if(phase){{
            const uint8_t *saved=phase==2?look->extra+k*768:
                 (k<6?look->output+k*768:look->pending+(k-6)*768);
            memcpy(rows+k*768,saved,768);
        }}
    }}
    if(phase3 && phase2)return;
    mld_poly *third=(mld_poly*)(look->extra+{r}*768);
    uint8_t seed[34];memcpy(seed,mat->rho,32);
    for(unsigned col=0;col<7;col++){{
        mld_yvec_get_poly_lazy87(current,y,col);lcbase_poly_ntt(current);
        if(ahead){{
            lcbase87_poly_uniform_gamma1(&mat->cur,y->rhoprime,(uint16_t)(y->kappa+7+col));
            lcbase_poly_ntt(&mat->cur);
        }}
        if(three){{
            lcbase87_poly_uniform_gamma1(third,y->rhoprime,(uint16_t)(y->kappa+14+col));
            lcbase_poly_ntt(third);
        }}
        seed[32]=(uint8_t)col;
        for(unsigned k=0;k<8;k++){{
            if((k<{r}?phase3:phase2)!=0)continue;
            uint8_t *r0=rows+k*768;
            uint8_t *r1=(k<6?look->output+k*768:look->pending+(k-6)*768);
            uint8_t *r2=k<{r}?look->extra+k*768:(uint8_t*)0;
            seed[33]=(uint8_t)k;
            mld_shake128ctx state;uint8_t block[168];
            lcbase_shake128_init(&state);lcbase_shake128_absorb(&state,seed,34);
            lcbase_shake128_finalize(&state);
            unsigned count=0;
            while(count<256){{
                lcbase_shake128_squeeze(block,168,&state);
                for(unsigned j=0;j<168 && count<256;j+=3){{
                    uint32_t a=(block[j]|((uint32_t)block[j+1]<<8)|((uint32_t)block[j+2]<<16))&0x7fffffu;
                    if(a>=8380417u)continue;
                    unsigned i=lc_matrix_native_index(count++);
                    lc_pair_add(r0,current,i,(int32_t)a,col==0);
                    if(ahead)lc_pair_add(r1,&mat->cur,i,(int32_t)a,col==0);
                    if(three && r2)lc_pair_add(r2,third,i,(int32_t)a,col==0);
                }}
            }}
            lcbase_shake128_release(&state);mld_zeroize(block,sizeof(block));
        }}
    }}
    mld_zeroize(seed,sizeof(seed));
""")

def matrix_prefix(s,n=5,partial=0):
    s=once(s,"uint8_t *output;","uint8_t *output;\n    uint8_t *extra;")
    rembytes=(3*partial+31)//32*32
    s=once(s,"sizeof(mld_polymat87),0*768,2*768",f"sizeof(mld_polymat87),{n*768+rembytes},2*768")
    a,b=body(s,"shared_route_attempt")
    s=s[:a]+"\n    s->look.extra=s->slot[D_ACACHE];\n"+s[a:]
    a,b=body(s,"lc_pair_product")
    code=s[a:b]
    mark="mld_shake128ctx state;"
    code=once(code,mark,f"""
      uint8_t *cache=slot<{n}?look->extra+768*slot:(uint8_t*)0;
      if(cache && y->kappa){{
          for(unsigned i=0;i<256;i++){{
              uint8_t *d=cache+3*i;
              uint32_t a=d[0]|((uint32_t)d[1]<<8)|((uint32_t)d[2]<<16);
              lc_pair_add(r0,current,i,(int32_t)a,l==0);
              if(saved)lc_pair_add(r1,&mat->cur,i,(int32_t)a,l==0);
          }}
          continue;
      }}
      """+mark)
    mark="unsigned i=lc_matrix_native_index(count++);"
    code=once(code,mark,mark+"""
          if(cache){uint8_t *d=cache+3*i;d[0]=(uint8_t)a;d[1]=(uint8_t)(a>>8);d[2]=(uint8_t)(a>>16);}""")
    if partial:
        block="lc_pair_add(r0,current,i,(int32_t)a,l==0);"
        pos=code.rindex(block)
        code=code[:pos]+f"""
          if(slot=={n} && i<{partial}){{
            uint8_t *d=look->extra+768*{n}+3*i;
            if(y->kappa)a=(uint32_t)d[0]|((uint32_t)d[1]<<8)|((uint32_t)d[2]<<16);
            else{{d[0]=(uint8_t)a;d[1]=(uint8_t)(a>>8);d[2]=(uint8_t)(a>>16);}}
          }}
          """+code[pos:]
    return s[:a]+code+s[b:]
