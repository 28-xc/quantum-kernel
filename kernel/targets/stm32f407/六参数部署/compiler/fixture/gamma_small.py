def small(src,p):
    # Each aligned word load uses memcpy so that strict aliasing and byte alignment are explicit.
    spec={44:(4,18,9),65:(2,20,5),87:(2,20,5)}
    g,bits,span=spec[p]
    head='static void lc_expand_gamma(int32_t *out,unsigned bits,int32_t gamma) {'
    assert src.count(head)==1
    a=src.index(head);b=src.index('\n}',a)+2
    lines=[head,'  (void)bits;','  unsigned char *bytes=(unsigned char*)out;',f'  for(unsigned block={256//g};block-- >0;){{',f'    const unsigned char *in=bytes+block*{span};','    uint32_t a; __builtin_memcpy(&a,in,4);']
    if g==4:lines+=['    uint32_t b; __builtin_memcpy(&b,in+4,4);','    const uint32_t c=in[8];']
    else:lines+=['    const uint32_t b=in[4];']
    names=['a','b','c']
    for i in range(g-1,-1,-1):
        idx,s=divmod(i*bits,32);expr=names[idx] if s==0 else '('+names[idx]+'>>'+str(s)+')'
        if s+bits>32:expr='('+expr+'|('+names[idx+1]+'<<'+str(32-s)+'))'
        lines.append(f'    out[block*{g}+{i}]=gamma-(int32_t)({expr}&{(1<<bits)-1}u);')
    lines+=['  }','}']
    return src[:a]+'\n'.join(lines)+src[b:]
