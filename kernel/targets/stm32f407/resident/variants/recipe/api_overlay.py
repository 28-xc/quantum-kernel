def once(s,old,new):
    assert s.count(old)==1,('source rule changed',old);return s.replace(old,new)
def render(s):
    at=s.index('static int result(')
    s=s[:at]+'''extern int lc_f407_fits(int,int,const void *,size_t);
static int lc_target_workspace(lc_context *ctx,int p,int op) {
  if (lc_f407_fits(p,op,ctx->workspace,ctx->workspace_bytes)) return LC_OK;
  ctx->allocation_failures=1;
  return ctx->last_error=LC_E_WORKSPACE;
}
'''+s[at:]
    for op,entry in ((0,' if(!e){if(kem(p))'),(1,' if(!e){lc_arena_init'),(1,' if(!e){raw=lc_dsa_sign_seed')):
        s=once(s,entry,f' if(!e)e=lc_target_workspace(c,p,{op});\n'+entry)
    old_line=' lc_arena_init(&a,c->workspace,c->workspace_bytes);raw=lc_mlk_call(p,2,ss,NULL,ct,sk,&a);e=result(c,raw,&a,NULL);'
    s=once(s,old_line,' e=lc_target_workspace(c,p,2);if(!e){'+old_line.strip()+'}')
    entry=' raw=lc_dsa_verify(p,sig';s=once(s,entry,' if((e=lc_target_workspace(c,p,2)))return e;\n'+entry)
    return s
