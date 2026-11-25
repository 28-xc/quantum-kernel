/* Separate instrumentation: it does not alter the primary serialized timer. */
#define main serialized_reference_main
#include "driver.c"
#undef main

typedef struct { uint64_t import,setup,operation,export,release,total; } PHASES;
static int diagnostic_call(OS *o,int p,int op,const lc_sizes *z,
                           const TEST_INPUT *in,OUTPUT *out,PHASES *d) {
 EVP_PKEY *k=NULL;EVP_PKEY_CTX *c=NULL;int ok=0,encoding=1,mu=0;
 size_t n=0,n2=0;uint64_t t[6];t[0]=ticks();
 if(op==0){
  OSSL_PARAM params[]={OSSL_PARAM_octet_string("seed",(void*)in->coins,p>100?64:32),OSSL_PARAM_END};
  t[1]=t[0]; /* No serialized key input exists for key generation. */
  c=EVP_PKEY_CTX_new_from_name(o->ctx,o->algorithm,"provider=default");
  ok=c&&EVP_PKEY_keygen_init(c)>0&&EVP_PKEY_CTX_set_params(c,params)>0;
  t[2]=ticks();ok=ok&&EVP_PKEY_generate(c,&k)>0;t[3]=ticks();
  ok=ok&&EVP_PKEY_get_octet_string_param(k,"pub",out->pk,z->public_key,&n)>0&&n==z->public_key
       &&EVP_PKEY_get_octet_string_param(k,"priv",out->sk,z->secret_key,&n)>0&&n==z->secret_key;
  t[4]=ticks();
 }else{
  int secret=p>100?op==2:op==1;
  k=import_key(o,secret,secret?in->sk:in->pk,secret?z->secret_key:z->public_key);
  t[1]=ticks();c=k?EVP_PKEY_CTX_new_from_pkey(o->ctx,k,"provider=default"):NULL;
  if(p>100&&op==1){
   OSSL_PARAM params[]={OSSL_PARAM_octet_string("ikme",(void*)in->coins,32),OSSL_PARAM_END};n=z->ciphertext;n2=32;
   ok=c&&EVP_PKEY_encapsulate_init(c,params)>0;t[2]=ticks();
   ok=ok&&EVP_PKEY_encapsulate(c,out->ct,&n,out->ss,&n2)>0&&n==z->ciphertext&&n2==32;
  }else if(p>100){
   n=32;ok=c&&EVP_PKEY_decapsulate_init(c,NULL)>0;t[2]=ticks();
   ok=ok&&EVP_PKEY_decapsulate(c,out->ss,&n,in->ct,z->ciphertext)>0&&n==32;
  }else{
   OSSL_PARAM params[5];params[0]=OSSL_PARAM_construct_octet_string("context-string",(void*)in->domain,in->dn);
   params[1]=OSSL_PARAM_construct_int("message-encoding",&encoding);params[2]=OSSL_PARAM_construct_int("mu",&mu);
   if(op==1){
    params[3]=OSSL_PARAM_construct_octet_string("test-entropy",(void*)in->coins,32);params[4]=OSSL_PARAM_construct_end();n=z->signature;
    ok=c&&EVP_PKEY_sign_message_init(c,o->signature,params)>0;t[2]=ticks();
    ok=ok&&EVP_PKEY_sign(c,out->sig,&n,in->msg,in->mn)>0&&n==z->signature;
   }else{
    params[3]=OSSL_PARAM_construct_end();ok=c&&EVP_PKEY_verify_message_init(c,o->signature,params)>0;t[2]=ticks();
    ok=ok&&EVP_PKEY_verify(c,in->sig,z->signature,in->msg,in->mn)>0;
   }
  }
  t[3]=ticks();t[4]=t[3]; /* Output encoding occurs inside the provider operation. */
 }
 EVP_PKEY_CTX_free(c);EVP_PKEY_free(k);t[5]=ticks();
 d->import=t[1]-t[0];d->setup=t[2]-t[1];d->operation=t[3]-t[2];
 d->export=t[4]-t[3];d->release=t[5]-t[4];d->total=t[5]-t[0];
 for(int j=1;j<6;j++)if(t[j]<t[j-1])return LC_E_INTERNAL;
 return ok?0:LC_E_REJECT;
}
int main(int argc,char **argv) {
 if(argc!=14){fputs("usage: diagnostic library parameter op count seed output.csv capacity message_bytes context_bytes pct cpu expected_version diagnostic_only\n",stderr);return 2;}
 int p=atoi(argv[2]),op=atoi(argv[3]),n=atoi(argv[4]),cpu=atoi(argv[11]);
 uint64_t seed=strtoull(argv[5],NULL,10),freq=frequency();size_t cap=(size_t)strtoull(argv[7],NULL,10),mn=(size_t)strtoull(argv[8],NULL,10),dn=(size_t)strtoull(argv[9],NULL,10);
 const char *pct=argv[10];unsigned long expected=!strcmp(argv[12],"3.6.4")?0x30600040L:!strcmp(argv[12],"3.6.0")?0x30600000L:0;
 if(!algorithm(p)||op<0||op>2||n<1||n>1000000||!seed||!freq||cap<32||cap>262144||mn>16384||dn>255||(strcmp(pct,"none")&&strcmp(pct,"random"))||strcmp(argv[13],"diagnostic_only"))return 3;
 {FILE *f=fopen(argv[6],"rb");if(f){fclose(f);fputs("Refuse raw overwrite\n",stderr);return 3;}}
 if(!expected||OPENSSL_VERSION_NUMBER!=expected||OpenSSL_version_num()!=expected)return 4;
 if(!pin_cpu(cpu))return 5;
 LC l={0};OS o={0};lc_sizes z;TEST_INPUT in={0};OUTPUT out={0},check={0},plain={0};
 FILE *csv=NULL;EVP_MD_CTX *inputs=NULL,*outputs=NULL;EVP_MD *sha256=NULL;int rc=0,completed=0;char crypto[4096]={0};
 if(!load_lc(&l,argv[1],cap)||l.sizes(p,&z)||!init_os(&o,p,pct)||!crypto_path(crypto,sizeof crypto)){rc=6;goto done;}
 prng=seed;in.mn=mn;in.dn=dn;fill(in.coins,64);fill(in.msg,mn);fill(in.domain,dn);
 if(lattice_call(&l,p,0,&z,&in,&out)||openssl_call(&o,p,0,&z,&in,&check)||!equal(p,0,&z,&out,&check)){rc=7;goto done;}
 memcpy(in.pk,out.pk,z.public_key);memcpy(in.sk,out.sk,z.secret_key);
 if(transcript(&l,p,&z,&in)||!negatives(&o,&l,p,&z,&in)){rc=8;goto done;}
 sha256=EVP_MD_fetch(o.ctx,"SHA256","provider=default");inputs=EVP_MD_CTX_new();outputs=EVP_MD_CTX_new();
 if(!sha256||!inputs||!outputs||!EVP_DigestInit_ex(inputs,sha256,NULL)||!EVP_DigestInit_ex(outputs,sha256,NULL)){rc=9;goto done;}
 csv=fopen(argv[6],"wb");if(!csv){rc=10;goto done;}
 fputs("case_id,iteration,openssl_first,frequency,lattice_total_ticks,openssl_import_ticks,openssl_setup_ticks,openssl_operation_ticks,openssl_export_ticks,openssl_free_ticks,openssl_total_ticks,status,entropy_sha256,message_sha256,context_sha256\n",csv);
 for(int i=0;i<n;i++){
  PHASES d={0};uint64_t a,b;int r1,r2,status;char eh[65],mh[65],dh[65];
  fill(in.coins,64);if(p<100&&op>0)fill(in.msg,mn);
  if(op==2&&transcript(&l,p,&z,&in)){rc=11;break;}
  if(!hash(&o,in.coins,(op==0&&p>100)?64:32,eh)||!hash(&o,in.msg,mn,mh)||!hash(&o,in.domain,dn,dh)){rc=12;break;}
  if(!EVP_DigestUpdate(inputs,eh,64)||!EVP_DigestUpdate(inputs,mh,64)||!EVP_DigestUpdate(inputs,dh,64)||!EVP_DigestUpdate(inputs,in.pk,z.public_key)||(op==2&&!EVP_DigestUpdate(inputs,p>100?in.ct:in.sig,p>100?z.ciphertext:z.signature))){rc=13;break;}
  if(current_cpu()!=cpu){rc=14;break;}
  if(i&1){r2=diagnostic_call(&o,p,op,&z,&in,&check,&d);a=ticks();r1=lattice_call(&l,p,op,&z,&in,&out);b=ticks();}
  else{a=ticks();r1=lattice_call(&l,p,op,&z,&in,&out);b=ticks();r2=diagnostic_call(&o,p,op,&z,&in,&check,&d);}
  status=r1?r1:r2;
  if(!status&&(!equal(p,op,&z,&out,&check)||current_cpu()!=cpu||!arena_guards(&l)||b<a||d.total!=d.import+d.setup+d.operation+d.export+d.release))status=LC_E_INTERNAL;
  /* Instrumented provider bytes must also equal the unmodified primary path. */
  if(!status&&(openssl_call(&o,p,op,&z,&in,&plain)||!equal(p,op,&z,&out,&plain)))status=LC_E_INTERNAL;
  fprintf(csv,"%016" PRIx64 "-%d-%d-%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%d,%s,%s,%s\n",seed,p,op,i,i,i&1,freq,b-a,d.import,d.setup,d.operation,d.export,d.release,d.total,status,eh,mh,dh);
  if(fflush(csv)||status){rc=15;break;}
  if(!digest_output(outputs,p,op,&z,&in,&out)){rc=16;break;}completed++;
 }
 if(!rc){
  uint8_t a[32],b[32];unsigned an=0,bn=0;char ah[65],bh[65];
  if(!EVP_DigestFinal_ex(inputs,a,&an)||!EVP_DigestFinal_ex(outputs,b,&bn)||an!=32||bn!=32){rc=18;goto done;}
  hex(a,32,ah);hex(b,32,bh);printf("{\"status\":\"PASS\",\"measurement_class\":\"phase_diagnostic_only_not_formal\",\"samples\":%d,\"raw_rows\":%d,\"parameter\":%d,\"operation\":%d,\"seed\":%" PRIu64 ",\"cpu\":%d,\"frequency\":%" PRIu64 ",\"input_sequence_sha256\":\"%s\",\"output_sequence_sha256\":\"%s\",\"openssl_library\":",n,completed,p,op,seed,cpu,freq,ah,bh);
  json_string(crypto);printf(",\"import_pct\":");json_string(pct);printf(",\"openssl_version\":");json_string(OpenSSL_version(OPENSSL_VERSION));
  printf(",\"keygen_has_no_import\":true,\"non_keygen_output_encoding_within_operation\":true,\"setup_separate\":true,\"timing_overhead_subtracted\":false,\"phase_sum_exact\":true,\"matches_unmodified_primary_call\":true,\"sample_trimming\":false}\n");
 }
done:
 if(rc){fprintf(stderr,"diagnostic failed code=%d completed=%d\n",rc,completed);ERR_print_errors_fp(stderr);}
 if(csv&&fclose(csv)&&!rc)rc=19;
 EVP_MD_CTX_free(inputs);EVP_MD_CTX_free(outputs);EVP_MD_free(sha256);free_os(&o);
 OPENSSL_cleanse(&in,sizeof in);OPENSSL_cleanse(&out,sizeof out);OPENSSL_cleanse(&check,sizeof check);OPENSSL_cleanse(&plain,sizeof plain);
 if(l.raw){OPENSSL_cleanse(l.raw,cap+128);free(l.raw);}
#ifdef _WIN32
 if(l.handle)FreeLibrary((HMODULE)l.handle);
#else
 if(l.handle)dlclose(l.handle);
#endif
 return rc;
}
