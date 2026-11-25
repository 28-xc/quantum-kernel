/* Sampling-only workload. Fixed serialized key/message/ciphertext per run;
 * fresh deterministic operation entropy per iteration. Transcript generation
 * is outside the loop, including decapsulation and signature verification.
 * Samples in the core DSO therefore describe the requested operation.
 * This workload produces no comparable elapsed-time statistic. */
#define main serialized_driver_unused_main
#include "driver.c"
#undef main
int main(int argc,char **argv) {
 if(argc!=7){fputs("usage: profile_driver library parameter operation count seed cpu\n",stderr);return 2;}
 int p=atoi(argv[2]),op=atoi(argv[3]),count=atoi(argv[4]),cpu=atoi(argv[6]);uint64_t seed=strtoull(argv[5],NULL,10);
 if(!algorithm(p)||op<0||op>2||count<100||count>1000000||!seed||!pin_cpu(cpu))return 3;
 LC l={0};OS o={0};lc_sizes z;TEST_INPUT in={0};OUTPUT out={0},check={0};int rc=0;
 if(!load_lc(&l,argv[1],262144)||l.sizes(p,&z)||!init_os(&o,p,"none")){rc=4;goto done;}
 prng=seed;in.mn=1024;in.dn=0;fill(in.coins,64);fill(in.msg,in.mn);
 if(lattice_call(&l,p,0,&z,&in,&out)||openssl_call(&o,p,0,&z,&in,&check)||!equal(p,0,&z,&out,&check)){rc=5;goto done;}
 memcpy(in.pk,out.pk,z.public_key);memcpy(in.sk,out.sk,z.secret_key);
 if(transcript(&l,p,&z,&in)||!negatives(&o,&l,p,&z,&in)){rc=6;goto done;}
 for(int i=0;i<count;i++){
  fill(in.coins,64);
  if(lattice_call(&l,p,op,&z,&in,&out)||!arena_guards(&l)){rc=7;goto done;}
 }
 if(openssl_call(&o,p,op,&z,&in,&check)||!equal(p,op,&z,&out,&check)||current_cpu()!=cpu){rc=8;goto done;}
 printf("{\"status\":\"PASS\",\"parameter\":%d,\"operation\":%d,\"iterations\":%d,\"seed\":%" PRIu64 ",\"cpu\":%d,\"scope\":\"profiling only; fixed serialized key and message; exclude non-core DSO samples\"}\n",p,op,count,seed,cpu);
done:
 free_os(&o);OPENSSL_cleanse(&in,sizeof in);OPENSSL_cleanse(&out,sizeof out);OPENSSL_cleanse(&check,sizeof check);
 if(l.raw){OPENSSL_cleanse(l.raw,l.capacity+128);free(l.raw);}
#ifdef _WIN32
 if(l.handle)FreeLibrary((HMODULE)l.handle);
#else
 if(l.handle)dlclose(l.handle);
#endif
 return rc;
}
