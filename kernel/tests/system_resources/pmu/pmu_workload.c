/* Complete-operation PMU region, controlled through perf stat's FIFO protocol.
 * Reuse the fixed-input random generator and API types from the time driver. */
#define LC_FIXTURE_HELPERS_ONLY
#include "workload.c"

static void perf_command(FILE *control,FILE *ack,const char *command){
 char reply[4];int n=0,c;
 if(fprintf(control,"%s\n",command)<0||fflush(control))exit(31);
 /* Linux 5.15 perf writes sizeof("ack\n"), including its terminating NUL.
  * Consume that framing byte before the next acknowledgement. */
 while(n<4){c=fgetc(ack);if(c==EOF)exit(31);if(c==0&&n==0)continue;reply[n++]=(char)c;}
 if(memcmp(reply,"ack\n",4))exit(31);
}
int main(int argc,char **argv){
 if(argc!=8)return 2;
 int parameter=atoi(argv[2]),op=atoi(argv[3]),count=atoi(argv[4]),cpu=atoi(argv[6]);
 size_t capacity=strtoull(argv[5],0,0);rng=strtoull(argv[7],0,0);
 if(op<0||op>2||count<1||count>100000||!rng||capacity>262144||cpu<0||cpu>=CPU_SETSIZE)return 3;
 cpu_set_t set;CPU_ZERO(&set);CPU_SET(cpu,&set);if(sched_setaffinity(0,sizeof set,&set))return 4;
 void*h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!h)return 5;API a;
#define BIND(f,n) do{void*p=dlsym(h,n);if(!p)return 6;memcpy(&a.f,&p,sizeof p);}while(0)
 BIND(init,"lc_context_init");BIND(sizes,"lc_get_sizes");BIND(key,"lc_keypair");BIND(enc,"lc_encaps");BIND(dec,"lc_decaps");BIND(sign,"lc_sign");BIND(verify,"lc_verify");
#undef BIND
 lc_sizes z;if(a.sizes(parameter,&z))return 7;
 void*work=0;if(posix_memalign(&work,32,capacity?capacity:32))return 8;
 uint8_t pk[2592],sk[4896],ct[1568],ss[32],expected[32],sig[4627],msg[32],domain[16];
 memset(msg,0x3a,sizeof msg);memset(domain,0x65,sizeof domain);
 lc_context c;int rc=a.init(&c,work,capacity,random_bytes,0);
 if(!rc)rc=a.key(&c,parameter,pk,z.public_key,sk,z.secret_key);
 if(rc)return 21;
 if(parameter>100){rc=a.enc(&c,parameter,ct,z.ciphertext,expected,32,pk,z.public_key);if(!rc)rc=a.dec(&c,parameter,ss,32,ct,z.ciphertext,sk,z.secret_key);if(rc||memcmp(ss,expected,32))return 22;}
 else{rc=a.sign(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,sk,z.secret_key);if(!rc)rc=a.verify(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,pk,z.public_key);if(rc)return 23;}
 const char *controlpath=getenv("A127_PERF_CONTROL"),*ackpath=getenv("A127_PERF_ACK");
 if(!controlpath||!ackpath)return 30;
 FILE*control=fopen(controlpath,"w"),*ack=fopen(ackpath,"r");if(!control||!ack)return 30;
 /* Warmups execute with events disabled. The loop, context initialization,
  * random-input callback, complete algorithm, and cleanup form the region.
  * Output checking and all CSV/JSON processing happen after disable. */
 for(int i=-32;i<count;i++){
  if(i==0)perf_command(control,ack,"enable");
  rc=a.init(&c,work,capacity,random_bytes,0);
  if(!rc){
   if(op==0)rc=a.key(&c,parameter,pk,z.public_key,sk,z.secret_key);
   else if(parameter>100){if(op==1)rc=a.enc(&c,parameter,ct,z.ciphertext,ss,32,pk,z.public_key);else rc=a.dec(&c,parameter,ss,32,ct,z.ciphertext,sk,z.secret_key);}
   else if(op==1)rc=a.sign(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,sk,z.secret_key);
   else rc=a.verify(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,pk,z.public_key);
  }
  if(rc){perf_command(control,ack,"disable");return 24;}
 }
 perf_command(control,ack,"disable");fclose(control);fclose(ack);
 if(parameter>100){if(op==0){rc=a.enc(&c,parameter,ct,z.ciphertext,expected,32,pk,z.public_key);if(!rc)rc=a.dec(&c,parameter,ss,32,ct,z.ciphertext,sk,z.secret_key);if(!rc&&memcmp(ss,expected,32))rc=1;}else if(op==1){rc=a.dec(&c,parameter,expected,32,ct,z.ciphertext,sk,z.secret_key);if(!rc&&memcmp(ss,expected,32))rc=1;}else if(memcmp(ss,expected,32))rc=1;}
 else{if(op==0)rc=a.sign(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,sk,z.secret_key);if(!rc)rc=a.verify(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,pk,z.public_key);}
 if(rc)return 25;
 printf("{\"status\":\"PASS\",\"parameter\":%d,\"operation\":%d,\"measured_operations\":%d,\"warmup_excluded\":32,\"workspace_bytes\":%zu,\"cpu_logical\":%d,\"message_bytes\":32,\"context_bytes\":16}\n",parameter,op,count,capacity,sched_getcpu());
 volatile uint8_t*wipe=work;for(size_t i=0;i<capacity;i++)wipe[i]=0;wipe=sk;for(size_t i=0;i<sizeof sk;i++)wipe[i]=0;
 free(work);dlclose(h);return 0;
}
