/* glibc-only process interposition, enabled solely around measured calls.
 * Counts requested live bytes, not allocator metadata/physical residency.
 * A nonzero result makes the complete RAM bound unknown unless separately
 * accounted. No function from this file is linked into the product. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <string.h>
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t,size_t);
extern void *__libc_realloc(void*,size_t);
extern void __libc_free(void*);
static int active;
static uint64_t calls,frees,live,peak,errors;
static struct {void *p;size_t n;} slots[128];
static void add(void *p,size_t n){if(!active)return;calls++;if(!p)return;for(size_t i=0;i<128;i++)if(!slots[i].p){slots[i].p=p;slots[i].n=n;live+=n;if(live>peak)peak=live;return;}errors++;}
static void remove_ptr(void *p){if(!active||!p)return;for(size_t i=0;i<128;i++)if(slots[i].p==p){live-=slots[i].n;slots[i].p=NULL;return;}errors++;}
void *malloc(size_t n){void*p=__libc_malloc(n);add(p,n);return p;}
void *calloc(size_t n,size_t s){void*p=__libc_calloc(n,s);if(n&&s>SIZE_MAX/n){if(active)errors++;return p;}add(p,n*s);return p;}
void *realloc(void *p,size_t n){size_t i=128;int had_pointer=p!=NULL;if(active&&p)for(size_t k=0;k<128;k++)if(slots[k].p==p){i=k;break;}void*q=__libc_realloc(p,n);if(active){if(q||!n){if(i<128){live-=slots[i].n;slots[i].p=NULL;}else if(had_pointer)errors++;add(q,n);}else calls++;}return q;}
void free(void*p){if(active)frees++;remove_ptr(p);__libc_free(p);}
void r2_heap_reset(void){active=0;calls=frees=live=peak=errors=0;memset(slots,0,sizeof slots);}
void r2_heap_enable(int yes){active=yes;}
void r2_heap_snapshot(uint64_t out[5]){out[0]=calls;out[1]=frees;out[2]=live;out[3]=peak;out[4]=errors;}
