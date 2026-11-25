/* PQClean SHAKE needs 200/208-byte dynamically allocated Keccak states.
   Use a bounded, single-threaded slot pool and measure simultaneous storage. */
#include "board.h"
#include <stdlib.h>
#include <string.h>
static uint64_t slots[16][26];
static unsigned used,live,peak;
void reference_heap_reset_peak(void){peak=live;}
unsigned reference_heap_peak(void){return peak;}
void *malloc(size_t n){
    if(n>sizeof(slots[0])||!n)return NULL;
    for(unsigned j=0;j<16;j++)if(!(used&(1u<<j))){
        used|=1u<<j;live+=sizeof(slots[0]);if(live>peak)peak=live;return slots[j];
    }
    return NULL;
}
void free(void *p){
    if(!p)return;
    for(unsigned j=0;j<16;j++)if(p==slots[j]&&(used&(1u<<j))){
        clear_bytes(slots[j],sizeof(slots[j]));used&=~(1u<<j);live-=sizeof(slots[0]);return;
    }
    abort();
}
void abort(void){reset_to_dfu();}
void exit(int reason){(void)reason;reset_to_dfu();}
