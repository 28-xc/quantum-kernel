/* Probe-only IAT audit. Never linked into the measured deployment DLL. */
typedef void *(__cdecl *audit_malloc_fn)(size_t);
typedef void *(__cdecl *audit_calloc_fn)(size_t,size_t);
typedef void *(__cdecl *audit_realloc_fn)(void*,size_t);
typedef void (__cdecl *audit_free_fn)(void*);
static audit_malloc_fn audit_real_malloc;
static audit_calloc_fn audit_real_calloc;
static audit_realloc_fn audit_real_realloc;
static audit_free_fn audit_real_free;
static void **audit_calloc_slot,**audit_realloc_slot,**audit_free_slot;
static volatile int audit_active;
static size_t audit_calls,audit_free_calls,audit_live,audit_peak,audit_errors,audit_hooked,audit_unsupported;
static int audit_positive_control_local;
static size_t image_committed,image_readonly,image_writable,image_noaccess,image_reserved,image_size;
static struct {void *p;size_t bytes;} audit_allocations[32];
static void audit_add(void*p,size_t n){
 if(!audit_active)return;
 audit_calls++;
 if(!p)return;
 for(size_t i=0;i<32;i++)if(!audit_allocations[i].p){
  audit_allocations[i].p=p;audit_allocations[i].bytes=n;audit_live+=n;
  if(audit_live>audit_peak)audit_peak=audit_live;
  return;
 }
 audit_errors++;
}
static void audit_remove(void*p){
 if(!audit_active||!p)return;
 for(size_t i=0;i<32;i++)if(audit_allocations[i].p==p){
  audit_live-=audit_allocations[i].bytes;audit_allocations[i].p=NULL;return;
 }
 /* A free of state created outside the measured call is an unknown bound. */
 audit_errors++;
}
static void *__cdecl audit_malloc(size_t n){void*p=audit_real_malloc(n);audit_add(p,n);return p;}
static void *__cdecl audit_calloc(size_t n,size_t s){void*p=audit_real_calloc(n,s);audit_add(p,n*s);return p;}
static void *__cdecl audit_realloc(void*p,size_t n){
 size_t index=32;int had_pointer=p!=NULL;
 if(audit_active && p)for(size_t i=0;i<32;i++)if(audit_allocations[i].p==p){index=i;break;}
 void*q=audit_real_realloc(p,n);
 if(audit_active){
  if(q||!n){
   if(index<32){audit_live-=audit_allocations[index].bytes;audit_allocations[index].p=NULL;}
   else if(had_pointer)audit_errors++;
   audit_add(q,n);
  }else audit_calls++;
 }
 return q;
}
static void __cdecl audit_free(void*p){if(audit_active)audit_free_calls++;audit_remove(p);audit_real_free(p);}
static int memory_image_inventory(HMODULE dll){
 uint8_t*base=(uint8_t*)dll;IMAGE_DOS_HEADER*d=(IMAGE_DOS_HEADER*)base;
 IMAGE_NT_HEADERS64*n=(IMAGE_NT_HEADERS64*)(base+d->e_lfanew);
 image_size=n->OptionalHeader.SizeOfImage;
 uintptr_t p=(uintptr_t)base,end=p+image_size;
 while(p<end){MEMORY_BASIC_INFORMATION m;if(!VirtualQuery((void*)p,&m,sizeof m))return 0;
  uintptr_t top=(uintptr_t)m.BaseAddress+m.RegionSize;if(top>end)top=end;
  size_t bytes=top-p;DWORD pr=m.Protect&0xff;
  if(m.State==MEM_COMMIT){image_committed+=bytes;
   if(pr==PAGE_READWRITE||pr==PAGE_WRITECOPY||pr==PAGE_EXECUTE_READWRITE||pr==PAGE_EXECUTE_WRITECOPY)image_writable+=bytes;
   else if(pr==PAGE_NOACCESS)image_noaccess+=bytes;else image_readonly+=bytes;
  }else if(m.State==MEM_RESERVE)image_reserved+=bytes;
  p=top;
 }
 return 1;
}
static int memory_audit_install(HMODULE dll){
 uint8_t*base=(uint8_t*)dll;IMAGE_DOS_HEADER*d=(IMAGE_DOS_HEADER*)base;
 IMAGE_NT_HEADERS64*n=(IMAGE_NT_HEADERS64*)(base+d->e_lfanew);
 DWORD rva=n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
 if(!rva)return 1;
 IMAGE_IMPORT_DESCRIPTOR*id=(IMAGE_IMPORT_DESCRIPTOR*)(base+rva);
 for(;id->Name;id++){
  if(!id->OriginalFirstThunk)return 0;
  IMAGE_THUNK_DATA64*names=(IMAGE_THUNK_DATA64*)(base+id->OriginalFirstThunk);
  IMAGE_THUNK_DATA64*slots=(IMAGE_THUNK_DATA64*)(base+id->FirstThunk);
  for(;names->u1.AddressOfData;names++,slots++){
   if(IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal))continue;
   const char*name=(const char*)((IMAGE_IMPORT_BY_NAME*)(base+names->u1.AddressOfData))->Name;
   void*replacement=NULL;void**slot=(void**)&slots->u1.Function;
   if(!strcmp(name,"malloc")){audit_real_malloc=(audit_malloc_fn)*slot;replacement=(void*)audit_malloc;}
   else if(!strcmp(name,"calloc")){audit_real_calloc=(audit_calloc_fn)*slot;audit_calloc_slot=slot;replacement=(void*)audit_calloc;}
   else if(!strcmp(name,"realloc")){audit_real_realloc=(audit_realloc_fn)*slot;audit_realloc_slot=slot;replacement=(void*)audit_realloc;}
   else if(!strcmp(name,"free")){audit_real_free=(audit_free_fn)*slot;audit_free_slot=slot;replacement=(void*)audit_free;}
   else if(strstr(name,"Alloc")||strstr(name,"alloc")||strstr(name,"Heap")||strstr(name,"strdup"))audit_unsupported++;
   if(replacement){DWORD old,tmp;if(!VirtualProtect(slot,sizeof(void*),PAGE_READWRITE,&old))return 0;
    *slot=replacement;if(!VirtualProtect(slot,sizeof(void*),old,&tmp))return 0;audit_hooked++;
   }
  }
 }
 return !audit_unsupported;
}
static int memory_heap_control(void*unused){
 (void)unused;
 if(!audit_calloc_slot||!audit_realloc_slot||!audit_free_slot){
  /* A library with no allocator imports has no allocator IAT to exercise.
   * Test the same accounting wrappers against the probe's CRT, explicitly
   * separate from a target-IAT interception test. Partial IATs stay unknown. */
  if(audit_hooked||audit_unsupported)return -995;
  audit_positive_control_local=1;audit_real_calloc=calloc;audit_real_realloc=realloc;audit_real_free=free;
  void*p=audit_calloc(4,16);if(!p)return -996;
  void*q=audit_realloc(p,96);if(!q){audit_free(p);return -997;}
  audit_free(q);return 0;
 }
 void*p=((audit_calloc_fn)*audit_calloc_slot)(4,16);
 if(!p)return -996;
 void*q=((audit_realloc_fn)*audit_realloc_slot)(p,96);
 if(!q){((audit_free_fn)*audit_free_slot)(p);return -997;}
 ((audit_free_fn)*audit_free_slot)(q);return 0;
}
