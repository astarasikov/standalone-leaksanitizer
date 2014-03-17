//=-- lsan_interceptors.cc ------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
// Interceptors for standalone LSan.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_interception.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_platform_limits_posix.h"
#include "lsan.h"
#include "lsan_allocator.h"
#include "lsan_thread.h"

using namespace __lsan;

extern "C" {
int pthread_attr_init(void *attr);
int pthread_attr_destroy(void *attr);
int pthread_attr_getdetachstate(void *attr, int *v);
int pthread_key_create(unsigned *key, void (*destructor)(void* v));
int pthread_setspecific(unsigned key, const void *v);
void* malloc(uptr size);
void free(void *p);
void cfree(void *p);
void* calloc(uptr nmemb, uptr size);
void* realloc(void *q, uptr size);
void* memalign(uptr alignment, uptr size);
int posix_memalign(void **memptr, uptr alignment, uptr size);
void* __libc_memalign(uptr alignment, uptr size);
void* valloc(uptr size);
void* pvalloc(uptr size);
uptr malloc_usable_size(void *ptr);
struct fake_mallinfo mallinfo(void);
int mallopt(int cmd, int value);
}

#define GET_STACK_TRACE                                              \
  StackTrace stack;                                                  \
  {                                                                  \
    uptr stack_top = 0, stack_bottom = 0;                            \
    ThreadContext *t;                                                \
    bool fast = common_flags()->fast_unwind_on_malloc;               \
    if (fast && (t = CurrentThreadContext())) {                      \
      stack_top = t->stack_end();                                    \
      stack_bottom = t->stack_begin();                               \
    }                                                                \
    stack.Unwind(__sanitizer::common_flags()->malloc_context_size,   \
                 StackTrace::GetCurrentPc(), GET_CURRENT_FRAME(), 0, \
                 stack_top, stack_bottom, fast);                     \
  }

#define ENSURE_LSAN_INITED do {   \
  CHECK(!lsan_init_is_running);   \
  if (!lsan_inited)               \
    __lsan_init();                \
} while (0)

static void* lsan_malloc(uptr size);
static void lsan_free(void *p);
static void lsan_cfree(void *p);
static void* lsan_calloc(uptr nmemb, uptr size);
static void* lsan_realloc(void *q, uptr size);
static void* lsan_memalign(uptr alignment, uptr size);
static int lsan_posix_memalign(void **memptr, uptr alignment, uptr size);
static void* lsan___libc_memalign(uptr alignment, uptr size);
static void* lsan_valloc(uptr size);
static void* lsan_pvalloc(uptr size);
static uptr lsan_malloc_usable_size(void *ptr);
static struct fake_mallinfo lsan_mallinfo(void);
static int lsan_mallopt(int cmd, int value);

static void* (*volatile used_malloc)(uptr size) = lsan_malloc;
static void (*volatile used_free)(void *p) = lsan_free;
static void (*volatile used_cfree)(void *p) = lsan_cfree;
static void* (*volatile used_calloc)(uptr nmemb, uptr size) = lsan_calloc;
static void* (*volatile used_realloc)(void *q, uptr size) = lsan_realloc;
static void* (*volatile used_memalign)(uptr alignment, uptr size) = lsan_memalign;
static int (*volatile used_posix_memalign)(void **memptr, uptr alignment, uptr size) = lsan_posix_memalign;
static void* (*volatile used___libc_memalign)(uptr alignment, uptr size) = lsan___libc_memalign;
static void* (*volatile used_valloc)(uptr size) = lsan_valloc;
static void* (*volatile used_pvalloc)(uptr size) = lsan_pvalloc;
static uptr (*volatile used_malloc_usable_size)(void *ptr) = lsan_malloc_usable_size;
static struct fake_mallinfo (*volatile used_mallinfo)(void) = lsan_mallinfo;
static int (*volatile used_mallopt)(int cmd, int value) = lsan_mallopt;

#define ID(x) x
#define LSAN_FNAME(x) lsan_ ## x

#define LSAN_ASSIGN_USED_PTR(name, wrapper) \
  used_ ## name = wrapper(name)

// second argument is intentionally ignored
#define LSAN_INTERCEPT_ACTION(name, wrapper) \
  INTERCEPT_FUNCTION(name)

#define LSAN_WRAPPERS_DO(action, wrapper) do { \
  action(malloc, wrapper); \
  action(free, wrapper); \
  action(cfree, wrapper); \
  action(calloc, wrapper); \
  action(realloc, wrapper); \
  action(memalign, wrapper); \
  action(posix_memalign, wrapper); \
  action(__libc_memalign, wrapper); \
  action(valloc, wrapper); \
  action(pvalloc, wrapper); \
  action(malloc_usable_size, wrapper); \
  action(mallinfo, wrapper); \
  action(mallopt, wrapper); \
} while (0)

///// Malloc/free interceptors. /////
const bool kAlwaysClearMemory = true;

namespace std {
  struct nothrow_t;
}

static void* lsan_malloc(uptr size) {
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE;
  return Allocate(stack, size, 1, kAlwaysClearMemory);
}

INTERCEPTOR(void*, malloc, uptr size) {
  return used_malloc(size);
}

static void lsan_free(void*p) {
  ENSURE_LSAN_INITED;
  Deallocate(p);
}

INTERCEPTOR(void, free, void *p) {
  used_free(p);
}

static void* lsan_calloc(uptr nmemb, uptr size) {
  if (lsan_init_is_running) {
    // Hack: dlsym calls calloc before REAL(calloc) is retrieved from dlsym.
    const uptr kCallocPoolSize = 1024;
    static uptr calloc_memory_for_dlsym[kCallocPoolSize];
    static uptr allocated;
    uptr size_in_words = ((nmemb * size) + kWordSize - 1) / kWordSize;
    void *mem = (void*)&calloc_memory_for_dlsym[allocated];
    allocated += size_in_words;
    CHECK(allocated < kCallocPoolSize);
    return mem;
  }
  if (CallocShouldReturnNullDueToOverflow(size, nmemb)) return 0;
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE;
  size *= nmemb;
  return Allocate(stack, size, 1, true);
}

INTERCEPTOR(void*, calloc, uptr nmemb, uptr size) {
  return lsan_calloc(nmemb, size);
  //return used_calloc(nmemb, size);
}

static void* lsan_realloc(void *q, uptr size) {
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE;
  return Reallocate(stack, q, size, 1);
}

INTERCEPTOR(void*, realloc, void *q, uptr size) {
  return used_realloc(q, size);
}

static void* lsan_memalign(uptr alignment, uptr size) {
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE;
  return Allocate(stack, size, alignment, kAlwaysClearMemory);
}

INTERCEPTOR(void*, memalign, uptr alignment, uptr size) {
  return used_memalign(alignment, size);
}

static int lsan_posix_memalign(void **memptr, uptr alignment, uptr size) {
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE;
  *memptr = Allocate(stack, size, alignment, kAlwaysClearMemory);
  // FIXME: Return ENOMEM if user requested more than max alloc size.
  return 0;
}

INTERCEPTOR(int, posix_memalign, void **memptr, uptr alignment, uptr size) {
  return used_posix_memalign(memptr, alignment, size);
}

static void* lsan_valloc(uptr size) {
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE;
  if (size == 0)
    size = GetPageSizeCached();
  return Allocate(stack, size, GetPageSizeCached(), kAlwaysClearMemory);
}

INTERCEPTOR(void*, valloc, uptr size) {
  return used_valloc(size);
}

static uptr lsan_malloc_usable_size(void *ptr) {
  ENSURE_LSAN_INITED;
  return GetMallocUsableSize(ptr);
}

INTERCEPTOR(uptr, malloc_usable_size, void *ptr) {
  return used_malloc_usable_size(ptr);
}

struct fake_mallinfo {
  int x[10];
};

static struct fake_mallinfo lsan_mallinfo(void) {
  struct fake_mallinfo res;
  internal_memset(&res, 0, sizeof(res));
  return res;
}

INTERCEPTOR(struct fake_mallinfo, mallinfo, void) {
  return used_mallinfo();
}

static int lsan_mallopt(int cmd, int value) {
  return -1;
}

INTERCEPTOR(int, mallopt, int cmd, int value) {
  return used_mallopt(cmd, value);
}

static void* lsan_pvalloc(uptr size) {
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE;
  uptr PageSize = GetPageSizeCached();
  size = RoundUpTo(size, PageSize);
  if (size == 0) {
    // pvalloc(0) should allocate one page.
    size = PageSize;
  }
  return Allocate(stack, size, GetPageSizeCached(), kAlwaysClearMemory);
}

INTERCEPTOR(void*, pvalloc, uptr size) {
  return used_pvalloc(size);
}

static void lsan_cfree(void *p) {
   ENSURE_LSAN_INITED;
   Deallocate(p);
}

INTERCEPTOR(void, cfree, void *p) {
  return used_cfree(p);
}

#define OPERATOR_NEW_BODY                              \
  ENSURE_LSAN_INITED;                                  \
  GET_STACK_TRACE;                                     \
  return Allocate(stack, size, 1, kAlwaysClearMemory);

INTERCEPTOR_ATTRIBUTE
void *operator new(uptr size) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new[](uptr size) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new(uptr size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new[](uptr size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }

#define OPERATOR_DELETE_BODY \
  ENSURE_LSAN_INITED;        \
  Deallocate(ptr);

INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr) throw() { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr) throw() { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, std::nothrow_t const&) { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, std::nothrow_t const &) {
  OPERATOR_DELETE_BODY;
}

// We need this to intercept the __libc_memalign calls that are used to
// allocate dynamic TLS space in ld-linux.so.

static void* lsan___libc_memalign(uptr alignment, uptr size) {
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE;
  return Allocate(stack, size, alignment, kAlwaysClearMemory);
}

INTERCEPTOR(void*, __libc_memalign, uptr alignment, uptr size) {
  return used___libc_memalign(alignment, size);
}


///// Thread initialization and finalization. /////

static unsigned g_thread_finalize_key;

static void thread_finalize(void *v) {
  uptr iter = (uptr)v;
  if (iter > 1) {
    if (pthread_setspecific(g_thread_finalize_key, (void*)(iter - 1))) {
      Report("LeakSanitizer: failed to set thread key.\n");
      Die();
    }
    return;
  }
  ThreadFinish();
}

struct ThreadParam {
  void *(*callback)(void *arg);
  void *param;
  atomic_uintptr_t tid;
};

extern "C" void *__lsan_thread_start_func(void *arg) {
  ThreadParam *p = (ThreadParam*)arg;
  void* (*callback)(void *arg) = p->callback;
  void *param = p->param;
  // Wait until the last iteration to maximize the chance that we are the last
  // destructor to run.
  if (pthread_setspecific(g_thread_finalize_key,
                          (void*)kPthreadDestructorIterations)) {
    Report("LeakSanitizer: failed to set thread key.\n");
    Die();
  }
  int tid = 0;
  while ((tid = atomic_load(&p->tid, memory_order_acquire)) == 0)
    internal_sched_yield();
  atomic_store(&p->tid, 0, memory_order_release);
  SetCurrentThread(tid);
  ThreadStart(tid, GetTid());
  return callback(param);
}

INTERCEPTOR(int, pthread_create, void *th, void *attr,
            void *(*callback)(void *), void *param) {
  ENSURE_LSAN_INITED;
  EnsureMainThreadIDIsCorrect();
  __sanitizer_pthread_attr_t myattr;
  if (attr == 0) {
    pthread_attr_init(&myattr);
    attr = &myattr;
  }
  AdjustStackSize(attr);
  int detached = 0;
  pthread_attr_getdetachstate(attr, &detached);
  ThreadParam p;
  p.callback = callback;
  p.param = param;
  atomic_store(&p.tid, 0, memory_order_relaxed);
  int res = REAL(pthread_create)(th, attr, __lsan_thread_start_func, &p);
  if (res == 0) {
    int tid = ThreadCreate(GetCurrentThread(), *(uptr *)th, detached);
    CHECK_NE(tid, 0);
    atomic_store(&p.tid, tid, memory_order_release);
    while (atomic_load(&p.tid, memory_order_acquire) != 0)
      internal_sched_yield();
  }
  if (attr == &myattr)
    pthread_attr_destroy(&myattr);
  return res;
}

INTERCEPTOR(int, pthread_join, void *th, void **ret) {
  ENSURE_LSAN_INITED;
  int tid = ThreadTid((uptr)th);
  int res = REAL(pthread_join)(th, ret);
  if (res == 0)
    ThreadJoin(tid);
  return res;
}

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE
void __lsan_enable_interceptors(void) {
  ENSURE_LSAN_INITED;
  LSAN_WRAPPERS_DO(LSAN_ASSIGN_USED_PTR, LSAN_FNAME);
}

SANITIZER_INTERFACE_ATTRIBUTE
void __lsan_disable_interceptors(void) {
  ENSURE_LSAN_INITED;
  LSAN_WRAPPERS_DO(LSAN_ASSIGN_USED_PTR, REAL);
}

} // end of lsan enable/disable functions


namespace __lsan {

void InitializeInterceptors() {
  LSAN_WRAPPERS_DO(LSAN_INTERCEPT_ACTION, ID);
  INTERCEPT_FUNCTION(pthread_create);
  INTERCEPT_FUNCTION(pthread_join);

  if (pthread_key_create(&g_thread_finalize_key, &thread_finalize)) {
    Report("LeakSanitizer: failed to create thread key.\n");
    Die();
  }
}

}  // namespace __lsan
