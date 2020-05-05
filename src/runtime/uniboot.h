#include <predef.h>

#define KMEM_BASE   0xffff800000000000ull
#define KERNEL_BASE 0xffffffff80000000ull
#define KMEM_LIMIT  0xffffffff00000000ull
#define PAGES_BASE  0xffffffffc0000000ull
#define USER_LIMIT  0x0000800000000000ull

#ifdef BOOT

#include <def32.h>

#else /* BOOT */

#include <def64.h>
#define USER_VA_TAG_OFFSET 44
#ifdef STAGE3
#define VA_TAG_BASE   KMEM_BASE
#define VA_TAG_OFFSET 39
#define VA_TAG_WIDTH  8
#else
#define VA_TAG_BASE   0
#define VA_TAG_OFFSET USER_VA_TAG_OFFSET
#define VA_TAG_WIDTH  3
#endif

static inline void *tag(void* v, u64 tval) {
    return pointer_from_u64(VA_TAG_BASE | (tval << VA_TAG_OFFSET) | u64_from_pointer(v));
}

static inline u16 tagof(void* v) {
    return (u64_from_pointer(v) >> VA_TAG_OFFSET) & ((1ull << VA_TAG_WIDTH) - 1);
}

#define valueof(__x) (__x)

#endif /* BOOT */

extern void * AP_BOOT_PAGE;

/* AP boot page */
#define AP_BOOT_START u64_from_pointer(&AP_BOOT_PAGE)
#define AP_BOOT_END (AP_BOOT_START + PAGESIZE)

/* identity-mapped space for initial page tables */
#define INITIAL_PAGES_SIZE (64 * KB)

/* the stage2 secondary working heap - this needs to be large enough
   to accomodate all tfs allocations when loading the kernel - it gets
   recycled in stage3, so be generous */
#define STAGE2_WORKING_HEAP_SIZE (128 * MB)

#define STAGE2_STACK_SIZE  (128 * KB)  /* stage2 stack is recycled, too */
#define KERNEL_STACK_SIZE  (128 * KB)
#define EXCEPT_STACK_SIZE  (32 * KB)
#define INT_STACK_SIZE     (32 * KB)
#define BH_STACK_SIZE      (32 * KB)
#define SYSCALL_STACK_SIZE (32 * KB)

/* maximum buckets that can fit within a PAGESIZE_2M mcache */
#define TABLE_MAX_BUCKETS 131072

/* runloop timer minimum and maximum */
#define RUNLOOP_TIMER_MAX_PERIOD_US     100000
#define RUNLOOP_TIMER_MIN_PERIOD_US     1000

/* XXX just for initial mp bringup... */
#define MAX_CPUS 16

/* could probably find progammatically via cpuid... */
#define DEFAULT_CACHELINE_SIZE 64

/* TFS stuff */
#define TFS_LOG_DEFAULT_EXTENSION_SIZE (512*KB)

/* Xen stuff */
#define XENNET_INIT_RX_BUFFERS_FACTOR 4
#define XENNET_RX_SERVICEQUEUE_DEPTH 512
#define XENNET_TX_SERVICEQUEUE_DEPTH 512

/* mm stuff */
#define CACHE_DRAIN_CUTOFF (64 * MB)

#include <x86.h>
void xsave(void *);

