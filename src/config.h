/* identity-mapped space for initial page tables */
#define INITIAL_PAGES_SIZE (64 * KB)

/* the stage2 secondary working heap - this needs to be large enough
   to accomodate all tfs allocations when loading the kernel - it gets
   recycled in stage3, so be generous */
#define STAGE2_WORKING_HEAP_SIZE (128 * MB)

#define STAGE2_STACK_SIZE  (128 * KB)  /* stage2 stack is recycled, too */
#define KERNEL_STACK_SIZE  (128 * KB)  /* must match value in crt0.s */
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
#define TFS_LOG_FLUSH_DELAY_SECONDS 1

/* Xen stuff */
#define XENNET_INIT_RX_BUFFERS_FACTOR 4
#define XENNET_RX_SERVICEQUEUE_DEPTH 512
#define XENNET_TX_SERVICEQUEUE_DEPTH 512

/* mm stuff */
#define PAGECACHE_DRAIN_CUTOFF (64 * MB)
#define PAGECACHE_SCAN_PERIOD_SECONDS 5
