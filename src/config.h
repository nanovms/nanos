/* identity-mapped space for initial page tables */
#define INITIAL_PAGES_SIZE (1 * MB)

/* The stage2 working heap needs to be large enough to accomodate all tfs
   allocations when loading the kernel. It gets recycled on stage3 entry. */
#define STAGE2_WORKING_HEAP_SIZE (4 * MB)

#define STAGE2_STACK_SIZE  (128 * KB)  /* stage2 stack is recycled, too */
#define KERNEL_STACK_SIZE  (128 * KB)  /* must match value in crt0.s */
#define EXCEPT_STACK_SIZE  (64 * KB)
#define INT_STACK_SIZE     (32 * KB)
#define BH_STACK_SIZE      (32 * KB)
#define SYSCALL_STACK_SIZE (32 * KB)

#define PAGE_INVAL_QUEUE_LENGTH  4096

/* maximum buckets that can fit within a PAGESIZE_2M mcache */
#define TABLE_MAX_BUCKETS 131072

/* runloop timer minimum and maximum */
#define RUNLOOP_TIMER_MAX_PERIOD_US     100000
#define RUNLOOP_TIMER_MIN_PERIOD_US     1000

/* length of thread scheduling queue */
#define MAX_THREADS 8192

/* could probably find progammatically via cpuid... */
#define DEFAULT_CACHELINE_SIZE 64

/* TFS stuff */
#define TFS_LOG_INITIAL_SIZE           SECTOR_SIZE
#define TFS_LOG_DEFAULT_EXTENSION_SIZE (512*KB)
#define TFS_LOG_FLUSH_DELAY_SECONDS 1
/* Minimum number of obsolete log entries needed to trigger a log compaction. */
#define TFS_LOG_COMPACT_OBSOLETE   8192
/* Log compaction is not triggered if the ratio between total entries and
 * obsolete entries is above the constant below. */
#define TFS_LOG_COMPACT_RATIO   2

/* Xen stuff */
#define XENNET_INIT_RX_BUFFERS_FACTOR 4
#define XENNET_RX_SERVICEQUEUE_DEPTH 512
#define XENNET_TX_SERVICEQUEUE_DEPTH 512

/* mm stuff */
#define PAGECACHE_DRAIN_CUTOFF (64 * MB)
#define PAGECACHE_SCAN_PERIOD_SECONDS 5
#define LOW_MEMORY_THRESHOLD   (64 * MB)

/* don't go below this minimum amount of physical memory when inflating balloon */
#define BALLOON_MEMORY_MINIMUM (16 * MB)

/* attempt to deflate balloon when physical memory is below this threshold */
#define BALLOON_DEFLATE_THRESHOLD (16 * MB)

/* must be large enough for vendor code that use malloc/free interface */
#define MAX_MCACHE_ORDER 16

/* ftrace buffer size */
#define DEFAULT_TRACE_ARRAY_SIZE        (512ULL << 20)

/* on-disk log dump section */
#define KLOG_DUMP_SIZE  (4 * KB)

/* debug parameters */
#define FRAME_TRACE_DEPTH 32
#define STACK_TRACE_DEPTH 32
