/* identity-mapped space for initial page tables */
#define INITIAL_PAGES_SIZE (1 * MB)

/* The stage2 working heap needs to be large enough to accomodate all tfs
   allocations when loading the kernel. It gets recycled on stage3 entry. */
#define STAGE2_WORKING_HEAP_SIZE (4 * MB)
#define STAGE2_STACK_SIZE  (32 * KB)  /* stage2 stack is recycled, too */

/* stacks installed by machine or in asm entry */
#define EXCEPT_STACK_SIZE  (32 * KB)
#define INT_STACK_SIZE     (32 * KB)

/* contexts with embedded stacks */
#define KERNEL_CONTEXT_SIZE  (32 * KB)
#define SYSCALL_CONTEXT_SIZE (32 * KB)
#define PROCESS_CONTEXT_SIZE (32 * KB)

#define PAGE_INVAL_QUEUE_LENGTH  4096

/* maximum buckets that can fit within a PAGESIZE_2M mcache */
#define TABLE_MAX_BUCKETS 131072

/* runloop timer minimum and maximum */
#define RUNLOOP_TIMER_MAX_PERIOD_US     100000
#define RUNLOOP_TIMER_MIN_PERIOD_US     1000

/* length of thread scheduling queue */
#define MAX_THREADS 8192

/* size of free context queues */
#define FREE_KERNEL_CONTEXT_QUEUE_SIZE  8
#define FREE_SYSCALL_CONTEXT_QUEUE_SIZE 8
#define FREE_PROCESS_CONTEXT_QUEUE_SIZE 8

/* per-cpu queue */
#define CPU_QUEUE_SIZE 512

/* general scheduling queues */
#define BHQUEUE_SIZE       8192
#define RUNQUEUE_SIZE      8192
#define ASYNC_QUEUE_1_SIZE 65536

/* locking */
#define MUTEX_ACQUIRE_SPIN_LIMIT (1ull << 20)

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
#define MEM_CLEAN_THRESHOLD (64 * MB)
#define MEM_CLEAN_THRESHOLD_SHIFT   6
#define PAGECACHE_SCAN_PERIOD_SECONDS 5
#define PAGEHEAP_MEMORY_RESERVE         (8 * MB)
#define PAGEHEAP_LOWMEM_MEMORY_RESERVE  (4 * MB)
#define PAGEHEAP_LOWMEM_PAGESIZE        (1 * MB)
#define LOW_MEMORY_THRESHOLD   (64 * MB)
#define SG_FRAG_BYTE_THRESHOLD (128*KB)
#define PAGECACHE_MAX_SG_ENTRIES    8192

/* don't go below this minimum amount of physical memory when inflating balloon */
#define BALLOON_MEMORY_MINIMUM (16 * MB)

/* Number of objects that should be retained in the cache when a cache drain is requested */
#define NET_RX_BUFFERS_RETAIN           64
#define STORAGE_REQUESTS_RETAIN         64
#define PAGECACHE_PAGES_RETAIN          64
#define PAGECACHE_COMPLETIONS_RETAIN    64

/* must be large enough for vendor code that use malloc/free interface */
#define MAX_MCACHE_ORDER 16
#define MAX_LOWMEM_MCACHE_ORDER 11

/* ftrace buffer size */
#define DEFAULT_TRACE_ARRAY_SIZE        (512ULL << 20)

/* on-disk log dump section */
#define KLOG_DUMP_SIZE  (4 * KB)

/* debug parameters */
#define FRAME_TRACE_DEPTH 32
#define STACK_TRACE_DEPTH 32

/* how long to wait for program to exit on sigterm */
#define UNIX_SHUTDOWN_TIMEOUT_SECS 30

/* net parameters (not covered by lwipopts.h) */

/* number of iterations to spin for lwip lock acquire before suspending context */
#define LWIP_LOCK_SPIN_ITERATIONS (1ull << 16)
