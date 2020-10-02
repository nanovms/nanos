#include <runtime.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>

#ifdef __aarch64__
#include <sys/prctl.h>
#endif

//#define TAG_HEAP_DEBUG
#ifdef TAG_HEAP_DEBUG
#define tag_debug(x, ...) do {rprintf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define tag_debug(x, ...)
#endif

/* Helper functions to ignore unused result (eliminate CC warning) */
static inline void igr(int x) {}

timestamp timeval_to_time(struct timeval *a)
{
    return((((unsigned long long)a->tv_sec)<<32)|
           (((unsigned long long)a->tv_usec)<<32)/1000000);
}

/* For unix target, just leave rtc offset as zero and treat
   gettimeofday() as monotonic. We can revisit if we ever care about
   truly monotonic time in unit test land. */

clock_now platform_monotonic_now;

void *malloc(size_t size);
void free(void *ptr);

u64 random_seed()
{
    return random();
}

static u64 bytes_allocated;

static u64 allocated(heap h)
{
    return bytes_allocated;
}

static void malloc_free(heap h, u64 z, bytes length)
{
    assert(bytes_allocated >= length);
    bytes_allocated -= length;
    free(pointer_from_u64(z));
}

static u64 malloc_alloc(heap h, bytes s)
{
    bytes_allocated += s;
    void *p = malloc(s);
    return p ? (u64)p : INVALID_PHYSICAL;
}

heap malloc_allocator()
{
    heap h = malloc(sizeof(struct heap));
    h->alloc = malloc_alloc;
    h->dealloc = malloc_free;
    h->destroy = 0;
    h->pagesize = PAGESIZE;
    h->allocated = allocated;
    h->total = 0;
    bytes_allocated = 0;
    return h;
}

void halt(char *format, ...)
{
    buffer z = little_stack_buffer(500);
    vlist a;
    vstart(a, format);
    vbprintf(z, alloca_wrap_buffer(format, runtime_strlen(format)), &a);
    igr(write(1, buffer_ref(z, 0), buffer_length(z)));
    exit(2);
}

#ifndef __aarch64__
static heap allocate_tagged_region(heap h, u64 tag)
{
    u64 size = 256 * MB;
    void *region = mmap(pointer_from_u64(tag << VA_TAG_OFFSET),
                        size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    return (heap)create_id_heap(h, h, u64_from_pointer(region), size, 1, false);
}
#else
struct tagheap {
    struct heap h;
    heap mh;
    u64 vtag;
};

static void tag_dealloc(heap h, u64 a, bytes s)
{
    struct tagheap *th = (struct tagheap *)h;
    tag_debug("tag %d, a 0x%lx, s 0x%lx\n", th->vtag >> VA_TAG_OFFSET, a, s);
    deallocate_u64(th->mh, a & MASK(48), s);
}

static u64 tag_alloc(heap h, bytes s)
{
    struct tagheap *th = (struct tagheap *)h;
    void *p = allocate(th->mh, s);
    if (p == INVALID_ADDRESS)
        return INVALID_PHYSICAL;
    u64 a = u64_from_pointer(p);
    assert((a >> VA_TAG_OFFSET) == 0);
    a |= th->vtag;
    tag_debug("tag %d, s 0x%lx, a 0x%lx\n", th->vtag >> VA_TAG_OFFSET, s, a);
    return a;
}

#define PR_SET_TAGGED_ADDR_CTRL      55
#define PR_TAGGED_ADDR_ENABLE        (1UL << 0)

static heap allocate_tagged_region(heap h, u64 tag)
{
    static boolean abi_init = false;
    if (!abi_init) {
        abi_init = true;
        int rv = prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0);
        if (rv < 0)
            halt("prctl failed on PR_SET_TAGGED_ADDR_CTRL %d (%s)\n", errno, strerror(errno));
    }
    struct tagheap *th = allocate(h, sizeof(struct tagheap));
    if (th == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    assert(tag < 256);
    th->mh = h;
    th->vtag = tag << VA_TAG_OFFSET;
    th->h.alloc = tag_alloc;
    th->h.dealloc = tag_dealloc;
    th->h.destroy = 0;
    th->h.pagesize = 32; // XXX
    th->h.allocated = 0;
    th->h.total = 0;
    tag_debug("tag %d, bits 0x%lx, heap %p\n", tag, th->vtag, th);
    return &th->h;
}
#endif

extern void init_extra_prints();

/* ignore clock id for unix tests */
closure_function(0, 0, timestamp, unix_now)
{
    struct timeval result;
    gettimeofday(&result,0);
    return timeval_to_time(&result);
}

// 64 bit unix process
heap init_process_runtime()
{
    heap h = malloc_allocator();
    platform_monotonic_now = closure(h, unix_now);
    init_random();
    init_runtime(h);
    init_tuples(allocate_tagged_region(h, tag_tuple));
    init_symbols(allocate_tagged_region(h, tag_symbol), h);
    init_sg(h);
    init_extra_prints();
    signal(SIGPIPE, SIG_IGN);
    return h;
}

void console_write(const char *s, bytes count)
{
    igr(write(1, s, count));
}

u64 physical_from_virtual(void *__x)
{
    return u64_from_pointer(__x);
}

tuple parse_arguments(heap h, int argc, char **argv)
{
    tuple t = allocate_tuple();
    vector unassociated = 0;
    symbol tag = 0;
    for (int i = 1; i<argc; i++) {
        buffer b = wrap_buffer_cstring(h, argv[i]);
        if (*argv[i] == '-') {
            b->start++;
            tag = intern(b);
        } else {
            if (tag) {
                table_set(t, tag, b);
                tag = 0;
            } else {
                if (!unassociated) {
                    unassociated = allocate_vector(h, 10);
                }
                vector_push(unassociated, b);
            }
        }
    }
    if (unassociated)
        table_set(t, sym(unassociated), tuple_from_vector(unassociated));

    return t;
}

void print_stack_from_here()
{
    // empty for now
}
