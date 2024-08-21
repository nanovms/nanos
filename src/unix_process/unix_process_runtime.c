#include <runtime.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>

#if defined(__aarch64__) && !defined(__APPLE__)
#include <sys/prctl.h>
#endif

//#define TAG_HEAP_DEBUG
#ifdef TAG_HEAP_DEBUG
#define tag_debug(x, ...) do {rprintf("%s: " x, func_ss, ##__VA_ARGS__);} while(0)
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

u64 hw_get_seed()
{
    return random();
}

static heap malloc_heap;
static u64 bytes_allocated;

static u64 allocated(heap h)
{
    return bytes_allocated;
}

#ifndef __aarch64__

static void malloc_free(heap h, u64 z, bytes length)
{
    assert(bytes_allocated >= length);
    bytes_allocated -= length;
    free(pointer_from_u64(z - 8));
}

static u64 malloc_alloc(heap h, bytes s)
{
    void *p = malloc(s + 8);    /* 8 bytes to preserve 64-bit alignment */
    if (p) {
        bytes_allocated += s;
        return u64_from_pointer(tag(p + 8, tag_unknown));
    } else {
        return INVALID_PHYSICAL;
    }
}

#else

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

#endif

heap malloc_allocator()
{
    heap h = malloc(sizeof(struct heap));
    h->alloc = malloc_alloc;
    h->dealloc = malloc_free;
    h->destroy = 0;
    h->pagesize = PAGESIZE;
    h->allocated = allocated;
    h->total = 0;
    h->management = 0;
    malloc_heap = h;
    bytes_allocated = 0;
    return h;
}

void halt_with_code(u8 code, sstring format, ...)
{
    buffer z = little_stack_buffer(500);
    vlist a;
    vstart(a, format);
    vbprintf(z, format, &a);
    igr(write(1, buffer_ref(z, 0), buffer_length(z)));
    exit(2);
}

struct tagheap {
    struct heap h;
    heap mh;
    u64 tag;
};

static void tag_dealloc(heap h, u64 a, bytes s)
{
    struct tagheap *th = (struct tagheap *)h;
    tag_debug("tag %d, a 0x%lx, s 0x%lx\n", th->tag, a, s);
    deallocate_u64(th->mh, a & MASK(48), s);
}

static u64 tag_alloc(heap h, bytes s)
{
    struct tagheap *th = (struct tagheap *)h;
    void *p = allocate(th->mh, s);
    if (p == INVALID_ADDRESS)
        return INVALID_PHYSICAL;
    tag_debug("tag %d, s 0x%lx, p %p\n", th->tag, s, p);
    return u64_from_pointer(tag(p, th->tag));
}

static heap allocate_tagged_region(heap h, u64 tag)
{
#if defined(__aarch64__) && !defined(__APPLE__)
#define PR_SET_TAGGED_ADDR_CTRL      55
#define PR_TAGGED_ADDR_ENABLE        (1UL << 0)
    static boolean abi_init = false;
    if (!abi_init) {
        abi_init = true;
        int rv = prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0);
        if (rv < 0)
            halt("prctl failed on PR_SET_TAGGED_ADDR_CTRL %d (%s)\n", errno, errno_sstring());
    }
#endif
    struct tagheap *th = allocate(h, sizeof(struct tagheap));
    if (th == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    assert(tag < 256);
    th->mh = h;
    th->tag = tag;
    th->h.alloc = tag_alloc;
    th->h.dealloc = tag_dealloc;
    th->h.destroy = 0;
    th->h.pagesize = 32; // XXX
    th->h.allocated = 0;
    th->h.total = 0;
    th->h.management = 0;
    tag_debug("tag %d, bits 0x%lx, heap %p\n", tag, th->tag, th);
    return &th->h;
}

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
    init_random(h);
    init_runtime(h, h);
    init_integers(allocate_tagged_region(h, tag_integer));
    init_tuples(allocate_tagged_region(h, tag_table_tuple));
    init_symbols(allocate_tagged_region(h, tag_symbol), h);
    init_vectors(allocate_tagged_region(h, tag_vector), h);
    init_strings(allocate_tagged_region(h, tag_string), h);
    init_sg(h);
    init_extra_prints();
    signal(SIGPIPE, SIG_IGN);
    return h;
}

sstring errno_sstring(void)
{
    sstring s = {
        .ptr = strerror(errno),
    };
    s.len = strlen(s.ptr);
    return s;
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
        string s = wrap_string(argv[i], strlen(argv[i]));
        if (*argv[i] == '-') {
            s->start++;
            tag = intern(s);
        } else {
            if (tag) {
                set(t, tag, s);
                tag = 0;
            } else {
                if (!unassociated) {
                    unassociated = allocate_tagged_vector(10);
                }
                vector_push(unassociated, s);
            }
        }
    }
    if (unassociated)
        set(t, sym(unassociated), unassociated);

    return t;
}

void print_frame_trace_from_here()
{
    // empty for now
}
