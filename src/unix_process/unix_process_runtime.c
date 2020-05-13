#include <runtime.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>

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
    return (u64)malloc(s);
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

static heap allocate_tagged_region(heap h, u64 tag)
{
    u64 size = 256 * MB;
    void *region = mmap(pointer_from_u64(tag << VA_TAG_OFFSET),
                        size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    return (heap)create_id_heap(h, h, u64_from_pointer(region), size, 1);
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
