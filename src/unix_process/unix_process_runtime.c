#include <runtime.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>

/* Helper functions to ignore unused result (eliminate CC warning) */
static inline void igr(int x) {}

void *malloc(size_t size);
void free(void *ptr);

timestamp timeval_to_time(struct timeval *a)
{
    return((((unsigned long long)a->tv_sec)<<32)|
           (((unsigned long long)a->tv_usec)<<32)/1000000);
}

timestamp now()
{
    struct timeval result;

    gettimeofday(&result,0);
    return(timeval_to_time(&result));
}

u64 random_seed()
{
    return random();
}

static void malloc_free(heap h, u64 z, bytes length)
{
    free(pointer_from_u64(z));
}

static u64 malloc_alloc(heap h, bytes s)
{
    return (u64)malloc(s);
}

heap malloc_allocator()
{
    heap h = malloc(sizeof(struct heap));
    h->alloc = malloc_alloc;
    h->dealloc = malloc_free;
    h->destroy = 0;
    h->pagesize = PAGESIZE;
    h->allocated = 0;
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

heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    u64 size = 4*1024*1024;
    void *region = mmap(pointer_from_u64(tag << va_tag_offset),
                        size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    // use a specific growable heap
    return create_id_heap(heap_general(kh), u64_from_pointer(region), size, 1);
}

// xxx - not the kernel
static struct kernel_heaps heaps; /* really just for init_runtime() */

extern void init_extra_prints();

// 64 bit unix process
heap init_process_runtime()
{
    heaps.general = malloc_allocator();
    init_random();
    init_runtime(&heaps);
    init_extra_prints();
    signal(SIGPIPE, SIG_IGN);
    return heaps.general;
}

void console_write(char *s, bytes count)
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
