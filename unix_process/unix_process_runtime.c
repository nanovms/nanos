#include <runtime.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <signal.h>

// xxx - can't use <time.h> because of redefinition of time

extern int gettimeofday(struct timeval *tv, void *tz);

void debug(buffer b)
{
    write(2, b->contents, buffer_length(b));
}

static char hex[]="0123456789abcdef";

void print_u64(u64 s)
{
    for (int x = 60; x >= 0; x -= 4)
        write(2, &hex[(s >> x)&0xf], 1);
}

void console(char *x)
{
    write(2, x, runtime_strlen(x));
}


time timeval_to_time(struct timeval *a)
{
    return((((unsigned long long)a->tv_sec)<<32)|
           (((unsigned long long)a->tv_usec)<<32)/1000000);
}

time now()
{
    struct timeval result;
    
    gettimeofday(&result,0);
    return(timeval_to_time(&result));
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
    return h;
}

void halt(char *format, ...)
{
    buffer z = little_stack_buffer(500);
    vlist a;
    vstart(a, format);
    vbprintf(z, alloca_wrap_buffer(format, runtime_strlen(format)), &a);
    write(1, buffer_ref(z, 0), buffer_length(z));
    exit(-1);
}

heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    u64 size = 4*1024*1024;
    void *region = mmap(pointer_from_u64(tag << va_tag_offset),
                        size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    // use a specific growable heap
    return create_id_heap(heap_general(kh), u64_from_pointer(region), size, 1);
}


static void format_errno(buffer dest, buffer fmt, vlist *a)
{
    char *e = strerror(varg(*a, int));
    int len = runtime_strlen(e);
    buffer_write(dest, e, len);
}

// xxx - not the kernel
static struct kernel_heaps heaps; /* really just for init_runtime() */

extern void init_extra_prints();

// 64 bit unix process                  
heap init_process_runtime()
{
    heaps.general = malloc_allocator();
    init_runtime(&heaps);
    init_extra_prints();
    signal(SIGPIPE, SIG_IGN);
    // unix errno print formatter
    register_format('E', format_errno);       
    return heaps.general;
}

void serial_out(u8 k)
{
    write(1, &k, 1);
}


u64 physical_from_virtual(void *__x)
{
    return u64_from_pointer(__x);
}

