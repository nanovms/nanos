#include <runtime.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>

void debug(buffer b)
{
    write(2, b->contents, buffer_length(b));
}

void print_u64(u64 x)
{
}

void console(char *x)
{
}

time now()
{
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

typedef struct inc_heap {
    struct heap h;
    u64 length;
    u64 base;
} *inc_heap;

static u64 inc_alloc(heap h, bytes count)
{
    inc_heap i = (inc_heap)h;
    u64 result = i->base;
    i->base += pad(count, h->pagesize);
    return result;
}

heap create_inc_heap(heap h, u64 base, u64 length, u64 pagesize)
{
    inc_heap i = allocate(h, sizeof(struct inc_heap));
    i->base = base;
    i->h.alloc = inc_alloc;
    i->h.dealloc = leak;
    i->h.pagesize = pagesize;    
    return((heap)i);
}

heap allocate_tagged_region(heap h, u64 tag)
{
    u64 size = 4*1024*1024;
    void *region = mmap(pointer_from_u64(tag << va_tag_offset),
                        size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    // use a specific growable heap
    return create_inc_heap(h, u64_from_pointer(region), size, 1);
}

extern void init_extra_prints();

static void format_errno(buffer dest, buffer fmt, vlist *a)
{
    char *e = strerror(varg(*a, int));
    int len = runtime_strlen(e);
    buffer_write(dest, e, len);
}

// 64 bit unix process                  
heap init_process_runtime()
{
    heap h = malloc_allocator();
    init_runtime(h);
    init_extra_prints();
    // unix errno print formatter
    register_format('E', format_errno);       
    return h;
}

void serial_out(u8 k)
{
    write(1, &k, 1);
}


u64 physical_from_virtual(void *__x)
{
    return u64_from_pointer(__x);
}

