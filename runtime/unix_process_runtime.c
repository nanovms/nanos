#include <runtime.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

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
}

heap allocate_tagged_region(heap h, u64 tag)
{
    u64 size = 4*1024*1024;
    void *region = mmap(pointer_from_u64(tag << va_tag_offset),
                        size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    // use a specific growable heap
    return create_id_heap(h, u64_from_pointer(region), size, 1);
}

extern void init_extra_prints();
    
// 64 bit unix process                  
heap init_process_runtime()
{
    heap h = malloc_allocator();
    init_runtime(h);
    init_extra_prints();
    return h;
}
