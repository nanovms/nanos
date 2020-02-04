#include <runtime.h>

typedef struct freelist {
    struct heap h;
    u64 count;
    u64 total;
    heap parent;
    void *free;
    u64 size;
} *freelist;

static u64 freelist_allocated(heap h)
{
    return ((freelist)h)->count;
}

static u64 freelist_total(heap h)
{
    return ((freelist)h)->total;
}

static void freelist_deallocate(heap h, u64 x, bytes size)
{
    freelist f = (freelist)h;
    *(void **)pointer_from_u64(x) = f->free;
    f->free = pointer_from_u64(x);
    //    rprintf("freelist deallocate %p\n", x);
    size = MAX(size, sizeof(void *));
    assert(f->count >= size);
    f->count -= size;
}

static u64 freelist_allocate(heap h, bytes size)
{
    freelist f = (freelist)h;
    if (size != f->size) {
        console("bad unsized allocator ");
        print_u64(size);
        console(" ");
        print_u64(f->size);
        console(" ");
        print_u64(u64_from_pointer(__builtin_return_address(0)));        
        console("\n");
	return INVALID_PHYSICAL;
    }

    size = MAX(size, sizeof(void *));
    f->count += size;
    if (!f->free) {
        //        console("freelist spill\n");
        f->total += size;
        return allocate_u64(f->parent, size);
    }
    //    console("freelist cached\n");
    void *result = f->free;
    f->free = *(void **)f->free;
    return u64_from_pointer(result);
}

heap wrap_freelist(heap meta, heap parent, bytes size)
{
    freelist f = allocate(meta, sizeof(struct freelist));
    f->h.alloc = freelist_allocate;
    f->h.dealloc = freelist_deallocate;
    f->h.destroy = 0;
    f->h.allocated = freelist_allocated;
    f->h.total = freelist_total;
    f->h.pagesize = size; // not necessarily a power of two
    f->count = 0;
    f->total = 0;
    f->parent = parent;
    f->free = 0;
    f->size = size;
    return ((heap)f);
}
