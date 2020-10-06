#include <kernel.h>

typedef struct heaplock {
    struct heap h;
    struct spinlock lock;
    heap parent;
    heap meta;
} *heaplock;

#define lock_heap(hl) u64 _flags = spin_lock_irq(&hl->lock)
#define unlock_heap(hl) spin_unlock_irq(&hl->lock, _flags)

static u64 heaplock_alloc(heap h, bytes size)
{
    heaplock hl = (heaplock)h;
    lock_heap(hl);
    u64 a = allocate_u64(hl->parent, size);
    unlock_heap(hl);
    return a;
}

static void heaplock_dealloc(heap h, u64 x, bytes size)
{
    heaplock hl = (heaplock)h;
    lock_heap(hl);
    deallocate_u64(hl->parent, x, size);
    unlock_heap(hl);
}

/* assuming no contention on destroy */
static void heaplock_destroy(heap h)
{
    heaplock hl = (heaplock)h;
    destroy_heap(hl->parent);
    deallocate(hl->meta, hl, sizeof(*hl));
}

static bytes heaplock_allocated(heap h)
{
    heaplock hl = (heaplock)h;
    lock_heap(hl);
    bytes count = heap_allocated(hl->parent);
    unlock_heap(hl);
    return count;
}

static bytes heaplock_total(heap h)
{
    heaplock hl = (heaplock)h;
    lock_heap(hl);
    bytes count = heap_total(hl->parent);
    unlock_heap(hl);
    return count;
}

/* meta only used on creation */
heap locking_heap_wrapper(heap meta, heap parent, bytes size)
{
    heaplock hl = allocate(meta, sizeof(*hl));
    if (hl == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    hl->h.alloc = heaplock_alloc;
    hl->h.dealloc = heaplock_dealloc;
    hl->h.destroy = heaplock_destroy;
    hl->h.allocated = heaplock_allocated;
    hl->h.total = heaplock_total;
    hl->h.pagesize = size;
    hl->parent = parent;
    spin_lock_init(&hl->lock);
    return (heap)hl;
}
