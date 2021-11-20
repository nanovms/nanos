#include <kernel.h>
#include <management.h>

typedef struct heaplock {
    struct heap h;
    struct spinlock lock;
    heap parent;
    heap meta;
    tuple mgmt;
    tuple parent_mgmt;
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

closure_function(1, 1, value, heaplock_get,
                 heaplock, hl,
                 symbol, s)
{
    lock_heap(bound(hl));
    value v = get(bound(hl)->parent_mgmt, s);
    unlock_heap(bound(hl));
    return v;
}

closure_function(1, 2, void, heaplock_set,
                 heaplock, hl,
                 symbol, s, value, v)
{
    lock_heap(bound(hl));
    set(bound(hl)->parent_mgmt, s, v);
    unlock_heap(bound(hl));
}

closure_function(1, 1, boolean, heaplock_iterate,
                 heaplock, hl,
                 binding_handler, h)
{
    lock_heap(bound(hl));
    boolean result = iterate(bound(hl)->parent_mgmt, h);
    unlock_heap(bound(hl));
    return result;
}

static value heaplock_management(heap h)
{
    heaplock hl = (heaplock)h;
    value v = hl->mgmt;         /* atomic, no lock */
    if (v)
        return v;

    v = timm("type", "heaplock");
    assert(v);
    tuple ft = allocate_function_tuple(closure(hl->meta, heaplock_get, hl),
                                       closure(hl->meta, heaplock_set, hl),
                                       closure(hl->meta, heaplock_iterate, hl));
    set(v, sym(parent), ft);

    value pm = heap_management(hl->parent);
    lock_heap(hl);
    hl->mgmt = v;
    hl->parent_mgmt = pm;
    unlock_heap(hl);
    return v;
}

/* meta only used on creation */
heap locking_heap_wrapper(heap meta, heap parent)
{
    heaplock hl = allocate(meta, sizeof(*hl));
    if (hl == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    hl->h.alloc = heaplock_alloc;
    hl->h.dealloc = heaplock_dealloc;
    hl->h.destroy = heaplock_destroy;
    hl->h.allocated = heaplock_allocated;
    hl->h.total = heaplock_total;
    hl->h.pagesize = parent->pagesize;
    hl->h.management = heaplock_management;
    hl->parent = parent;
    hl->meta = meta;
    hl->mgmt = 0;
    hl->parent_mgmt = 0;
    spin_lock_init(&hl->lock);
    return (heap)hl;
}
