/* This heap wrapper creates a view of the parent heap where the parent heap's total
 * memory is reduced by the reserved amount specified at initialization. This
 * prevents the wrapped heap from exhausting the parent heap.
 */
#include <runtime.h>
#include <management.h>

typedef struct reservelock {
    union {
        struct heap h;
        struct backed_heap bh;
    };
    heap parent;
    heap meta;
    bytes reserved;
    tuple mgmt;
} *reservelock;

static u64 reservelock_alloc(heap h, bytes size)
{
    reservelock rl = (reservelock)h;
    if (heap_free(rl->parent) < rl->reserved + size)
        return INVALID_PHYSICAL;
    return allocate_u64(rl->parent, size);
}

static void reservelock_dealloc(heap h, u64 x, bytes size)
{
    reservelock rl = (reservelock)h;
    rl->parent->dealloc(rl->parent, x, size);
}

static void reservelock_destroy(heap h)
{
    reservelock rl = (reservelock)h;
    deallocate(rl->meta, rl, sizeof(*rl));
}

static bytes reservelock_allocated(heap h)
{
    reservelock rl = (reservelock)h;
    return rl->parent->allocated(rl->parent);
}

static bytes reservelock_total(heap h)
{
    reservelock rl = (reservelock)h;
    bytes t = rl->parent->total(rl->parent);
    assert(t > rl->reserved);
    return t - rl->reserved;
}

closure_function(2, 0, value, reservelock_get_allocated,
                 reservelock, rl, value, v)
{
    return value_rewrite_u64(bound(v), heap_allocated((heap)bound(rl)));
}

closure_function(2, 0, value, reservelock_get_total,
                 reservelock, rl, value, v)
{
    return value_rewrite_u64(bound(v), reservelock_total((heap)bound(rl)));
}

closure_function(2, 0, value, reservelock_get_free,
                 reservelock, rl, value, v)
{
    return value_rewrite_u64(bound(v), heap_free((heap)bound(rl)));
}

#define register_stat(rl, n, t, name)                                   \
    v = value_from_u64(0);                                              \
    s = sym(name);                                                      \
    set(t, s, v);                                                       \
    tuple_notifier_register_get_notify(n, s, closure(rl->meta, reservelock_get_ ##name, rl, v));

static value reservelock_management(heap h)
{
    reservelock rl = (reservelock)h;
    if (rl->mgmt)
        return rl->mgmt;
    value v;
    symbol s;
    tuple t = timm("type", "reservelock", "pagesize", "%d", rl->h.pagesize);
    assert(t != INVALID_ADDRESS);
    tuple_notifier n = tuple_notifier_wrap(t, false);
    assert(n != INVALID_ADDRESS);
    register_stat(rl, n, t, allocated);
    register_stat(rl, n, t, total);
    register_stat(rl, n, t, free);
    rl->mgmt = (tuple)n;
    return n;
}

void *reservelock_alloc_map(backed_heap bh, bytes len, u64 *phys)
{
    reservelock rl = (reservelock)bh;
    if (heap_free(rl->parent) < rl->reserved + len)
        return INVALID_ADDRESS;
    return alloc_map((backed_heap)rl->parent, len, phys);
}

void reservelock_dealloc_unmap(backed_heap bh, void *virt, u64 phys, bytes len)
{
    reservelock rl = (reservelock)bh;
    dealloc_unmap((backed_heap)rl->parent, virt, phys, len);
}

heap reserve_heap_wrapper(heap meta, heap parent, bytes reserved)
{
    reservelock rl = allocate(meta, sizeof(*rl));
    if (rl == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    assert(parent->total && parent->allocated && heap_free(parent) > reserved);
    rl->h.alloc = reservelock_alloc;
    rl->h.dealloc = reservelock_dealloc;
    rl->h.destroy = reservelock_destroy;
    rl->h.allocated = reservelock_allocated;
    rl->h.total = reservelock_total;
    rl->h.pagesize = parent->pagesize;
    rl->h.management = reservelock_management;
    rl->parent = parent;
    rl->meta = meta;
    rl->reserved = reserved;
    rl->mgmt = 0;
    return (heap)rl;
}

backed_heap reserve_backed_heap_wrapper(heap meta, backed_heap parent, bytes reserved)
{
    reservelock rl = (reservelock)reserve_heap_wrapper(meta, (heap)parent, reserved);
    if (rl == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    rl->bh.alloc_map = reservelock_alloc_map;
    rl->bh.dealloc_unmap = reservelock_dealloc_unmap;
    return (backed_heap)rl;
}
