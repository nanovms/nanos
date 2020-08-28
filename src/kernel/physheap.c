#include <kernel.h>
//#include <page.h>

/* these methods would hook into free page list / epoch stuff... */
#define phys_heap_lock() u64 _savedflags = spin_lock_irq(&phys_spinlock)
#define phys_heap_unlock() spin_unlock_irq(&phys_spinlock, _savedflags)

static struct spinlock phys_spinlock;
static id_heap phys_internal;

static u64 wrap_alloc(heap h, bytes b)
{
    phys_heap_lock();
    u64 r = allocate_u64((heap)phys_internal, b);
    phys_heap_unlock();
    return r;
}

static void wrap_dealloc(heap h, u64 a, bytes b)
{
    phys_heap_lock();
    deallocate_u64((heap)phys_internal, a, b);
    phys_heap_unlock();
}

static boolean wrap_add_range(id_heap i, u64 base, u64 length)
{
    phys_heap_lock();
    boolean r = id_heap_add_range(phys_internal, base, length);
    phys_heap_unlock();
    return r;
}

static boolean wrap_set_area(id_heap i, u64 base, u64 length, boolean validate, boolean allocate)
{
    phys_heap_lock();
    boolean r = id_heap_set_area(phys_internal, base, length, validate, allocate);
    phys_heap_unlock();
    return r;
}

static void wrap_set_randomize(id_heap i, boolean randomize)
{
    phys_heap_lock();
    id_heap_set_randomize(phys_internal, randomize);
    phys_heap_unlock();
}

static u64 wrap_alloc_subrange(id_heap i, bytes count, u64 start, u64 end)
{
    phys_heap_lock();
    u64 r = id_heap_alloc_subrange(phys_internal, count, start, end);
    phys_heap_unlock();
    return r;
}

/* don't need lock for these */
static u64 wrap_total(heap h)
{
    return phys_internal->total;
}

static u64 wrap_allocated(heap h)
{
    return phys_internal->allocated;
}

id_heap init_phys_heap(heap h, id_heap physical)
{
    spin_lock_init(&phys_spinlock);
    phys_internal = physical;
    id_heap i = allocate(h, sizeof(struct id_heap));
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    i->h.alloc = wrap_alloc;
    i->h.dealloc = wrap_dealloc;
    i->h.destroy = 0;
    i->h.allocated = wrap_allocated;
    i->h.total = wrap_total;
    i->h.pagesize = physical->h.pagesize;
    i->add_range = wrap_add_range;
    i->set_area = wrap_set_area;
    i->set_randomize = wrap_set_randomize;
    i->alloc_subrange = wrap_alloc_subrange;
    return i;
}
