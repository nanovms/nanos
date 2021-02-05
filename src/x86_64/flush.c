#include <kernel.h>
#include <apic.h>

#define FLUSH_THRESHOLD 32
#define MAX_FLUSH_ENTRIES 1024
#define COMP_QUEUE_SIZE (MAX_FLUSH_ENTRIES*2)
#define ENTRIES_SERVICE_THRESHOLD (MAX_FLUSH_ENTRIES/2)

static boolean initialized = false;
static int flush_ipi;
static heap flush_heap;
static volatile word inval_gen;
static queue free_flush_entries;
static struct list entries;
static int entries_count;
static volatile boolean service_scheduled;
static thunk flush_service;
static queue flush_completion_queue;
static struct rw_spinlock flush_lock;

static void queue_flush_service();

declare_closure_struct(1, 0, void, flush_complete,
    flush_entry, f);

struct flush_entry {
    struct list l;
    u64 gen;
    u64 cpu_mask;
    struct refcount ref;
    boolean flush;
    u64 pages[FLUSH_THRESHOLD];
    int npages;
    thunk completion;
    closure_struct(flush_complete, finish);
};

static void invalidate (u64 page)
{
    asm volatile("invlpg (%0)" :: "r" (page) : "memory");
}

define_closure_function(1, 0, void, flush_complete, flush_entry, f)
{
    flush_entry f = bound(f);
    assert(f->cpu_mask == 0);
    queue_flush_service();
}

/* must be called with interrupts off */
static void _flush_handler(void)
{
    cpuinfo ci = current_cpu();
    /* Each generation has at least one page, so if the gen difference is
     * greater than FLUSH_THRESHOLD, just do a full tlb flush */
    boolean full_flush = inval_gen - ci->inval_gen > FLUSH_THRESHOLD;

    spin_rlock(&flush_lock);
    while (ci->inval_gen != inval_gen) {
        word oldgen = ci->inval_gen;
        ci->inval_gen = inval_gen;
        list_foreach(&entries, l) {
            flush_entry f = struct_from_list(l, flush_entry, l);
            if (f->gen <= oldgen)
                continue;
            if (f->gen > ci->inval_gen)
                break;
            if (!full_flush) {
                if (f->flush)
                    full_flush = true;
                else {
                    for (int i = 0; i < f->npages; i++)
                        invalidate(f->pages[i]);
                }
            }
            atomic_clear_bit(&f->cpu_mask, ci->id);
            refcount_release(&f->ref);
        }
    }
    spin_runlock(&flush_lock);

    if (full_flush)
        flush_tlb();
}

closure_function(0, 0, void, flush_handler)
{
    _flush_handler();
}

void page_invalidate_flush()
{
    _flush_handler();
}

void page_invalidate(flush_entry f, u64 p)
{
    if (initialized) {
        if (f->flush)
            return;
        f->pages[f->npages++] = p;
        if (f->npages >= FLUSH_THRESHOLD)
            f->flush = true;
    } else {
        invalidate(p);
    }
}

static void service_list(boolean trydefer)
{
    list_foreach(&entries, l) {
        flush_entry f = struct_from_list(l, flush_entry, l);
        if (f->ref.c > 0)
            continue;
        list_delete(&f->l);
        entries_count--;
        if (trydefer) {
            if (!enqueue(flush_completion_queue, f->completion))
                apply(f->completion);
        } else
            apply(f->completion);
        assert(enqueue(free_flush_entries, f));
    }
}

closure_function(0, 0, void, do_flush_service)
{
    thunk c;

    while (service_scheduled) {
        service_scheduled = false;
        u64 flags = spin_wlock_irq(&flush_lock);
        service_list(false);
        spin_wunlock_irq(&flush_lock, flags);
        while ((c = dequeue(flush_completion_queue)) != INVALID_ADDRESS) {
            apply(c);
        }
    }
}

static void queue_flush_service()
{
    if (!service_scheduled) {
        service_scheduled = true;
        assert(enqueue(runqueue, flush_service));
    }
}

/* N.B. It is possible for the completion to be run with flush_lock held in
 * low flush resource situations, so it must not invoke operations that
 * could call page_invalidate_sync again or else face deadlock.
 */
void page_invalidate_sync(flush_entry f, thunk completion)
{
    if (initialized) {
        if (f->npages == 0) {
            assert(enqueue(free_flush_entries, f));
            if (completion && completion != ignore) {
                assert(enqueue(flush_completion_queue, completion));
                queue_flush_service();
            }
            return;
        }
        f->cpu_mask = MASK(total_processors);
        init_refcount(&f->ref, total_processors, init_closure(&f->finish, flush_complete, f));
        f->completion = completion;

        u64 flags = irq_disable_save();
        spin_wlock(&flush_lock);

        /* The service thunk doesn't always get a chance to run before
         * running out of flush resources, so proactively service the list */
        if (entries_count > ENTRIES_SERVICE_THRESHOLD)
            service_list(true);

        /* Set flush true on all previous entries to avoid wasted
         * invalidations if this entry causes a flush */
        if (f->flush) {
            list_foreach(&entries, l) {
                flush_entry ff = struct_from_list(l, flush_entry, l);
                if (!ff->flush)
                    ff->flush = true;
            }
        }
        list_push_back(&entries, &f->l);
        entries_count++;
        f->gen = fetch_and_add((word *)&inval_gen, 1) + 1;
        spin_wunlock(&flush_lock);

        apic_ipi(TARGET_EXCLUSIVE_BROADCAST, 0, flush_ipi);
        _flush_handler();
        irq_restore(flags);
    } else {
        if (completion)
            apply(completion);
    }
}

flush_entry get_page_flush_entry()
{
    flush_entry fe;

    if (!initialized)
        return 0;

    u64 flags = irq_disable_save();
    /* Do the flush work here if this cpu gets too far behind which
        * can happen with large mapping operations */
    if (inval_gen - current_cpu()->inval_gen > FLUSH_THRESHOLD)
        _flush_handler();
    irq_restore(flags);

    /* This spins because it must succeed */
    while ((fe = dequeue(free_flush_entries)) == INVALID_ADDRESS)
        kern_pause();

    assert(fe != INVALID_ADDRESS);
    runtime_memset((void *)fe, 0, sizeof(*fe));
    return fe;
}

void init_flush(heap h)
{
    flush_ipi = allocate_interrupt();
    register_interrupt(flush_ipi, closure(h, flush_handler), "flush ipi");
    flush_heap = h;
    list_init(&entries);
    flush_service = closure(flush_heap, do_flush_service);
    free_flush_entries = allocate_queue(flush_heap, MAX_FLUSH_ENTRIES + 1);
    flush_completion_queue = allocate_queue(flush_heap, COMP_QUEUE_SIZE);
    flush_entry fa = allocate(flush_heap, sizeof(struct flush_entry) * MAX_FLUSH_ENTRIES);
    assert(fa);
    for (flush_entry f = fa; f < fa + MAX_FLUSH_ENTRIES; f++)
        assert(enqueue(free_flush_entries, f));
    initialized = true;
}

