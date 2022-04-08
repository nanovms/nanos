#include <kernel.h>

#define FLUSH_THRESHOLD 32
#define MAX_FLUSH_ENTRIES 1024
#define COMP_QUEUE_SIZE (MAX_FLUSH_ENTRIES*2)
#define ENTRIES_SERVICE_THRESHOLD (MAX_FLUSH_ENTRIES/2)

BSS_RO_AFTER_INIT static boolean initialized;
BSS_RO_AFTER_INIT static int flush_ipi;
static volatile word inval_gen;
BSS_RO_AFTER_INIT static queue free_flush_entries;
static struct list entries;
static int entries_count;
static volatile boolean service_scheduled;
BSS_RO_AFTER_INIT static thunk flush_service;
BSS_RO_AFTER_INIT static queue flush_completion_queue;
static struct rw_spinlock flush_lock;

static void queue_flush_service(void);

declare_closure_struct(1, 0, void, flush_complete,
    flush_entry, f);

struct flush_entry {
    struct list l;
    u64 gen;
    struct refcount ref;
    boolean flush;
    u64 pages[FLUSH_THRESHOLD];
    int npages;
    status_handler completion;
    closure_struct(flush_complete, finish);
};

define_closure_function(1, 0, void, flush_complete, flush_entry, f)
{
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
            refcount_release(&f->ref);
        }
    }
    spin_runlock(&flush_lock);

    flush_tlb(full_flush);
}

closure_function(0, 0, void, flush_handler)
{
    _flush_handler();
}

void page_invalidate_flush(void)
{
    if (initialized)
        _flush_handler();
}

void page_invalidate(flush_entry f, u64 p)
{
    if (f && initialized) {
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
        if (f->completion) {
            if (trydefer) {
                if (!enqueue(flush_completion_queue, f->completion))
                    async_apply_status_handler(f->completion, STATUS_OK);
            } else {
                async_apply_status_handler(f->completion, STATUS_OK);
            }
        }
        assert(enqueue(free_flush_entries, f));
    }
}

closure_function(0, 0, void, do_flush_service)
{
    status_handler c;

    while (service_scheduled) {
        service_scheduled = false;
        u64 flags = spin_wlock_irq(&flush_lock);
        service_list(false);
        spin_wunlock_irq(&flush_lock, flags);
        while ((c = dequeue(flush_completion_queue)) != INVALID_ADDRESS)
            async_apply_status_handler(c, STATUS_OK);
    }
}

static void queue_flush_service(void)
{
    if (!service_scheduled) {
        service_scheduled = true;
        assert(enqueue_irqsafe(bhqueue, flush_service));
    }
}

/* N.B. It is possible for the completion to be run with flush_lock held in
 * low flush resource situations, so it must not invoke operations that
 * could call page_invalidate_sync again or else face deadlock.
 */
void page_invalidate_sync(flush_entry f, status_handler completion)
{
    if (initialized) {
        if (f->npages == 0) {
            assert(enqueue(free_flush_entries, f));
            if (completion) {
                assert(enqueue(flush_completion_queue, completion));
                queue_flush_service();
            }
            return;
        }
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

        send_ipi(TARGET_EXCLUSIVE_BROADCAST, flush_ipi);
        _flush_handler();
        irq_restore(flags);
    } else {
        flush_tlb(false);
        if (completion)
            async_apply_status_handler(completion, STATUS_OK);
    }
}

flush_entry get_page_flush_entry(void)
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
    flush_ipi = allocate_ipi_interrupt();
    register_interrupt(flush_ipi, closure(h, flush_handler), "flush ipi");
    list_init(&entries);
    flush_service = closure(h, do_flush_service);
    free_flush_entries = allocate_queue(h, MAX_FLUSH_ENTRIES + 1);
    flush_completion_queue = allocate_queue(h, COMP_QUEUE_SIZE);
    flush_entry fa = allocate(h, sizeof(struct flush_entry) * MAX_FLUSH_ENTRIES);
    assert(fa);
    for (flush_entry f = fa; f < fa + MAX_FLUSH_ENTRIES; f++)
        assert(enqueue(free_flush_entries, f));
    initialized = true;
}
