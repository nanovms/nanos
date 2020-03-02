#include <kernel.h>
#include <page.h>
#include <apic.h>

// in order to keep SMP_TEST conditionalized
static boolean initialized = false;
static queue flush_queue;
static int flush_ipi;
static heap flush_heap;

typedef struct flush_entry {
    struct refcount r;
    u64 page; // or INVALID_ADDRESS for a full flush
} *flush_entry;

static void invalidate (u64 page)
{
    asm volatile("invlpg (%0)" :: "r" (page) : "memory");            
}

closure_function(0, 0, void, flush_handler)
{
    flush_entry f = queue_peek(flush_queue);
    if (f->page == INVALID_PHYSICAL) {
        flush_tlb();
    } else {
        invalidate(f->page);
    }
    if (refcount_release(&f->r))
        deallocate(flush_heap, dequeue(flush_queue), sizeof(struct flush_entry));
}

void page_invalidate(u64 p, thunk completion)
{
    if (initialized) {
        flush_entry f = allocate(flush_heap, sizeof(struct flush_entry));
        init_refcount(&f->r, total_processors, completion);
        enqueue(flush_queue, f);
        // we can choose to delay/amortize this
        apic_ipi(TARGET_EXCLUSIVE_BROADCAST, 0, flush_ipi);        
    } else {
        invalidate(p);
        apply(completion);
    }
}

void init_flush(heap h)
{
    flush_queue = allocate_queue(h, 128);
    flush_ipi = allocate_interrupt();
    register_interrupt(flush_ipi, closure(h, flush_handler), "flush ipi");
    flush_heap = h; // xxx - not really
    initialized = true;
}

