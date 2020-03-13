#include <kernel.h>
#include <page.h>
#include <apic.h>

// in order to keep SMP_TEST conditionalized
static boolean initialized = false;
static queue flush_completions;
static queue flush_pages;
static int flush_ipi;
static heap flush_heap;

static void invalidate (u64 page)
{
    asm volatile("invlpg (%0)" :: "r" (page) : "memory");            
}

closure_function(0, 0, void, flush_handler)
{
    // scan the whole business
    u64 p = u64_from_pointer(queue_peek(flush_pages));
    if (p == INVALID_PHYSICAL) {
        flush_tlb();
    } else {
        invalidate(p);
    }
}

void page_invalidate(u64 p)
{
    if (initialized) {
        p |= total_processors;
        enqueue(flush_pages, pointer_from_u64(p));
    } else {
        invalidate(p);
    }
}

void init_flush(heap h)
{
    // really max threads (?)
    flush_completions = allocate_queue(h, 128);
    flush_pages = allocate_queue(h, 128);    
    flush_ipi = allocate_interrupt();
    register_interrupt(flush_ipi, closure(h, flush_handler), "flush ipi");
    flush_heap = h; // xxx - not really
    initialized = true;
}

void tlb_flush_queue_completion(thunk t)
{
    if (initialized) {
        enqueue(flush_completions, t);
    } else {
        apply(t);
    }
}
