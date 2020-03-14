#include <kernel.h>
#include <page.h>
#include <apic.h>

// in order to keep SMP_TEST conditionalized
static boolean initialized = false;
static queue flush_completions;
static int flush_ipi;
static heap flush_heap;
// could be static and a power of two
static u64 entries_size = 32;
static u64 *entries;
// seperate cache lines?
static u64 eread = 0, ewrite = 0;

static void invalidate (u64 page)
{
    asm volatile("invlpg (%0)" :: "r" (page) : "memory");            
}

#define entry(__i) (entries+(__i%entries_size))

void ap_flush()
{
    for (int i = eread ; i != ewrite;  i++){
        //        rprintf ("service entry %d %d %p\n", i, current_cpu()->id, *entry(i));        
        u64 p = *entry(i);
        if ((p & ~PAGEMASK) == (INVALID_PHYSICAL & ~PAGEMASK)) {
            // dont want to take the page lock? i dont understand why this deadlocks, not cli?
            page base;
            mov_from_cr("cr3", base);
            mov_to_cr("cr3", base);            
        } else {
            invalidate(p);
        }
        // mask instead of refcnt? check if this the count before the operation or after
        u64 r;
        if ((r = (fetch_and_add(entry(i), -1ull) & PAGEMASK)) == 1) {
            eread++;
            if (eread == ewrite)  {
                thunk k;
                while ((k=dequeue(flush_completions)) != INVALID_ADDRESS) {
                    apply(k);
                }
            }
        }
    }
}

closure_function(0, 0, void, flush_handler)
{
    ap_flush();
}

void start_flush()
{
    apic_ipi(TARGET_EXCLUSIVE_BROADCAST, 0, flush_ipi);
    ap_flush();    
}

// this is serialized under the page table lock(?)
void page_invalidate(u64 p)
{
    if (initialized) {
        p |= total_processors;
        int available = entries_size - (ewrite -eread);

        if (available == 1) {
            // set refcnt to 16 and make another sweep. safety? i dont
            // think there is a real race here
            // we really dont care about the other entries anymore            
            *entry(ewrite-1) = (INVALID_PHYSICAL & ~PAGEMASK) | total_processors;
            start_flush();
        } else {
            *entry(ewrite) = p | total_processors;
            ewrite++;
        }
    } else {
        invalidate(p);
    }
}

void tlb_flush_queue_completion(thunk t)
{
    if (initialized) {
        enqueue(flush_completions, t);
        start_flush();
    } else {
        apply(t);
    }
}

void init_flush(heap h)
{
    // really max threads (?)
    flush_completions = allocate_queue(h, 128);
    entries = allocate(h, sizeof(u64) * entries_size);
    eread = ewrite = 0;
    flush_ipi = allocate_interrupt();
    register_interrupt(flush_ipi, closure(h, flush_handler), "flush ipi");
    flush_heap = h; // xxx - not really
    initialized = true;
}
