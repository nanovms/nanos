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
static u64 eread, ewrite;

static void invalidate (u64 page)
{
    asm volatile("invlpg (%0)" :: "r" (page) : "memory");            
}

void ap_flush()
{
    rprintf("ap flush %d\n", current_cpu()->id);
    
    for (int i = eread ; i < ewrite;  i =(i + 1) % entries_size) {
        u64 p = entries[i];
        if ((p & ~PAGEMASK) == (INVALID_PHYSICAL & ~PAGEMASK)) {
            flush_tlb();
        } else {
            invalidate(p);
        }
        // mask instead of refcnt? check if this the count before the operation or
        // after
        if ((fetch_and_add(entries + i, -1ull) & PAGEMASK) == 1) {
            // serialized by the refcnt
            eread++;
            if (eread == ewrite)  {
                thunk k;
                while ((k=dequeue(flush_completions))) {
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
    rprintf("start flush\n");
    apic_ipi(TARGET_EXCLUSIVE_BROADCAST, 0, flush_ipi);
    ap_flush();    
}

// this is serialized under the page table lock(?)
void page_invalidate(u64 p)
{
    if (initialized) {
        p |= total_processors;
        int available = ((ewrite + entries_size)-eread)%entries_size; 
        if (available == 1) {
            // set refcnt to 16 and make another sweep            
            start_flush();
        } else {
            if (available < 2) {
                entries[ewrite] = (INVALID_PHYSICAL & ~PAGEMASK) | total_processors;
            } else {
                entries[ewrite] = p | total_processors;
            }
            ewrite = (ewrite+1)%entries_size;
        }
    } else {
        invalidate(p);
    }
}

void tlb_flush_queue_completion(thunk t)
{
    if (initialized) {
        rprintf("flush schedule\n");
        enqueue(flush_completions, t);
        start_flush();
    } else {
        rprintf("flush not init\n");
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
