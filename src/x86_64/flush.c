#include <kernel.h>
#include <page.h>
#include <apic.h>

static boolean initialized = false;
static int flush_ipi;
static heap flush_heap;


static void invalidate (u64 page)
{
    asm volatile("invlpg (%0)" :: "r" (page) : "memory");
}

static void _flush_handler(void)
{
    cpuinfo ci = current_cpu();
    void *p;
    while ((p = dequeue(ci->inval_queue)) != INVALID_ADDRESS) {
        invalidate((u64)p);
    }
}

closure_function(0, 0, void, flush_handler)
{
    _flush_handler();
}


void page_invalidate(u64 p)
{
    if (initialized) {
        for (int i = 0; i < total_processors; i++) {
            while (!enqueue(cpuinfos[i].inval_queue, (void *)p))
                page_invalidate_sync(ignore);
        }
    } else {
        invalidate(p);
    }
}

void page_invalidate_sync(thunk completion)
{
    if (initialized) {
        u64 flags = irq_disable_save();
        int id = current_cpu()->id;
        for (int i = 0; i < total_processors; i++) {
            if (i != id)
                apic_ipi(i, 0, flush_ipi);
        }
        _flush_handler();
        irq_restore(flags);
    }

    if (completion)
        apply(completion);
    }

void init_flush(heap h)
{
    flush_ipi = allocate_interrupt();
    register_interrupt(flush_ipi, closure(h, flush_handler), "flush ipi");
    flush_heap = h; // xxx - not really
    initialized = true;
}

