#include <runtime.h>
#include <x86_64.h>
#include <apic.h>

static struct {
    u64 size;
    u64 sem;
    u64 head;                   /* next to enqueue */
    u64 tail;                   /* next to dequeue */
} kernlock;

static u64 *kernlock_ring;

static inline int dequeue_cpu(void)
{
    u64 src = fetch_and_add(&kernlock.tail, 1);
    return (int)kernlock_ring[src % kernlock.size];
}

static inline void enqueue_cpu(int cpu)
{
    u64 dest = fetch_and_add(&kernlock.head, 1);
    kernlock_ring[dest % kernlock.size] = cpu; /* cas for paranoia? */
}

void kern_lock(void)
{
    cpuinfo ci = get_cpuinfo();
    u64 s = fetch_and_add(&kernlock.sem, 1);
    assert(s < kernlock.size);

    if (s > 0) {
        disable_interrupts();
        ci->ipi_wakeup = false;
        enqueue_cpu(ci->id);
        while (!ci->ipi_wakeup)
            kernel_sleep();
    }
}

void kern_unlock(void)
{
    u64 s = fetch_and_add(&kernlock.sem, -1);
    assert(s > 0);

    if (s > 1) {
        int cid;
        /* minute spin for race between sem bump and enqueue */
        do {
            cid = dequeue_cpu();
        } while (cid == -1);
        wake_cpu(cid);
    }
}

void init_kernlock(heap h, int n_cpus)
{
    /* maybe round up to order */
    kernlock_ring = allocate(h, n_cpus * sizeof(u64));
    kernlock.size = n_cpus;
    kernlock.sem = 0;
    kernlock.head = kernlock.tail = 0;
}
