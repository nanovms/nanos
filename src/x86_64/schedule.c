#include <kernel.h>
#include <tfs.h> // needed for unix.h
#include <unix.h> // some deps
#include <apic.h>


/* Try to keep these within the confines of the runloop lock so we
   don't create too much of a mess. */
//#define SCHED_DEBUG
#ifdef SCHED_DEBUG
#define sched_debug(x, ...) do {log_printf("SCHED", "[%2d] " x, current_cpu()->id, ##__VA_ARGS__);} while(0)
#else
#define sched_debug(x, ...)
#endif

// currently defined in x86_64.h
static char *state_strings_backing[] = {
    "not present",
    "idle",
    "kernel",
    "interrupt",
    "user",         
};

char **state_strings = state_strings_backing;
static int wakeup_vector;
int shutdown_vector;

queue runqueue;                 /* kernel space from ?*/
queue bhqueue;                  /* kernel from interrupt */
queue thread_queue;             /* kernel to user */
timerheap runloop_timers;
u64 idle_cpu_mask;              /* xxx - limited to 64 aps. consider merging with bitmask */
timestamp last_timer_update;

static timestamp runloop_timer_min;
static timestamp runloop_timer_max;

static struct spinlock kernel_lock;

void kern_lock()
{
    cpuinfo ci = current_cpu();
    assert(ci->state != cpu_interrupt);
    spin_lock(&kernel_lock);
    ci->have_kernel_lock = true;
}

boolean kern_try_lock()
{
    cpuinfo ci = current_cpu();
    assert(ci->state != cpu_interrupt);
    if (ci->have_kernel_lock)
        return true;
    if (!spin_try(&kernel_lock))
        return false;
    ci->have_kernel_lock = true;
    return true;
}

void kern_unlock()
{
    cpuinfo ci = current_cpu();
    assert(ci->state != cpu_interrupt);
    ci->have_kernel_lock = false;
    spin_unlock(&kernel_lock);
}

static void run_thunk(thunk t, int cpustate)
{
    cpuinfo ci = current_cpu();
    sched_debug(" run: %F state: %s\n", t, state_strings[cpustate]);
    // as we are walking by, if there is work to be done and an idle cpu,
    // get it to wake up and examine the queue
    if (idle_cpu_mask &&
        ((queue_length(bhqueue) > 0) ||
         (queue_length(runqueue) > 0) ||
         (queue_length(thread_queue) > 0))) {
        // unfortunately, if idle cpu mask is zero (which can happen since this
        // is racy), the result is the previous value ... so asm here
        u64 mask_copy = idle_cpu_mask;
        u64 cpu = msb(mask_copy);        
        // this really shouldn't ever be current_cpu() ? 
        if (cpu != INVALID_PHYSICAL && cpu != current_cpu()->id) {
            sched_debug("sending wakeup ipi to %d %x\n", cpu, wakeup_vector);
            atomic_clear_bit(&idle_cpu_mask, cpu);
            apic_ipi(cpu, 0, wakeup_vector);
        }
    }

    ci->state = cpustate;
    apply(t);
    // do we want to enforce this? i kinda just want to collapse
    // the stack and ensure that the thunk actually wanted to come back here
    //    halt("handler returned %d", cpustate);
}

/* called with kernel lock held */
static inline void update_timer(void)
{
    timestamp next = timer_check(runloop_timers);
    if (last_timer_update && next == last_timer_update)
        return;
    last_timer_update = next;
    s64 delta = next - now(CLOCK_ID_MONOTONIC);
    timestamp timeout = delta > (s64)runloop_timer_min ? MAX(delta, runloop_timer_max) : runloop_timer_min;
    sched_debug("set platform timer: delta %lx, timeout %lx\n", delta, timeout);
    runloop_timer(timeout);
}

NOTRACE void __attribute__((noreturn)) kernel_sleep(void)
{
    // we're going to cover up this race by checking the state in the interrupt
    // handler...we shouldn't return here if we do get interrupted
    cpuinfo ci = get_cpuinfo();
    sched_debug("sleep\n");
    ci->state = cpu_idle;
    atomic_set_bit(&idle_cpu_mask, ci->id);
    if (ci->have_kernel_lock)
        kern_unlock();

    /* loop to absorb spurious wakeups from hlt - happens on some platforms (e.g. xen) */
    while (1)
        asm volatile("sti; hlt" ::: "memory");
}

// should we ever be in the user frame here? i .. guess so?
NOTRACE void __attribute__((noreturn)) runloop_internal()
{
    cpuinfo ci = current_cpu();
    thunk t;

    disable_interrupts();
    sched_debug("runloop from %s b:%d r:%d t:%d i:%x lock:%d\n", state_strings[ci->state],
                queue_length(bhqueue), queue_length(runqueue), queue_length(thread_queue),
                idle_cpu_mask, ci->have_kernel_lock);
    ci->state = cpu_kernel;
    if (kern_try_lock()) {
        /* invoke expired timer callbacks */
        ci->state = cpu_kernel;
        timer_service(runloop_timers, now(CLOCK_ID_MONOTONIC));

        /* serve bhqueue to completion */
        while ((t = dequeue(bhqueue)) != INVALID_ADDRESS) {
            run_thunk(t, cpu_kernel);
        }

        /* serve existing, but not additionally queued (deferred), items on runqueue */
        u64 n_rq = queue_length(runqueue);
        while (n_rq-- > 0 && (t = dequeue(runqueue)) != INVALID_ADDRESS) {
            run_thunk(t, cpu_kernel);
        }

        /* should be a list of per-runloop checks - also low-pri background */
        mm_service();
        update_timer();

        kern_unlock();
    }

    if ((t = dequeue(thread_queue)) != INVALID_ADDRESS)
        run_thunk(t, cpu_user);
    if (ci->current_thread)
        thread_pause(ci->current_thread);

    kernel_sleep();
}    

closure_function(0, 0, void, global_shutdown)
{
    __asm__("cli; hlt");
}

void init_scheduler(heap h)
{
    spin_lock_init(&kernel_lock);
    runloop_timer_min = microseconds(RUNLOOP_TIMER_MIN_PERIOD_US);
    runloop_timer_max = microseconds(RUNLOOP_TIMER_MAX_PERIOD_US);
    wakeup_vector = allocate_interrupt();
    register_interrupt(wakeup_vector, ignore, "wakeup ipi");
    shutdown_vector = allocate_interrupt();    
    register_interrupt(shutdown_vector, closure(h, global_shutdown), "shutdown ipi");    
    assert(wakeup_vector != INVALID_PHYSICAL);
    /* scheduling queues init */
    runqueue = allocate_queue(h, 64);
    bhqueue = allocate_queue(h, 2048);
    thread_queue = allocate_queue(h, 64);
    runloop_timers = allocate_timerheap(h, "runloop");
    assert(runloop_timers != INVALID_ADDRESS);
}
