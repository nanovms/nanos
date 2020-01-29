#include <runtime.h>
#include <x86_64.h>
#include <tfs.h> // needed for unix.h
#include <unix.h> // some deps
#include <lock.h>
#include <apic.h>


/* Try to keep these within the confines of the runloop lock so we
   don't create too much of a mess. */
//#define SCHED_DEBUG
#ifdef SCHED_DEBUG
#define sched_debug(x, ...) do {log_printf("SCHED", "[%2d] " x, ci->id, ##__VA_ARGS__);} while(0)
#else
#define sched_debug(x, ...) (void)ci
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

queue runqueue;                 /* kernel space from ?*/
queue bhqueue;                  /* kernel from interrupt */
queue thread_queue;              /* kernel to user */
u64 idle_cpu_mask;              /* xxx - limited to 64 aps. consider merging with bitmask */

static timestamp runloop_timer_min;
static timestamp runloop_timer_max;

static thunk timer_update;

closure_function(0, 0, void, timer_update_internal)
{
    /* find timer interval from timer heap, bound by configurable min and max */
    timestamp timeout = MAX(MIN(timer_check(), runloop_timer_max), runloop_timer_min);
    runloop_timer(timeout);
}

void timer_schedule(void)
{
    enqueue(bhqueue, timer_update);
}

closure_function(0, 0, void, timer_interrupt_internal)
{
    timer_schedule();
}

thunk timer_interrupt;

static u64 kernel_lock;

void kern_lock()
{
    cpuinfo ci = current_cpu();
    spin_lock(&kernel_lock);
    ci->have_kernel_lock = true;
}

boolean kern_try_lock()
{
    cpuinfo ci = current_cpu();
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
    assert(ci->have_kernel_lock);
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
        /* racy, but matters not ... at worst spurious wakeup */
        u64 mask_copy = idle_cpu_mask;
        u64 cpu = msb(mask_copy);
        if (cpu != INVALID_PHYSICAL && cpu != current_cpu()->id) {
            sched_debug("sending wakeup ipi to %d\n", cpu);
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

// should we ever be in the user frame here? i .. guess so?
void runloop_internal()
{
    cpuinfo ci = current_cpu();
    thunk t;

    disable_interrupts();
    sched_debug("runloop %s b:%d r:%d i:%x i:%d lock:%d\n", state_strings[ci->state],
                queue_length(bhqueue), queue_length(runqueue), queue_length(thread_queue),
                idle_cpu_mask, ci->have_kernel_lock);
    if (kern_try_lock()) {
        /* serve bhqueue to completion */
        while ((t = dequeue(bhqueue)) != INVALID_ADDRESS) {
            run_thunk(t, cpu_kernel);
        }

        /* serve existing, but not additionally queued (deferred), items on runqueue */
        u64 n_rq = queue_length(runqueue);
        while (n_rq-- > 0 && (t = dequeue(runqueue)) != INVALID_ADDRESS) {
            run_thunk(t, cpu_kernel);
        }
        kern_unlock();
    }

    if ((t = dequeue(thread_queue)) != INVALID_ADDRESS)
        run_thunk(t, cpu_user);
    
    kernel_sleep();
    halt("shouldn't be here");
}    


closure_function(0, 0, void, ipi_interrupt)
{
    cpuinfo ci = get_cpuinfo();
    sched_debug("cpu %d wakes up\n", ci->id);
}

void init_scheduler(heap h)
{
    kernel_lock = 0;
    timer_update = closure(h, timer_update_internal);
    timer_interrupt = closure(h, timer_interrupt_internal);
    runloop_timer_min = microseconds(RUNLOOP_TIMER_MIN_PERIOD_US);
    runloop_timer_max = microseconds(RUNLOOP_TIMER_MAX_PERIOD_US);
    wakeup_vector = allocate_interrupt();
    register_interrupt(wakeup_vector, closure(h, ipi_interrupt));    
    assert(wakeup_vector != INVALID_PHYSICAL);    
    /* scheduling queues init */
    runqueue = allocate_queue(h, 64);
    /* XXX bhqueue is large to accomodate vq completions; explore batch processing on vq side */
    bhqueue = allocate_queue(h, 2048);
    thread_queue = allocate_queue(h, 64);
}

// is kern lock held here?
void kernel_sleep(void)
{
    // we're going to cover up this race by checking the state in the interrupt
    // handler...we shouldn't return here if we do get interrupted    
    cpuinfo ci = get_cpuinfo();
    sched_debug("sleep %d\n", ci->id);
    ci->state = cpu_idle;
    atomic_set_bit(&idle_cpu_mask, ci->id);
    if (ci->have_kernel_lock)
        kern_unlock();
    // wmb() ?  interrupt would probably enforce that
    asm volatile("sti; hlt" ::: "memory");
    halt("cpu %d return from kernel sleep", ci->id);
}

