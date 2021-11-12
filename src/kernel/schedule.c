#include <kernel.h>

/* Try to keep these within the confines of the runloop lock so we
   don't create too much of a mess. */
//#define SCHED_DEBUG
#ifdef SCHED_DEBUG
#define sched_debug(x, ...) do {log_printf("SCHED", "[%02d] " x, current_cpu()->id, ##__VA_ARGS__);} while(0)
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
boolean shutting_down;

queue bhqueue;                  /* kernel from interrupt */
queue bhqueue_async_1;          /* queue of async 1 arg completions */
queue runqueue;
queue runqueue_async_1;
bitmap idle_cpu_mask;

timerqueue kernel_timers;
thunk timer_interrupt_handler;

static struct spinlock kernel_lock;

void kern_lock()
{
    cpuinfo ci = current_cpu();
    context f = get_running_frame(ci);
    assert(ci->state == cpu_kernel);

    /* allow interrupt handling to occur while spinning */
    u64 flags = irq_enable_save();
    frame_enable_interrupts(f);
    spin_lock(&kernel_lock);
    ci->have_kernel_lock = true;
    irq_restore(flags);
    frame_disable_interrupts(f);
}

boolean kern_try_lock()
{
    cpuinfo ci = current_cpu();
    assert(ci->state != cpu_interrupt);
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

static void run_thunk(thunk t)
{
    sched_debug(" run: %F state: %s\n", t, state_strings[current_cpu()->state]);
    apply(t);
}

static inline void sched_thread_pause(void)
{
    if (shutting_down)
        return;
    nanos_thread nt = get_current_thread();
    if (nt) {
        sched_debug("sched_thread_pause, nt %p\n", nt);
        apply(nt->pause);
    }
}

NOTRACE void __attribute__((noreturn)) kernel_sleep(void)
{
    // we're going to cover up this race by checking the state in the interrupt
    // handler...we shouldn't return here if we do get interrupted
    cpuinfo ci = current_cpu();
    sched_debug("sleep\n");
    ci->state = cpu_idle;
    bitmap_set_atomic(idle_cpu_mask, ci->id, 1);

    while (1) {
        wait_for_interrupt();
    }
}

void wakeup_or_interrupt_cpu_all()
{
    cpuinfo ci = current_cpu();
    for (int i = 0; i < total_processors; i++) {
        if (i != ci->id) {
            bitmap_set_atomic(idle_cpu_mask, i, 0);
            send_ipi(i, wakeup_vector);
        }
    }
}

static void wakeup_cpu(u64 cpu)
{
    if (bitmap_test_and_set_atomic(idle_cpu_mask, cpu, 0)) {
        sched_debug("waking up CPU %d\n", cpu);
        send_ipi(cpu, wakeup_vector);
    }
}

static thunk migrate_to_self(thunk t, u64 first_cpu, u64 ncpus)
{
    u64 cpu;
    while ((ncpus > 0) &&
            ((cpu = bitmap_range_get_first(idle_cpu_mask, first_cpu, ncpus)) != INVALID_PHYSICAL)) {
        cpuinfo cpui = cpuinfo_from_id(cpu);
        if (t == INVALID_ADDRESS) {
            t = dequeue(cpui->thread_queue);
            if (t != INVALID_ADDRESS)
                sched_debug("migrating thread from idle CPU %d to self\n", cpu);
        }
        if ((t != INVALID_ADDRESS) && !queue_empty(cpui->thread_queue))
            wakeup_cpu(cpu);
        ncpus -= cpu - first_cpu + 1;
        first_cpu = cpu + 1;
    }
    return t;
}

static void migrate_from_self(cpuinfo ci, u64 first_cpu, u64 ncpus)
{
    u64 cpu;
    while ((ncpus > 0) &&
            ((cpu = bitmap_range_get_first(idle_cpu_mask, first_cpu, ncpus)) != INVALID_PHYSICAL)) {
        cpuinfo cpui = cpuinfo_from_id(cpu);
        thunk t;
        if (!queue_empty(cpui->thread_queue)) {
            wakeup_cpu(cpu);
        } else if ((t = dequeue(ci->thread_queue)) != INVALID_ADDRESS) {
            sched_debug("migrating thread from self to idle CPU %d\n", cpu);
            enqueue(cpui->thread_queue, t);
            wakeup_cpu(cpu);
        }
        ncpus -= cpu - first_cpu + 1;
        first_cpu = cpu + 1;
    }
}

static inline boolean update_timer(void)
{
    timestamp next = kernel_timers->next_expiry;
    if (!compare_and_swap_boolean(&kernel_timers->update, true, false))
        return false;
    s64 delta = next - now(CLOCK_ID_MONOTONIC_RAW);
    timestamp timeout = delta > (s64)kernel_timers->min ? MIN(delta, kernel_timers->max) : kernel_timers->min;
    sched_debug("set platform timer: delta %lx, timeout %lx\n", delta, timeout);
    current_cpu()->last_timer_update = next + timeout - delta;
    set_platform_timer(timeout);
    return true;
}

closure_function(0, 0, void, kernel_timers_service)
{
    /* timer_service() should be reentrant, so we don't take a lock here */
    kernel_timers->service_scheduled = false;
    timer_service(kernel_timers, now(CLOCK_ID_MONOTONIC_RAW));
}

closure_function(0, 0, void, timer_interrupt_handler_fn)
{
    schedule_timer_service();
}

static inline void service_async_1(queue q)
{
    struct applied_async_1 aa;
    while (dequeue_n_irqsafe(q, (void **)&aa, sizeof(aa) / sizeof(u64)), aa.a != INVALID_ADDRESS) {
        sched_debug(" run: %F arg0: 0x%lx status: %v\n",
                    aa, state_strings[current_cpu()->state], aa->arg0);
        apply(aa.a, aa.arg0);
    }
}

// should we ever be in the user frame here? i .. guess so?
NOTRACE void __attribute__((noreturn)) runloop_internal()
{
    cpuinfo ci = current_cpu();
    thunk t;

    sched_thread_pause();
    disable_interrupts();
    sched_debug("runloop from %s b:%d r:%d t:%d%s\n", state_strings[ci->state],
                queue_length(bhqueue), queue_length(runqueue), queue_length(ci->thread_queue),
                ci->have_kernel_lock ? " locked" : "");
    ci->state = cpu_kernel;
    /* Make sure TLB entries are appropriately flushed before doing any work */
    page_invalidate_flush();

    /* queue for cpu specific operations */
    while ((t = dequeue(ci->cpu_queue)) != INVALID_ADDRESS)
        run_thunk(t);

    /* serve deferred status_handlers, some of which may not return */
    service_async_1(bhqueue_async_1);

    /* bhqueue is for operations outside the realm of the kernel lock,
       e.g. storage I/O completions */
    while ((t = dequeue(bhqueue)) != INVALID_ADDRESS)
        run_thunk(t);

    if (kern_try_lock()) {
        /* invoke expired timer callbacks */
        ci->state = cpu_kernel;

        service_async_1(runqueue_async_1);

        while ((t = dequeue(runqueue)) != INVALID_ADDRESS)
            run_thunk(t);

        /* should be a list of per-runloop checks - also low-pri background */
        mm_service();
        kern_unlock();
    }

    boolean timer_updated = update_timer();

    if (!shutting_down) {
        t = dequeue(ci->thread_queue);
        if (t == INVALID_ADDRESS) {
            /* Try to steal a thread from an idle CPU (so that it doesn't
             * have to be woken up), and wake up CPUs that have a non-empty
             * thread queue). */
            if (ci->id + 1 < total_processors)
                t = migrate_to_self(t, ci->id + 1, total_processors - ci->id - 1);
            if (ci->id > 0)
                t = migrate_to_self(t, 0, ci->id);
            if (t == INVALID_ADDRESS) {
                /* No threads found in idle CPUs: try to steal a thread from a
                 * CPU that is currently running another thread. */
                for (u64 cpu = ci->id + 1; ; cpu++) {
                    if (cpu == total_processors)
                        cpu = 0;
                    if (cpu == ci->id)
                        break;
                    cpuinfo cpui = cpuinfo_from_id(cpu);
                    if (cpui->state == cpu_user) {
                        t = dequeue(cpui->thread_queue);
                        if (t != INVALID_ADDRESS) {
                            sched_debug("migrating thread from CPU %d to self\n", cpu);
                            break;
                        }
                    }
                }
            }
        } else {
            /* Wake up idle CPUs that have a non-empty thread queue, and if our
             * thread queue is non-empty, migrate our threads to idle CPUs. */
            if (ci->id + 1 < total_processors)
                migrate_from_self(ci, ci->id + 1, total_processors - ci->id - 1);
            if (ci->id > 0)
                migrate_from_self(ci, 0, ci->id);
        }
        if (t != INVALID_ADDRESS) {
            if (!timer_updated) {
                /* Before we schedule a thread on this CPU, we want to be sure
                   that a timer will fire on this core within the interval
                   kernel_timers->max into the future. Taking the place of a
                   true time quantum per thread, this acts to prevent a thread
                   from running for too long and starving out other threads. */
                timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
                s64 timeout = ci->last_timer_update - here;
                if ((timeout < 0) || (timeout > kernel_timers->max)) {
                    sched_debug("setting CPU scheduler timer\n");
                    set_platform_timer(kernel_timers->max);
                    ci->last_timer_update = here + kernel_timers->max;
                }
            }
            run_thunk(t);
        }
    }

    sched_thread_pause();
    kernel_sleep();
}    

closure_function(0, 0, void, global_shutdown)
{
    machine_halt();
}

void init_scheduler(heap h)
{
    spin_lock_init(&kernel_lock);

    /* timer init */
    kernel_timers = allocate_timerqueue(h, "runloop");
    assert(kernel_timers != INVALID_ADDRESS);
    kernel_timers->min = microseconds(RUNLOOP_TIMER_MIN_PERIOD_US);
    kernel_timers->max = microseconds(RUNLOOP_TIMER_MAX_PERIOD_US);
    kernel_timers->service = closure(h, kernel_timers_service);
    timer_interrupt_handler = closure(h, timer_interrupt_handler_fn);

    /* IPI init */
    wakeup_vector = allocate_ipi_interrupt();
    register_interrupt(wakeup_vector, ignore, "wakeup ipi");
    shutdown_vector = allocate_ipi_interrupt();
    register_interrupt(shutdown_vector, closure(h, global_shutdown), "shutdown ipi");
    assert(wakeup_vector != INVALID_PHYSICAL);

    /* scheduling queues init */
    // XXX configs
    bhqueue = allocate_queue(h, 2048);
    bhqueue_async_1 = allocate_queue(h, 8192);
    runqueue = allocate_queue(h, 2048);
    runqueue_async_1 = allocate_queue(h, 8192);
    shutting_down = false;
}

void init_scheduler_cpus(heap h)
{
    idle_cpu_mask = allocate_bitmap(h, h, present_processors);
    assert(idle_cpu_mask != INVALID_ADDRESS);
    bitmap_alloc(idle_cpu_mask, present_processors);
}
