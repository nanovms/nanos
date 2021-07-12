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

queue runqueue;                 /* kernel space from ?*/
queue bhqueue;                  /* kernel from interrupt */
timerheap runloop_timers;
bitmap idle_cpu_mask;
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

timer kern_register_timer(clock_id id, timestamp val, boolean absolute,
            timestamp interval, timer_handler n)
{
    return register_timer(runloop_timers, id, val, absolute, interval, n);
}
KLIB_EXPORT(kern_register_timer);

static void run_thunk(thunk t)
{
    sched_debug(" run: %F state: %s\n", t, state_strings[current_cpu()->state]);
    apply(t);
    // do we want to enforce this? i kinda just want to collapse
    // the stack and ensure that the thunk actually wanted to come back here
    //    halt("handler returned %d", cpustate);
}

/* called with kernel lock held */
static inline boolean update_timer(void)
{
    timestamp next = timer_check(runloop_timers);
    if (last_timer_update && next == last_timer_update)
        return false;
    s64 delta = next - now(CLOCK_ID_MONOTONIC_RAW);
    timestamp timeout = delta > (s64)runloop_timer_min ? MIN(delta, runloop_timer_max) : runloop_timer_min;
    sched_debug("set platform timer: delta %lx, timeout %lx\n", delta, timeout);
    last_timer_update = current_cpu()->last_timer_update = next + timeout - delta;
    runloop_timer(timeout);
    return true;
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

void schedule_thread_frame(context frame, boolean prefer_current)
{
    if (total_processors == 1) {
        schedule_frame(frame);
        return;
    }
    cpuinfo target;
    cpuinfo ci = current_cpu();
    if (prefer_current && queue_empty(ci->thread_queue)) {
        target = ci;
        goto schedule;
    }
    cpuinfo prev = pointer_from_u64(frame[FRAME_CPU]);
    target = prev;
    u64 cpu = bitmap_range_get_first(idle_cpu_mask, prev->id, total_processors - prev->id);
    if (cpu != INVALID_PHYSICAL) {
        target = cpuinfo_from_id(cpu);
        goto schedule;
    }
    cpu = bitmap_range_get_first(idle_cpu_mask, 0, prev->id);
    if (cpu != INVALID_PHYSICAL)
        target = cpuinfo_from_id(cpu);
  schedule:
    frame[FRAME_CPU] = u64_from_pointer(target);
    frame[FRAME_QUEUE] = u64_from_pointer(target->thread_queue);
    schedule_frame(frame);
    if ((target != ci) && (bitmap_get(idle_cpu_mask, target->id)))
        send_ipi(target->id, wakeup_vector);
}

NOTRACE void __attribute__((noreturn)) kernel_sleep(void)
{
    cpuinfo ci = current_cpu();
    sched_debug("sleep\n");
    ci->state = cpu_idle;
    if (idle_cpu_mask) {
        bitmap_set_atomic(idle_cpu_mask, ci->id, 1);
        if (!shutting_down && !queue_empty(ci->thread_queue)) {
            bitmap_set_atomic(idle_cpu_mask, ci->id, 0);
            runloop();
        }
    }

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

// should we ever be in the user frame here? i .. guess so?
NOTRACE void __attribute__((noreturn)) runloop_internal()
{
    cpuinfo ci = current_cpu();
    thunk t;
    boolean timer_updated = false;

    sched_thread_pause();
    disable_interrupts();
    sched_debug("runloop from %s b:%d r:%d t:%d%s\n", state_strings[ci->state],
                queue_length(bhqueue), queue_length(runqueue), queue_length(ci->thread_queue),
                ci->have_kernel_lock ? " locked" : "");
    ci->state = cpu_kernel;
    /* Make sure TLB entries are appropriately flushed before doing any work */
    page_invalidate_flush();

    /* bhqueue is for operations outside the realm of the kernel lock,
       e.g. storage I/O completions */
    while ((t = dequeue(bhqueue)) != INVALID_ADDRESS)
        run_thunk(t);

    if (kern_try_lock()) {
        /* invoke expired timer callbacks */
        ci->state = cpu_kernel;
        timer_service(runloop_timers, now(CLOCK_ID_MONOTONIC_RAW));

        while ((t = dequeue(runqueue)) != INVALID_ADDRESS)
            run_thunk(t);

        /* should be a list of per-runloop checks - also low-pri background */
        mm_service();
        timer_updated = update_timer();
        kern_unlock();
    }

    if (!shutting_down) {
        t = dequeue(ci->thread_queue);
        if (t == INVALID_ADDRESS) {
            /* Try to steal a thread from a CPU that is currently running another thread. */
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
        if (t != INVALID_ADDRESS) {
            if (!timer_updated && (total_processors > 1)) {
                timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
                s64 timeout = ci->last_timer_update - here;
                if ((timeout < 0) || (timeout > runloop_timer_max)) {
                    sched_debug("setting CPU scheduler timer\n");
                    runloop_timer(runloop_timer_max);
                    ci->last_timer_update = here + runloop_timer_max;
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
    runloop_timer_min = microseconds(RUNLOOP_TIMER_MIN_PERIOD_US);
    runloop_timer_max = microseconds(RUNLOOP_TIMER_MAX_PERIOD_US);
    wakeup_vector = allocate_ipi_interrupt();

    register_interrupt(wakeup_vector, ignore, "wakeup ipi");
    shutdown_vector = allocate_ipi_interrupt();
    register_interrupt(shutdown_vector, closure(h, global_shutdown), "shutdown ipi");
    assert(wakeup_vector != INVALID_PHYSICAL);
    /* scheduling queues init */
    runqueue = allocate_queue(h, 2048);
    bhqueue = allocate_queue(h, 2048);
    runloop_timers = allocate_timerheap(h, "runloop");
    assert(runloop_timers != INVALID_ADDRESS);
    shutting_down = false;
}

void init_scheduler_cpus(heap h)
{
    idle_cpu_mask = allocate_bitmap(h, h, total_processors);
    assert(idle_cpu_mask != INVALID_ADDRESS);
    bitmap_alloc(idle_cpu_mask, total_processors);
}
