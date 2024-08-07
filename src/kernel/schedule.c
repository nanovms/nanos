#include <kernel.h>

//#define SCHED_DEBUG
#ifdef SCHED_DEBUG
#define sched_debug(x, ...) do {tprintf(sym(sched), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define sched_debug(x, ...)
#endif

static const sstring state_strings_backing[] = {
    ss_static_init("not present"),
    ss_static_init("idle"),
    ss_static_init("kernel"),
    ss_static_init("interrupt"),
    ss_static_init("user"),
};

const sstring * const state_strings = state_strings_backing;
BSS_RO_AFTER_INIT static int wakeup_vector;
BSS_RO_AFTER_INIT int shutdown_vector;
u32 shutting_down = 0;

BSS_RO_AFTER_INIT queue bhqueue;                  /* kernel from interrupt */
BSS_RO_AFTER_INIT queue runqueue;
BSS_RO_AFTER_INIT queue async_queue_1;            /* queue of async 1 arg completions */
BSS_RO_AFTER_INIT bitmap idle_cpu_mask;

BSS_RO_AFTER_INIT timerqueue kernel_timers;
BSS_RO_AFTER_INIT thunk timer_interrupt_handler;

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

static sched_task sched_dequeue_for_cpu(sched_queue sq, u64 cpu)
{
    u32 i;
    sched_task task;
    spin_lock(&sq->lock);

    /* Note: due to weak ordering in the priority queue, this code does NOT guarantee that the
     * chosen task is the highest priority (lowest runtime) task among all eligible tasks; however,
     * choosing a potentially sub-optimal task minimizes the time spent walking the queue. */
    for (i = 0; (task = pqueue_peek_at(sq->q, i)) != INVALID_ADDRESS; i++) {
        if (bitmap_get(task->affinity, cpu)) {
            pqueue_remove_at(sq->q, i);
            break;
        }
    }

    if (task != INVALID_ADDRESS) {
        sched_debug("sq %p, dequeued for %ld task %p, index %u, runtime %T\n", sq, cpu, task, i,
                    task->runtime - sq->min_runtime);
        if (i == 0)
            sq->min_runtime = task->runtime;
        task->runtime -= sq->min_runtime;
    }
    spin_unlock(&sq->lock);
    return task;
}

static sched_task migrate_to_self(sched_task t, u64 self, u64 first_cpu, u64 ncpus)
{
    u64 cpu;
    while ((ncpus > 0) &&
            ((cpu = bitmap_range_get_first(idle_cpu_mask, first_cpu, ncpus)) != INVALID_PHYSICAL)) {
        cpuinfo cpui = cpuinfo_from_id(cpu);
        if (t == INVALID_ADDRESS) {
            t = sched_dequeue_for_cpu(&cpui->thread_queue, self);
            if (t != INVALID_ADDRESS)
                sched_debug("migrating thread from idle CPU %d to self\n", cpu);
        }
        if (!sched_queue_empty(&cpui->thread_queue))
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
        sched_task task;
        if (!sched_queue_empty(&cpui->thread_queue)) {
            wakeup_cpu(cpu);
        } else if ((task = sched_dequeue_for_cpu(&ci->thread_queue, cpu)) != INVALID_ADDRESS) {
            sched_debug("migrating thread from self to idle CPU %d\n", cpu);
            sched_enqueue(&cpui->thread_queue, task);
            wakeup_cpu(cpu);
        }
        ncpus -= cpu - first_cpu + 1;
        first_cpu = cpu + 1;
    }
}

static inline boolean update_timer(timestamp here)
{
    timestamp next = kernel_timers->next_expiry;
    if (!compare_and_swap_32(&kernel_timers->update, true, false))
        return false;
    s64 delta = next - here;
    timestamp timeout = MAX(delta, (s64)microseconds(RUNLOOP_TIMER_MIN_PERIOD_US));
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

static inline void service_thunk_queue(queue q)
{
    thunk t;
    context c;
    while ((t = dequeue(q)) != INVALID_ADDRESS) {
        c = context_from_closure(t);
        sched_debug(" run: %F state: %s context: %p\n", t, state_strings[current_cpu()->state], c);
        if (c)
            context_apply(c, t);
        else
            apply(t);
    }
}

static inline void service_async_1(queue q)
{
    struct applied_async_1 aa;
    while (dequeue_n_irqsafe(q, (void **)&aa, sizeof(aa) / sizeof(u64))) {
        sched_debug(" run: %F arg0: 0x%lx\n", aa.a, aa.arg0);
        context c = context_from_closure(aa.a);
        if (c)
            context_apply_1(c, aa.a, aa.arg0);
        else
            apply(aa.a, aa.arg0);
    }
}

NOTRACE void __attribute__((noreturn)) runloop_internal(void)
{
    cpuinfo ci = current_cpu();

    disable_interrupts();
    sched_debug("runloop from %s c: %d  a1: %d b:%d  r:%d  t:%d\n",
                state_strings[ci->state], queue_length(ci->cpu_queue),
                queue_length(async_queue_1), queue_length(bhqueue),
                queue_length(runqueue), sched_queue_length(&ci->thread_queue));
    ci->state = cpu_kernel;
    /* Make sure TLB entries are appropriately flushed before doing any work */
    page_invalidate_flush();

  retry:
    /* queue for cpu specific operations */
    service_thunk_queue(ci->cpu_queue);

    /* bhqueue is for deferred operations, enqueued by interrupt handlers */
    service_thunk_queue(bhqueue);

    /* serve deferred status_handlers, some of which may not return */
    service_async_1(async_queue_1);

    service_thunk_queue(runqueue);

    /* should be a list of per-runloop checks - also low-pri background */
    mm_service(false);

    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    boolean timer_updated = update_timer(here);

    if (!(shutting_down & SHUTDOWN_ONGOING)) {
        u64 self = ci->id;
        sched_task t = sched_dequeue(&ci->thread_queue);
        if (t == INVALID_ADDRESS) {
            /* Try to steal a thread from an idle CPU (so that it doesn't
             * have to be woken up), and wake up CPUs that have a non-empty
             * thread queue). */
            if (self + 1 < total_processors)
                t = migrate_to_self(t, self, self + 1, total_processors - self - 1);
            if (ci->id > 0)
                t = migrate_to_self(t, self, 0, self);
            if (t == INVALID_ADDRESS) {
                /* No threads found in idle CPUs: try to steal a thread from a
                 * CPU that is currently running another thread. */
                for (u64 cpu = self + 1; ; cpu++) {
                    if (cpu == total_processors)
                        cpu = 0;
                    if (cpu == self)
                        break;
                    cpuinfo cpui = cpuinfo_from_id(cpu);
                    if (cpui->state == cpu_user) {
                        t = sched_dequeue_for_cpu(&cpui->thread_queue, self);
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
            if (self + 1 < total_processors)
                migrate_from_self(ci, self + 1, total_processors - self - 1);
            if (self > 0)
                migrate_from_self(ci, 0, self);
        }
        if (t != INVALID_ADDRESS) {
            if (!timer_updated) {
                /* Before we schedule a thread on this CPU, we want to be sure
                   that a timer will fire on this core within the interval
                   kernel_timers->max into the future. Taking the place of a
                   true time quantum per thread, this acts to prevent a thread
                   from running for too long and starving out other threads. */
                s64 timeout = ci->last_timer_update - here;
                timestamp max_timeout = microseconds(RUNLOOP_TIMER_MAX_PERIOD_US);
                if (kernel_timers->empty || (timeout > (s64)max_timeout)) {
                    sched_debug("setting CPU scheduler timer\n");
                    set_platform_timer(max_timeout);
                    ci->last_timer_update = here + max_timeout;
                }
            }
            apply(t->t);
        }
    }

    /* We want to pick up items that were enqueued during this last pass, else
       runnable items may get stuck waiting for the next interrupt.

       Find cost of sleep / wakeup and consider spinning this check for that interval. */
    if (queue_length(ci->cpu_queue) || queue_length(async_queue_1) ||
        queue_length(bhqueue) || queue_length(runqueue) ||
        (!(shutting_down & SHUTDOWN_ONGOING) && !sched_queue_empty(&ci->thread_queue)))
        goto retry;

    kernel_sleep();
}

/* non-inlined trampoline target */
NOTRACE void __attribute__((noreturn)) runloop_target(void)
{
    runloop();
}

closure_function(0, 0, void, global_shutdown)
{
    machine_halt();
}

void init_scheduler(heap h)
{
    /* timer init */
    kernel_timers = allocate_timerqueue(h, 0, ss("runloop"));
    assert(kernel_timers != INVALID_ADDRESS);
    kernel_timers->service = closure(h, kernel_timers_service);
    timer_interrupt_handler = closure(h, timer_interrupt_handler_fn);

    /* IPI init */
    wakeup_vector = allocate_ipi_interrupt();
    register_interrupt(wakeup_vector, ignore, ss("wakeup ipi"));
    shutdown_vector = allocate_ipi_interrupt();
    register_interrupt(shutdown_vector, closure(h, global_shutdown), ss("shutdown ipi"));
    assert(wakeup_vector != INVALID_PHYSICAL);

    /* scheduling queues init */
    bhqueue = allocate_queue(h, BHQUEUE_SIZE);
    runqueue = allocate_queue(h, RUNQUEUE_SIZE);
    async_queue_1 = allocate_queue(h, ASYNC_QUEUE_1_SIZE);
}

void init_scheduler_cpus(heap h)
{
    idle_cpu_mask = allocate_bitmap(h, h, present_processors);
    assert(idle_cpu_mask != INVALID_ADDRESS);
    bitmap_alloc(idle_cpu_mask, present_processors);
}

static boolean sched_sort(void *a, void *b)
{
    sched_task ta = a, tb = b;
    return (ta->runtime > tb->runtime);
}

boolean sched_queue_init(sched_queue sq, heap h)
{
    sq->q = allocate_pqueue(h, sched_sort);
    if (sq->q == INVALID_ADDRESS)
        return false;
    sq->min_runtime = 0;
    spin_lock_init(&sq->lock);
    return true;
}

void sched_enqueue(sched_queue sq, sched_task task)
{
    spin_lock(&sq->lock);
    sched_debug("sq %p, enqueuing task %p, runtime %T\n", sq, task, task->runtime);
    task->runtime += sq->min_runtime;
    pqueue_insert(sq->q, task);
    spin_unlock(&sq->lock);
}

sched_task sched_dequeue(sched_queue sq)
{
    spin_lock(&sq->lock);
    sched_task task = pqueue_pop(sq->q);
    if (task != INVALID_ADDRESS) {
        sched_debug("sq %p, dequeued task %p, runtime %T\n", sq, task,
                    task->runtime - sq->min_runtime);
        sq->min_runtime = task->runtime;
        task->runtime = 0;
    }
    spin_unlock(&sq->lock);
    return task;
}

u64 sched_queue_length(sched_queue sq)
{
    return pqueue_length(sq->q);
}
