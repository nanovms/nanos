#include <kernel.h>

const char *context_type_strings[CONTEXT_TYPE_MAX] = {
    "undefined",
    "kernel",
    "syscall",
    "thread",
};

struct mm_stats mm_stats;

void *allocate_stack(heap h, u64 size)
{
    u64 padsize = pad(size, h->pagesize);
    void *base = allocate_zero(h, padsize);
    assert(base != INVALID_ADDRESS);
    return base + padsize - STACK_ALIGNMENT;
}

void deallocate_stack(heap h, u64 size, void *stack)
{
    u64 padsize = pad(size, h->pagesize);
    deallocate(h, u64_from_pointer(stack) - padsize + STACK_ALIGNMENT, padsize);
}

/* TODO: Deallocate these after some limit is reached. */
define_closure_function(2, 0, void, free_kernel_context,
                        kernel_context, kc, boolean, queued)
{
    /* The final release may happen while running in the context (and on the
       context stack), so defer the return to free list until after the
       context switch (runloop). */
    cpuinfo ci = current_cpu();
    if (!bound(queued)) {
        bound(queued) = true;
        enqueue_irqsafe(ci->cpu_queue, closure_self());
        return;
    }
    bound(queued) = false;
    list_insert_before(&ci->free_kernel_contexts, &bound(kc)->l);
}

static void kernel_context_pause(context c)
{
    context_release_refcount(c);
}

static void kernel_context_resume(context c)
{
    context_reserve_refcount(c);
}

static void kernel_context_schedule_return(context c)
{
    kernel_context kc = (kernel_context)c;
    assert(frame_is_full(kc->context.frame));
    assert(enqueue_irqsafe(runqueue, &kc->kernel_return));
}

define_closure_function(1, 0, void, kernel_context_return,
                        struct kernel_context *, kc)
{
    kernel_context kc = bound(kc);
    context_frame f = kc->context.frame;
    assert(f[FRAME_FULL]);
    context_switch(&kc->context);
    context_release_refcount(&kc->context);
    frame_return(f);
}

static void kernel_context_pre_suspend(context c)
{
    check_kernel_context_replace(current_cpu(), (kernel_context)c);
}

kernel_context allocate_kernel_context(void)
{
    build_assert((KERNEL_CONTEXT_SIZE & (KERNEL_CONTEXT_SIZE - 1)) == 0);
    kernel_context kc = allocate((heap)heap_linear_backed(get_kernel_heaps()),
                                 KERNEL_CONTEXT_SIZE);
    if (kc == INVALID_ADDRESS)
        return kc;
    context c = &kc->context;
    init_context(c, CONTEXT_TYPE_KERNEL);
    init_refcount(&c->refcount, 1, init_closure(&kc->free, free_kernel_context, kc, false));
    c->pause = kernel_context_pause;
    c->resume = kernel_context_resume;
    c->schedule_return = kernel_context_schedule_return;
    c->pre_suspend = kernel_context_pre_suspend;
    init_closure(&kc->kernel_return, kernel_context_return, kc);
    c->fault_handler = 0;
    c->transient_heap = heap_locked(get_kernel_heaps());
    void *stack_top = ((void *)kc) + KERNEL_CONTEXT_SIZE - STACK_ALIGNMENT;
    frame_set_stack_top(c->frame, stack_top);
    return kc;
}

BSS_RO_AFTER_INIT vector cpuinfos;

cpuinfo init_cpuinfo(heap backed, int cpu)
{
    cpuinfo ci = allocate_zero(backed, sizeof(struct cpuinfo));
    if (ci == INVALID_ADDRESS)
        return ci;
    if (!vector_set(cpuinfos, cpu, ci)) {
        deallocate(backed, ci, sizeof(struct cpuinfo));
        return INVALID_ADDRESS;
    }

    /* state */
    ci->id = cpu;
    ci->state = cpu_not_present;
    ci->thread_queue = allocate_queue(backed, MAX_THREADS);
    list_init(&ci->free_syscall_contexts);
    list_init(&ci->free_kernel_contexts);
    ci->cpu_queue = allocate_queue(backed, 8); // XXX This is an arbitrary size
    assert(ci->thread_queue != INVALID_ADDRESS);
    ci->last_timer_update = 0;
    ci->frcount = 0;
    init_cpuinfo_machine(ci, backed);
    return ci;
}

void init_kernel_contexts(heap backed)
{
    cpuinfos = allocate_vector(backed, 1);
    assert(cpuinfos != INVALID_ADDRESS);
    cpuinfo ci = init_cpuinfo(backed, 0);
    assert(ci != INVALID_ADDRESS);
    cpu_init(0);
    current_cpu()->state = cpu_kernel;
}
