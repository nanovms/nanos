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

define_closure_function(1, 0, void, free_kernel_context,
                        kernel_context, kc)
{
    /* TODO we can dealloc after some maximum... */
    list_insert_before(&current_cpu()->free_kernel_contexts, &bound(kc)->l);
}

define_closure_function(1, 0, void, kernel_context_schedule_return,
                        kernel_context, kc)
{
    kernel_context kc = bound(kc);
    assert(frame_is_full(kc->context.frame));
    assert(enqueue_irqsafe(runqueue, &kc->kernel_return));
}

define_closure_function(1, 0, void, kernel_context_return,
                        kernel_context, kc)
{
    context_frame f = bound(kc)->context.frame;
    assert(f[FRAME_FULL]);
    context_switch(&bound(kc)->context);
    frame_return(f);
}

define_closure_function(1, 0, void, kernel_context_pre_suspend,
                        kernel_context, kc)
{
    check_kernel_context_replace();
}

kernel_context allocate_kernel_context(void)
{
    heap h = heap_locked(get_kernel_heaps());
    kernel_context kc = allocate(h, sizeof(struct kernel_context));
    if (kc == INVALID_ADDRESS)
        return kc;
    context c = &kc->context;
    init_context(c, CONTEXT_TYPE_KERNEL);
    init_refcount(&kc->refcount, 1, init_closure(&kc->free, free_kernel_context, kc));
    c->pause = 0;
    c->resume = 0;
    c->schedule_return = init_closure(&kc->schedule_return, kernel_context_schedule_return, kc);
    c->pre_suspend = init_closure(&kc->pre_suspend, kernel_context_pre_suspend, kc);
    init_closure(&kc->kernel_return, kernel_context_return, kc);
    c->fault_handler = 0;
    c->transient_heap = h;
    void *stack = allocate_stack(h, SYSCALL_STACK_SIZE);
    frame_set_stack_top(c->frame, stack);
    install_runloop_trampoline(c, runloop);
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
    ci->have_kernel_lock = false;
    ci->thread_queue = allocate_queue(backed, MAX_THREADS);
    list_init(&ci->free_syscall_contexts);
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
