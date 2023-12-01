#include <kernel.h>
#include <symtab.h>

const char *context_type_strings[CONTEXT_TYPE_MAX] = {
    "undefined",
    "kernel",
    "syscall",
    "thread",
};

struct mm_stats mm_stats;

#ifdef __riscv
/* XXX newer gcc wants a memset to link to */
void *memset(void *a, u8 b, bytes len)
{
    runtime_memset(a, b, len);
    return a;
}
#endif

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

void print_frame_trace(u64 *fp)
{
    u64 *nfp;
    u64 *rap;

    for (int frame = 0; frame < FRAME_TRACE_DEPTH; frame++) {
        if (!validate_frame_ptr(fp))
            break;
        if ((rap = get_frame_ra_ptr(fp, &nfp)) == 0)
            break;

        if (*rap == 0)
            break;
        print_u64(u64_from_pointer(rap));
        rputs(":   ");
        fp = nfp;
        print_u64_with_sym(*rap);
        rputs("\n");
    }

    print_loaded_klibs();
}

void print_frame_trace_from_here(void)
{
    rputs("\nframe trace: \n");
    print_frame_trace(get_current_fp());
}

define_closure_function(2, 0, void, free_kernel_context,
                        queue, free_ctx_q, boolean, queued)
{
    kernel_context kc = struct_from_field(closure_self(), kernel_context, free);

    /* The final release may happen while running in the context (and on the
       context stack), so defer the return to free list until after the
       context switch (runloop). */
    cpuinfo ci = current_cpu();
    if (!bound(queued)) {
        bound(queued) = true;
        assert(enqueue_irqsafe(ci->cpu_queue, closure_self()));
        return;
    }

    bound(queued) = false;
    if (!enqueue(bound(free_ctx_q), kc))
        deallocate(heap_locked(get_kernel_heaps()), kc, kc->size);
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
    async_apply_bh((thunk)&kc->kernel_return);
}

define_closure_function(0, 0, void, kernel_context_return)
{
    kernel_context kc = struct_from_field(closure_self(), kernel_context, kernel_return);
    context_frame f = kc->context.frame;
    context_switch(&kc->context);
    assert(kc->context.refcount.c > 1);
    context_release_refcount(&kc->context);
    assert(frame_is_full(f));
    frame_return(f);
}

static void kernel_context_pre_suspend(context ctx);

void init_kernel_context(kernel_context kc, int type, int size, queue free_ctx_q)
{
    context c = &kc->context;
    init_context(c, type);
    init_refcount(&c->refcount, 1, init_closure(&kc->free, free_kernel_context,
                                                free_ctx_q, false));
    c->pause = kernel_context_pause;
    c->resume = kernel_context_resume;
    c->schedule_return = kernel_context_schedule_return;
    c->pre_suspend = kernel_context_pre_suspend;
    init_closure(&kc->kernel_return, kernel_context_return);
    c->fault_handler = 0;
    c->transient_heap = heap_locked(get_kernel_heaps());
    void *stack_top = ((void *)kc) + size - STACK_ALIGNMENT;
    frame_set_stack_top(c->frame, stack_top);
    kc->size = size;
    context_clear_err(c);
}

kernel_context allocate_kernel_context(cpuinfo ci)
{
    build_assert((KERNEL_CONTEXT_SIZE & (KERNEL_CONTEXT_SIZE - 1)) == 0);
    kernel_context kc = allocate(heap_locked(get_kernel_heaps()),
                                 KERNEL_CONTEXT_SIZE);
    if (kc == INVALID_ADDRESS)
        return kc;
    init_kernel_context(kc, CONTEXT_TYPE_KERNEL, KERNEL_CONTEXT_SIZE, ci->free_kernel_contexts);
    return kc;
}

static void kernel_context_pre_suspend(context ctx)
{
    cpuinfo ci = current_cpu();
    if (ci->m.kernel_context == ctx) {
        assert(ctx->refcount.c > 1); /* not final release */
        context_release_refcount(ctx);
        ctx = dequeue_single(ci->free_kernel_contexts);
        if (ctx != INVALID_ADDRESS) {
            refcount_set_count(&ctx->refcount, 1);
        } else {
            ctx = (context)allocate_kernel_context(ci);
            assert(ctx != INVALID_ADDRESS);
        }
        ci->m.kernel_context = ctx;
    }
}

BSS_RO_AFTER_INIT vector cpuinfos;
BSS_RO_AFTER_INIT vector percpu_init;

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
    assert(sched_queue_init(&ci->thread_queue, backed));
    ci->free_kernel_contexts = allocate_queue(backed, FREE_KERNEL_CONTEXT_QUEUE_SIZE);
    assert(ci->free_kernel_contexts != INVALID_ADDRESS);
    ci->free_syscall_contexts = allocate_queue(backed, FREE_SYSCALL_CONTEXT_QUEUE_SIZE);
    assert(ci->free_syscall_contexts != INVALID_ADDRESS);
    ci->free_process_contexts = allocate_queue(backed, FREE_PROCESS_CONTEXT_QUEUE_SIZE);
    assert(ci->free_process_contexts != INVALID_ADDRESS);
    ci->cpu_queue = allocate_queue(backed, CPU_QUEUE_SIZE);
    assert(ci->cpu_queue != INVALID_ADDRESS);
    ci->last_timer_update = 0;
    ci->frcount = 0;
    ci->mcs_prev = 0;
    ci->mcs_next = 0;
    ci->mcs_waiting = false;
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
    percpu_init = allocate_vector(backed, 1);
    assert(percpu_init != INVALID_ADDRESS);
}

/* finish suspend after frame save */
void __attribute__((noreturn)) context_suspend_finish(context ctx)
{
    context_reserve_refcount(ctx);
    ctx->frame[FRAME_FULL] = true; /* must be last */
    runloop();
}

void __attribute__((noreturn)) context_switch_finish(context prev, context next, void *a, u64 arg0, u64 arg1)
{
    if (prev != next) {
        cpuinfo ci = current_cpu();
        set_current_context(ci, next);
        context_release(prev);
        if (next->resume)
            next->resume(next);
    }
    ((void (*)(u64, u64))a)(arg0, arg1);
    runloop();
}

void register_percpu_init(thunk t)
{
    vector_push(percpu_init, t);
}

void run_percpu_init(void)
{
    thunk t;
    vector_foreach(percpu_init, t) {
        apply(t);
    }
}

void halt_with_code(u8 code, char *format, ...)
{
    buffer b = little_stack_buffer(512);
    vlist a;
    vstart(a, format);
    vbprintf(b, alloca_wrap_cstring(format), &a);
    vend(a);
    buffer_print(b);
    kernel_shutdown(code);
}

void unix_shutdown(void);
void kernel_powerdown(void) {
    shutting_down |= SHUTDOWN_POWER;
    unix_shutdown();
}

#ifndef CONFIG_TRACELOG
void tprintf(symbol tag, tuple attrs, const char *format, ...)
{
    vlist a;
    buffer b = little_stack_buffer(256);
    vstart(a, format);
    buffer f = alloca_wrap_buffer(format, runtime_strlen(format));
    bprintf(b, "[%T, %d, %v", now(CLOCK_ID_MONOTONIC), current_cpu()->id, tag);
    if (attrs)
        bprintf(b, " %v", attrs);
    bprintf(b, "] ");
    vbprintf(b, f, &a);
    vend(a);
    buffer_print(b);
}
#endif
