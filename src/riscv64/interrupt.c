#include <kernel.h>
#include <symtab.h>
#include <plic.h>

//#define INT_DEBUG
#ifdef INT_DEBUG
#define int_debug(x, ...) do {log_printf(ss("  INT"), ss(x), ##__VA_ARGS__);} while(0)
#else
#define int_debug(x, ...)
#endif

static const sstring interrupt_names[] = {
    ss_static_init("Instruction address misaligned"),
    ss_static_init("Instruction access fault"),
    ss_static_init("Illegal Instruction"),
    ss_static_init("Breakpoint"),
    ss_static_init("Load address misaligned"),
    ss_static_init("Load access fault"),
    ss_static_init("Store/AMO address misaligned"),
    ss_static_init("Store/AMO access fault"),
    ss_static_init("Environment call from U-mode"),
    ss_static_init("Environment call from S-mode"),
    ss_static_init("reserved 10"),
    ss_static_init("Environment call from M-mode"),
    ss_static_init("Instruction page fault"),
    ss_static_init("Load page fault"),
    ss_static_init("reserved 14"),
    ss_static_init("Store/AMO page fault"),
};


static const char register_names[][3] = {
    " pc",
    " ra",
    " sp",
    " gp",
    " tp",
    " t0",
    " t1",
    " t2",
    " fp",
    " s1",
    " a0",
    " a1",
    " a2",
    " a3",
    " a4",
    " a5",
    " a6",
    " a7",
    " s2",
    " s3",
    " s4",
    " s5",
    " s6",
    " s7",
    " s8",
    " s9",
    "s10",
    "s11",
    " t3",
    " t4",
    " t5",
    " t6",
};

typedef struct inthandler {
    struct list l;
    thunk t;
    sstring name;
} *inthandler;

static struct list *handlers;

static heap int_general;

#define IPI_BASE_INT (PLIC_MAX_INT + 1)
#define IPI_MAX_INT  (IPI_BASE_INT + 63)

static id_heap ipi_heap;

void print_stack(context_frame c)
{
    rputs("\nframe trace: \n");
    print_frame_trace(pointer_from_u64(c[FRAME_FP]));

    rputs("\nstack trace:\n");
    u64 *sp = pointer_from_u64(c[FRAME_SP]);
    for (u64 *x = sp; x < (sp + STACK_TRACE_DEPTH) &&
             validate_virtual(x, sizeof(u64)); x++) {
        print_u64(u64_from_pointer(x));
        rputs(":   ");
        print_u64_with_sym(*x);
        rputs("\n");
    }
    rputs("\n");
}

void dump_context(context ctx)
{
    context_frame f = ctx->frame;
    u64 v = SCAUSE_CODE(f[FRAME_CAUSE]);
    boolean isint = SCAUSE_INTERRUPT(f[FRAME_CAUSE]);
    if (isint)
        rputs(" interrupt: ");
    else
        rputs(" exception: ");
    print_u64(v);

    if (!isint && v < sizeof(interrupt_names)/sizeof(interrupt_names[0])) {
        rputs(" (");
        rput_sstring(interrupt_names[v]);
        rputs(")");
    }
    rputs("\n     frame: ");
    print_u64_with_sym(u64_from_pointer(f));
    if (ctx->type >= CONTEXT_TYPE_UNDEFINED && ctx->type < CONTEXT_TYPE_MAX) {
        rputs("\n      type: ");
        rput_sstring(context_type_strings[ctx->type]);
    }
    rputs("\nactive_cpu: ");
    print_u64(ctx->active_cpu);
    rputs("\n stack top: ");
    print_u64(f[FRAME_STACK_TOP]);
    rputs("\n    status: ");
    print_u64_with_sym(u64_from_pointer(f[FRAME_STATUS]));
    rputs("\n     stval: ");
    print_u64_with_sym(u64_from_pointer(f[FRAME_FAULT_ADDRESS]));
    rputs("\n");
    for (int i = 0; i < sizeof(register_names)/sizeof(register_names[0]); i++) {
        rput_sstring(isstring((char *)register_names[i], 3));
        rputs(": ");
        print_u64_with_sym(f[i]);
        rputs("\n");
    }
    print_stack(f);
}

void register_interrupt(int vector, thunk t, sstring name)
{
    // XXX ignore handlers for vector 0 (i.e. not implemented)
    if (vector == 0)
        return;

    boolean initialized = !list_empty(&handlers[vector]);
    int_debug("%s: vector %d, thunk %p (%F), name %s%s\n",
              func_ss, vector, t, t, name, initialized ? ss(", shared") : sstring_empty());

    inthandler h = allocate(int_general, sizeof(struct inthandler));
    assert(h != INVALID_ADDRESS);
    h->t = t;
    h->name = name;
    list_insert_before(&handlers[vector], &h->l);

    if (vector <= PLIC_MAX_INT && !initialized) {
        plic_set_int_priority(vector, 1);
        plic_clear_pending_int(vector);
        plic_enable_int(vector);
    }
}

void unregister_interrupt(int vector)
{
    // XXX ignore handlers for vector 0 (i.e. not implemented)
    if (vector == 0)
        return;
    int_debug("%s: vector %d\n", func_ss, vector);
    if (vector <= PLIC_MAX_INT)
        plic_disable_int(vector);
    if (list_empty(&handlers[vector]))
        halt("%s: no handler registered for vector %d\n", func_ss, vector);
    list_foreach(&handlers[vector], l) {
        inthandler h = struct_from_list(l, inthandler, l);
        int_debug("   remove handler %s (%F)\n", h->name, h->t);
        list_delete(&h->l);
        deallocate(int_general, h, sizeof(struct inthandler));
    }
}

void riscv_timer(void)
{
    /* disable timer via sbi */
    supervisor_ecall_1(SBI_EXT_0_1_SET_TIMER, -1ull);
    schedule_timer_service();
}

static boolean invoke_handlers_for_vector(cpuinfo ci, int v)
{
    if (list_empty(&handlers[v])) {
        rprintf("\nno handler for %s %d\n", v <= PLIC_MAX_INT ? ss("interrupt") : ss("IPI"), v);
        return false;
    }

    list_foreach(&handlers[v], l) {
        inthandler h = struct_from_list(l, inthandler, l);
        int_debug("   invoking handler %s (%F)\n", h->name, h->t);
        ci->state = cpu_interrupt;
        apply(h->t);
    }
    return true;
}

void trap_interrupt(void)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    context_frame f = ctx->frame;
    u64 v = SCAUSE_CODE(f[FRAME_CAUSE]);

    if (f[FRAME_FULL]) {
        console("\nframe already full\n");
        goto exit_fault;
    }

    f[FRAME_FULL] = true;
    context_reserve_refcount(ctx);

    int saved_state = ci->state;
    switch (v) {
    case TRAP_I_SSOFT:
        asm volatile("csrc sip, %0" : : "r"(SI_SSIP));
        u64 ipi_mask;
        while ((ipi_mask = atomic_swap_64(&ci->m.ipi_mask, 0))) {
            do {
                int bit = lsb(ipi_mask);
                if (!invoke_handlers_for_vector(ci, IPI_BASE_INT + bit))
                    goto exit_fault;
                ipi_mask &= ~U64_FROM_BIT(bit);
            } while (ipi_mask);
        }
        break;
    case TRAP_I_STIMER:
        int_debug("[%2d] timer interrupt, state %s\n", ci->id,
                state_strings[ci->state]);
        riscv_timer();
        break;
    case TRAP_I_SEXT: {
        u64 i;
        while ((i = plic_dispatch_int())) {
            int_debug("[%2d] # %d, state %s user %s\n", ci->id, i,
                     state_strings[ci->state],
                     (f[FRAME_STATUS] & STATUS_SPP) ? ss("false") : ss("true"));

            if (i > PLIC_MAX_INT) {
                rprintf("\ndispatched interrupt %d exceeds PLIC_MAX_INT\n", i);
                goto exit_fault;
            }

            if (!invoke_handlers_for_vector(ci, i))
                goto exit_fault;

            int_debug("   eoi %d\n", i);
            plic_eoi(i);
        }
        break;
    }
    default:
        assert(0);
    }

    /* enqueue interrupted user thread */
    if (is_thread_context(ctx) && !(shutting_down & SHUTDOWN_ONGOING)) {
        int_debug("int sched %p\n", ctx);
        context_schedule_return(ctx);
    }

    if (is_kernel_context(ctx) || is_syscall_context(ctx)) {
        context_release_refcount(ctx);
        if (saved_state != cpu_idle) {
            ci->state = cpu_kernel;
            frame_return(f);
        }
        f[FRAME_FULL] = false;      /* no longer saving frame for anything */
    }
    int_debug("   calling runloop\n");
    runloop();
  exit_fault:
    console("cpu ");
    print_u64(ci->id);
    console(", state ");
    console_sstring(state_strings[ci->state]);
    console(", vector ");
    print_u64(v);
    console("\n");
    dump_context(ctx);
    send_ipi(TARGET_EXCLUSIVE_BROADCAST, shutdown_vector);
    vm_exit(VM_EXIT_FAULT);
}

extern void (*syscall)(context_frame f);

void trap_exception(void)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    context_frame f = ctx->frame;
    u64 v = SCAUSE_CODE(f[FRAME_CAUSE]);

    if (f[FRAME_FULL]) {
        console("\nframe already full\n");
        print_u64(f[FRAME_FULL]);
        goto exit_fault;
    }

    f[FRAME_FULL] = true;
    context_reserve_refcount(ctx);

    if (f[FRAME_CAUSE] == TRAP_E_ECALL_UMODE) {
        f[FRAME_PC] += 4;   /* must advance pc, hw does not do it */
        context ctx = ci->m.syscall_context;
        set_current_context(ci, ctx);
        switch_stack_1(frame_get_stack_top(ctx->frame), syscall, f); /* frame is top of stack */
        console("\nsyscall returned to trap handler\n");
        goto exit_fault;
    }
    fault_handler fh = ctx->fault_handler;
    if (fh) {
#ifdef INT_DEBUG
        if (v < sizeof(interrupt_names)/sizeof(interrupt_names[0])) {
            rputs(" (");
            rputs_sstring(interrupt_names[v]);
            rputs(")");
        }
        rputs("\n   context: ");
        print_u64_with_sym(u64_from_pointer(ctx));
        rputs(" (");
        rputs(state_strings[ci->state]);
        rputs(")");
        rputs("\n    status: ");
        print_u64_with_sym(u64_from_pointer(f[FRAME_STATUS]));
        rputs("\n     stval: ");
        print_u64_with_sym(u64_from_pointer(f[FRAME_FAULT_ADDRESS]));
        rputs("\n       epc: ");
        print_u64_with_sym(u64_from_pointer(f[FRAME_PC]));
        rputs("\n");
#endif
        context retctx = apply(fh, ctx);
        if (retctx) {
            context_release_refcount(retctx);
            frame_return(retctx->frame);
        }
        assert(!is_kernel_context(ctx));
        runloop();
    } else {
        console("\nno fault handler for frame\n");
    }
  exit_fault:
    console("cpu ");
    print_u64(ci->id);
    console(", state ");
    console_sstring(state_strings[ci->state]);
    console(", vector ");
    print_u64(v);
    console("\n");
    dump_context(ctx);
    send_ipi(TARGET_EXCLUSIVE_BROADCAST, shutdown_vector);
    vm_exit(VM_EXIT_FAULT);
}

static void send_ipi_internal(u64 cpu, u8 vector)
{
    /* get hartid for cpu */
    cpuinfo target_ci = cpuinfo_from_id(cpu);
    u64 hartid = target_ci->m.hartid;
    assert(vector >= IPI_BASE_INT && vector <= IPI_MAX_INT);
    atomic_set_bit(&target_ci->m.ipi_mask, vector - IPI_BASE_INT);
    // rewrite to actually use mask, adjust hbase; otherwise limited to 64 cpus
    struct sbiret r = supervisor_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI,
                                       (1ull << hartid), 0, 0, 0, 0, 0);
    assert(r.error == 0);
}

void send_ipi(u64 cpu, u8 vector)
{
    if (cpu == TARGET_EXCLUSIVE_BROADCAST) {
        cpuinfo ci = current_cpu();
        for (int i = 0; i < present_processors; i++) {
            if (i == ci->id)
                continue;
            send_ipi_internal(i, vector);
        }
    } else {
        send_ipi_internal(cpu, vector);
    }
}

void init_interrupts(kernel_heaps kh)
{
    int_general = heap_locked(kh);
    handlers = allocate_zero(int_general, (IPI_MAX_INT + 1) * sizeof(handlers[0]));
    assert(handlers != INVALID_ADDRESS);
    ipi_heap = create_id_heap(int_general, int_general, IPI_BASE_INT,
                              IPI_MAX_INT - IPI_BASE_INT + 1, 1, true);
    assert(ipi_heap != INVALID_ADDRESS);
    for (int i = 0; i <= IPI_MAX_INT; i++)
        list_init(&handlers[i]);
    init_plic();
    plic_set_threshold(current_cpu()->m.hartid, 0);
}

u64 allocate_interrupt(void)
{
    assert(0);
    return 0;
}

void deallocate_interrupt(u64 irq)
{
    assert(0);
}

u64 allocate_mmio_interrupt(void)
{
    // no programmable hw interrupt support
    assert(0);
    return 0;
}

void deallocate_mmio_interrupt(u64 irq)
{
}

u64 allocate_ipi_interrupt(void)
{
    return allocate_u64((heap)ipi_heap, 1);
}

void deallocate_ipi_interrupt(u64 irq)
{
    deallocate_u64((heap)ipi_heap, irq, 1);
}

u64 allocate_msi_interrupt(void)
{
    // no programmable hw interrupt support
    assert(0);
}

void deallocate_msi_interrupt(u64 irq)
{
}

void __attribute__((noreturn)) __stack_chk_fail(void)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    rprintf("stack check failed on cpu %d\n", ci->id);
    dump_context(ctx);
    vm_exit(VM_EXIT_FAULT);
}
