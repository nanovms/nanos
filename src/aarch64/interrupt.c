#include <kernel.h>
#include <drivers/acpi.h>
#include <symtab.h>
#include <gic.h>

//#define INT_DEBUG
#ifdef INT_DEBUG
#define int_debug(x, ...) do {tprintf(sym(int), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define int_debug(x, ...)
#endif

typedef struct inthandler {
    struct list l;
    thunk t;
    sstring name;
} *inthandler;

BSS_RO_AFTER_INIT static struct list *handlers;

static const char gpreg_names[FRAME_N_GPREG][3] = {
    " x0", " x1", " x2", " x3", " x4", " x5", " x6", " x7",
    " x8", " x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", " sp" };

static const char fpsimd_names[35][4] = {
    "  q0", "  q1", "  q2", "  q3", "  q4", "  q5", "  q6", "  q7",
    "  q8", "  q9", " q10", " q11", " q12", " q13", " q14", " q15",
    " q16", " q17", " q18", " q19", " q20", " q21", " q22", " q23",
    " q24", " q25", " q26", " q27", " q28", " q29", " q30", " q31",
    "fpsr", "fpcr"};

static void print_far_if_valid(u32 iss)
{
    if ((iss & ESR_ISS_DATA_ABRT_FnV) == 0) {
        register u64 far;
        asm("mrs %0, FAR_EL1" : "=r"(far));
        rputs("\n       far: ");
        print_u64_with_sym(far);
    }
}

static void print_stack(context_frame c)
{
    rputs("\nframe trace: \n");
    print_frame_trace(pointer_from_u64(c[FRAME_X29]));

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
    rputs("\n     frame: ");
    print_u64_with_sym(u64_from_pointer(f));
    if (ctx->type >= CONTEXT_TYPE_UNDEFINED && ctx->type < CONTEXT_TYPE_MAX) {
        rputs("\n      type: ");
        rput_sstring(context_type_strings[ctx->type]);
    }
    rputs("\n      spsr: ");
    print_u64(f[FRAME_ESR_SPSR] & MASK(32));
    rputs("\n       esr: ");
    u32 esr = f[FRAME_ESR_SPSR] >> 32;
    print_u64(esr);

    int esr_ec = field_from_u64(esr, ESR_EC);
    u32 iss = field_from_u64(esr, ESR_ISS);
    switch (esr_ec) {
    case ESR_EC_UNKNOWN:
        rputs(" unknown");
        break;
    case ESR_EC_ILL_EXEC:
        rputs(" illegal execution");
        break;
    case ESR_EC_INST_ABRT_LEL:
    case ESR_EC_INST_ABRT:
        rputs(" instruction abort in ");
        rput_sstring(esr_ec == ESR_EC_INST_ABRT_LEL ? ss("el0") : ss("el1"));
        print_far_if_valid(iss);
        /* ... */
        break;
    case ESR_EC_PC_ALIGN_FAULT:
        rputs(" pc alignment");
        break;
    case ESR_EC_DATA_ABRT_LEL:
    case ESR_EC_DATA_ABRT:
        rputs(" data abort in ");
        rput_sstring(esr_ec == ESR_EC_DATA_ABRT_LEL ? ss("el0") : ss("el1"));
        rput_sstring(iss & ESR_ISS_DATA_ABRT_WnR ? ss(" write") : ss(" read"));
        if (iss & ESR_ISS_DATA_ABRT_CM)
            rputs(" cache");
        print_far_if_valid(iss);
        break;
    case ESR_EC_SP_ALIGN_FAULT:
        rputs(" sp alignment");
        break;
    case ESR_EC_SERROR_INT:
        rputs(" serror int");
        if (iss & ESR_ISS_SERROR_INT_IDS) {
            rputs(", impl defined, ISS: ");
            print_u64(iss);
        } else {
            sstring str;
            if (iss & ESR_ISS_SERROR_INT_IESB)
                rputs(", IESB");
            switch (field_from_u64(iss, ESR_ISS_SERROR_INT_AET)) {
            case ESR_ISS_SERROR_INT_AET_UC:
                str = ss(", UC");
                break;
            case ESR_ISS_SERROR_INT_AET_UEU:
                str = ss(", UEU");
                break;
            case ESR_ISS_SERROR_INT_AET_UEO:
                str = ss(", UEO");
                break;
            case ESR_ISS_SERROR_INT_AET_UER:
                str = ss(", UER");
                break;
            case ESR_ISS_SERROR_INT_AET_CE:
                str = ss(", CE");
                break;
            default:
                str = ss(", unknown AET");
            }
            rput_sstring(str);
            if (iss & ESR_ISS_SERROR_INT_EA)
                rputs(", EA");
            switch (field_from_u64(iss, ESR_ISS_SERROR_INT_DFSC)) {
            case ESR_ISS_SERROR_INT_DFSC_UNCAT:
                str = ss(" uncategorized");
                break;
            case ESR_ISS_SERROR_INT_DFSC_ASYNC:
                str = ss(" async");
                break;
            default:
                str = ss(" unknown");
            }
            rputs("DFSC ");
            rput_sstring(str);
        }
        break;
    case ESR_EC_BRK:
        rputs(" brk");
        break;
    default:
        rputs(" illegal ec: ");
        print_u64(esr_ec);
    }

    rputs("\n       elr: ");
    print_u64_with_sym(f[FRAME_ELR]);
    rputs("\n       far: ");
    print_u64_with_sym(f[FRAME_FAULT_ADDRESS]);
    rputs("\nactive_cpu: ");
    print_u64(ctx->active_cpu);
    rputs("\n stack top: ");
    print_u64(f[FRAME_STACK_TOP]);
    rputs("\n\n");

    u64 *fp = frame_extended(f);
    for (int j = 0; j < FRAME_N_GPREG; j++) {
        rputs("      ");
        rput_sstring(isstring((char *)gpreg_names[j], 3));
        rputs(": ");
        print_u64_with_sym(f[j]);
        int qidx = (2 * j);
        if (fp && (fp[qidx] || fp[qidx + 1])) {
            rput_sstring(isstring((char *)fpsimd_names[j], 4));
            rputs(": ");
            print_u64(fp[qidx + 1]);
            print_u64(fp[qidx]);
        }
        rputs("\n");
    }
    for (int j = 0; j < 2; j++) {
        u64 v = f[FRAME_FPSR + j];
        if (!v)
            continue;
        rputs("     ");
        rput_sstring(isstring((char *)fpsimd_names[32 + j], 4));
        rputs(": ");
        print_u64(v);
        rputs("\n");
    }
    print_stack(f);
}

extern void (*syscall)(context f);
extern void *angel_shutdown_trap;

NOTRACE
void synchronous_handler(void)
{
    cpuinfo ci = current_cpu();
    bitmap_set_atomic(idle_cpu_mask, ci->id, 0);
    context ctx = get_current_context(ci);
    context_frame f = ctx->frame;
    u32 esr = esr_from_frame(f);

    int_debug("caught exception, EL%d, esr 0x%x\n", f[FRAME_EL], esr);

    if (f[FRAME_FULL])
        halt("\nframe %p already full\n", f);
    f[FRAME_FULL] = true;
    context_reserve_refcount(ctx);

    int ec = field_from_u64(esr, ESR_EC);
    if (ec == ESR_EC_SVC_AARCH64 && (esr & ESR_IL) &&
        field_from_u64(esr, ESR_ISS_IMM16) == 0) {
        context ctx = ci->m.syscall_context;
        f[FRAME_VECTOR] = f[FRAME_X8];
        set_current_context(ci, ctx);
        switch_stack_1(frame_get_stack_top(ctx->frame), syscall, f);
        halt("%s: syscall returned\n", func_ss);
    }

    if (ec == ESR_EC_UNKNOWN) {
        /* If the fault was generated by the 'hlt 0xf000' trap in
           angel_shutdown, revert using psci to shut down. */
        if (f[FRAME_ELR] == u64_from_pointer(&angel_shutdown_trap)) {
            console("\nAngel shutdown trap failed; shutting down with PSCI.\n"
                    "QEMU exit code will not reflect program exit code.\n");
            psci_shutdown();
        }
    }

    fault_handler fh = ctx->fault_handler;
    if (fh) {
        context retctx = apply(fh, ctx);
        if (retctx) {
            context_release_refcount(retctx);
            if (is_usermode_fault(f))
                /* Before returning to EL0, restore the EL1 stack pointer (i.e. unconsume the stack
                 * space consumed by this function), otherwise the handler of the next exception
                 * taken from EL0 may use the modified stack pointer (and consume more stack space),
                 * which could lead to a stack overflow if a large number of such exceptions occurs
                 * before the next runloop invocation. */
                asm volatile("mov sp, %0" :: "r"(frame_get_stack_top(ci->m.kernel_context->frame)) :
                             "memory");
            frame_return(retctx->frame);
        }
        runloop();
    } else {
        console("\nno fault handler for frame ");
        dump_context(ctx);
        vm_exit(VM_EXIT_FAULT);
    }
}

NOTRACE
void irq_handler(void)
{
    cpuinfo ci = current_cpu();
    bitmap_set_atomic(idle_cpu_mask, ci->id, 0);
    context ctx = get_current_context(ci);
    context_frame f = ctx->frame;
    u64 i;

    int_debug("%s: enter\n", func_ss);

    int saved_state = ci->state;

    if (f[FRAME_FULL])
        halt("\nframe %p already full\n", f);
    f[FRAME_FULL] = true;
    context_reserve_refcount(ctx);

    while ((i = gic_dispatch_int()) != INTID_NO_PENDING) {
        int_debug("[%2d] # %d, state %s, EL%d, frame %p, elr 0x%lx, spsr_esr 0x%lx\n",
                  ci->id, i, state_strings[ci->state], f[FRAME_EL],
                  f, f[FRAME_ELR], f[FRAME_ESR_SPSR]);

        if (list_empty(&handlers[i]))
            halt("no handler for interrupt %d\n", i);

        list_foreach(&handlers[i], l) {
            inthandler h = struct_from_list(l, inthandler, l);
            int_debug("   invoking handler %s (%F)\n", h->name, h->t);
            ci->state = cpu_interrupt;
            apply(h->t);
        }

        int_debug("   eoi %d\n", i);
        gic_eoi(i);
    }

    /* enqueue interrupted user thread */
    if (is_thread_context(ctx) && !(shutting_down & SHUTDOWN_ONGOING)) {
        int_debug("int sched thread %p\n", ctx);
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
}

NOTRACE
void serror_handler(void)
{
    console("\nserror exception caught\n");
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    dump_context(ctx);
    vm_exit(VM_EXIT_FAULT);
}

NOTRACE
void invalid_handler(void)
{
    halt("%s\n", func_ss);
}

BSS_RO_AFTER_INIT static id_heap ipi_vector_heap;
BSS_RO_AFTER_INIT static id_heap msi_vector_heap;
BSS_RO_AFTER_INIT static id_heap mmio_vector_heap;
BSS_RO_AFTER_INIT static heap int_general;

#define MK_INT_ALLOC_FNS(name)                                          \
    u64 allocate_## name ##_interrupt(void)                             \
    {                                                                   \
        return name ## _vector_heap ? allocate_u64((heap)name ## _vector_heap, 1) : INVALID_PHYSICAL; \
    }                                                                   \
    void deallocate_## name ##_interrupt(u64 irq)                       \
    {                                                                   \
        if (name ## _vector_heap)                                       \
            deallocate_u64((heap)name ## _vector_heap, irq, 1);         \
    }

MK_INT_ALLOC_FNS(ipi)
MK_INT_ALLOC_FNS(msi)
MK_INT_ALLOC_FNS(mmio)

static void interrupt_init(int vector)
{
    gic_set_int_priority(vector, 0);
    if (vector >= gic_msi_vector_base && vector < (gic_msi_vector_base + gic_msi_vector_num))
        gic_set_int_config(vector, GICD_ICFGR_EDGE);
    gic_clear_pending_int(vector);
    gic_enable_int(vector);
}

static void irq_register_internal(int vector, thunk t, sstring name, range cpu_affinity)
{
    boolean initialized = !list_empty(&handlers[vector]);
    int_debug("%s: vector %d, thunk %p (%F), name %s%s\n",
              func_ss, vector, t, t, name, initialized ? ss(", shared") : sstring_empty());

    inthandler h = allocate(int_general, sizeof(struct inthandler));
    assert(h != INVALID_ADDRESS);
    h->t = t;
    h->name = name;
    list_insert_before(&handlers[vector], &h->l);

    if (!initialized) {
        if (!range_empty(cpu_affinity))
            gic_set_int_target(vector, irq_get_target_cpu(cpu_affinity));
        interrupt_init(vector);
    }
}

void register_interrupt(int vector, thunk t, sstring name)
{
    irq_register_internal(vector, t, name, irange(0, 0));
}

void unregister_interrupt(int vector)
{
    int_debug("%s: vector %d\n", func_ss, vector);
    gic_disable_int(vector);
    if (list_empty(&handlers[vector]))
        halt("%s: no handler registered for vector %d\n", func_ss, vector);
    list_foreach(&handlers[vector], l) {
        inthandler h = struct_from_list(l, inthandler, l);
        int_debug("   remove handler %s (%F)\n", h->name, h->t);
        list_delete(&h->l);
        deallocate(int_general, h, sizeof(struct inthandler));
    }
}

void irq_register_handler(int irq, thunk h, sstring name, range cpu_affinity)
{
    if (range_empty(cpu_affinity))
        cpu_affinity = irange(0, total_processors);
    irq_register_internal(irq, h, name, cpu_affinity);
}

extern void *exception_vectors;

/* set exception vector table base */
static void exc_vbar_set(void)
{
    register u64 v = u64_from_pointer(&exception_vectors);
    asm volatile("dsb sy; msr vbar_el1, %0" :: "r"(v));
}

closure_function(0, 0, void, arm_timer)
{
    // This assert failed once under KVM...not clear if it's a valid assumption...
    // assert(read_psr(CNTV_CTL_EL0) & CNTV_CTL_EL0_ISTATUS);
    write_psr(CNTV_CTL_EL0, 0);
    schedule_timer_service();
}

BSS_RO_AFTER_INIT closure_struct(arm_timer, _timer);

closure_function(0, 0, void, interrupt_percpu_init)
{
    exc_vbar_set();
    gic_percpu_init();
    for (int i = GIC_SGI_INTS_START; i < GIC_PPI_INTS_END; i++)
        if (!list_empty(&handlers[i]))
            interrupt_init(i);
}

BSS_RO_AFTER_INIT closure_struct(interrupt_percpu_init, int_percpu_init);

void init_interrupts(kernel_heaps kh)
{
    int_general = heap_locked(kh);

    exc_vbar_set();

    /* initialize interrupt controller */
    int gic_max_int = init_gic();

    handlers = mem_alloc(int_general, gic_max_int * sizeof(handlers[0]),
                         MEM_ZERO | MEM_NOWAIT | MEM_NOFAIL);
    for (int i = 0; i < gic_max_int; i++)
        list_init(&handlers[i]);

    /* msi vector heap */
    if (gic_msi_vector_num > 0) {
        assert(gic_msi_vector_base >= GIC_SPI_INTS_START);
        msi_vector_heap = create_id_heap(int_general, int_general, gic_msi_vector_base,
                                         gic_msi_vector_num, 1, false);
        assert(msi_vector_heap != INVALID_ADDRESS);
    }

    /* inter-processor vector heap */
    ipi_vector_heap = create_id_heap(int_general, int_general, GIC_SGI_INTS_START,
                                     GIC_SGI_INTS_END - GIC_SGI_INTS_START, 1, false);
    assert(ipi_vector_heap != INVALID_ADDRESS);

    /* virtio mmio vector heap */
    mmio_vector_heap = create_id_heap(int_general, int_general,
                                      GIC_SPI_INTS_START + VIRT_MMIO_IRQ_BASE,
                                      VIRT_MMIO_IRQ_NUM, 1, false);
    assert(mmio_vector_heap != INVALID_ADDRESS);

    /* timer init is minimal, stash irq setup here */
    u32 timer_irq = acpi_get_gt_irq();
    if (!timer_irq)
        timer_irq = GIC_TIMER_IRQ;
    gic_set_int_config(timer_irq, GICD_ICFGR_LEVEL);
    gic_set_int_priority(timer_irq, 0);
    register_interrupt(timer_irq, init_closure(&_timer, arm_timer), ss("arm timer"));

    register_percpu_init(init_closure(&int_percpu_init, interrupt_percpu_init));
}

void __attribute__((noreturn)) __stack_chk_fail(void)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    msg_err("stack check failed on cpu %d", ci->id);
    dump_context(ctx);
    vm_exit(VM_EXIT_FAULT);
}
