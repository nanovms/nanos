#include <kernel.h>
#include <symtab.h>
#include <gic.h>

//#define INT_DEBUG
#ifdef INT_DEBUG
#define int_debug(x, ...) do {log_printf("  INT", x, ##__VA_ARGS__);} while(0)
#else
#define int_debug(x, ...)
#endif

#define MAX_INTERRUPT_VECTORS  256 /* as defined by architecture; we may have less */

typedef struct inthandler {
    struct list l;
    thunk t;
    const char *name;
} *inthandler;

static struct list *handlers;

extern u32 n_interrupt_vectors;
extern u32 interrupt_vector_size;
extern void * interrupt_vectors;

static char* gpreg_names[FRAME_N_GPREG] = {
    "  x0", "  x1", "  x2", "  x3", "  x4", "  x5", "  x6", "  x7",
    "  x8", "  x9", " x10", " x11", " x12", " x13", " x14", " x15",
    " x16", " x17", " x18", " x19", " x20", " x21", " x22", " x23",
    " x24", " x25", " x26", " x27", " x28", " x29", " x30", "  sp" };

static char* fpsimd_names[35] = {
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

void print_frame(context f)
{
    rputs("\n     frame: ");
    print_u64_with_sym(u64_from_pointer(f));
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
        rputs(esr_ec == ESR_EC_INST_ABRT_LEL ? "el0" : "el1");
        print_far_if_valid(iss);
        /* ... */
        break;
    case ESR_EC_PC_ALIGN_FAULT:
        rputs(" pc alignment");
        break;
    case ESR_EC_DATA_ABRT_LEL:
    case ESR_EC_DATA_ABRT:
        rputs(" data abort in ");
        rputs(esr_ec == ESR_EC_DATA_ABRT_LEL ? "el0" : "el1");
        rputs(iss & ESR_ISS_DATA_ABRT_WnR ? " write" : " read");
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
            const char *str;
            if (iss & ESR_ISS_SERROR_INT_IESB)
                rputs(", IESB");
            switch (field_from_u64(iss, ESR_ISS_SERROR_INT_AET)) {
            case ESR_ISS_SERROR_INT_AET_UC:
                str = ", UC";
                break;
            case ESR_ISS_SERROR_INT_AET_UEU:
                str = ", UEU";
                break;
            case ESR_ISS_SERROR_INT_AET_UEO:
                str = ", UEO";
                break;
            case ESR_ISS_SERROR_INT_AET_UER:
                str = ", UER";
                break;
            case ESR_ISS_SERROR_INT_AET_CE:
                str = ", CE";
                break;
            default:
                str = ", unknown AET";
            }
            rputs(str);
            if (iss & ESR_ISS_SERROR_INT_EA)
                rputs(", EA");
            switch (field_from_u64(iss, ESR_ISS_SERROR_INT_DFSC)) {
            case ESR_ISS_SERROR_INT_DFSC_UNCAT:
                str = " uncategorized";
                break;
            case ESR_ISS_SERROR_INT_DFSC_ASYNC:
                str = " async";
                break;
            default:
                str = " unknown";
            }
            rputs("DFSC ");
            rputs(str);
        }
        break;
    default:
        rputs(" illegal ec: ");
        print_u64(esr_ec);
    }

    rputs("\n       elr: ");
    print_u64_with_sym(f[FRAME_ELR]);
    rputs("\n\n");

    for (int j = 0; j < FRAME_N_GPREG; j++) {
        rputs("      ");
        rputs(gpreg_names[j]);
        rputs(": ");
        print_u64_with_sym(f[j]);
        int qidx = FRAME_Q0 + (2 * j);
        if (f[qidx] || f[qidx + 1]) {
            rputs(fpsimd_names[j]);
            rputs(": ");
            print_u64(f[qidx + 1]);
            print_u64(f[qidx]);
        }
        rputs("\n");
    }
    for (int j = 0; j < 2; j++) {
        u64 v = f[FRAME_FPSR + j];
        if (!v)
            continue;
        rputs("      ");
        rputs(fpsimd_names[32 + j]);
        rputs(": ");
        print_u64(v);
        rputs("\n");
    }
}

void frame_trace(u64 *fp)
{
    for (unsigned int frame = 0; frame < FRAME_TRACE_DEPTH; frame ++) {
        if (!validate_virtual(fp, sizeof(u64)) ||
            !validate_virtual(fp + 1, sizeof(u64)))
            break;

        u64 n = fp[1];
        if (n == 0)
            break;
        print_u64(u64_from_pointer(fp + 1));
        rputs(":   ");
        fp = pointer_from_u64(fp[0]);
        print_u64_with_sym(n);
        rputs("\n");
    }
}

void print_frame_trace_from_here(void)
{
    rputs("\nframe trace: \n");
    u64 fp;
    asm("mov %0, x29" : "=r" (fp));
    frame_trace(pointer_from_u64(fp));
}

void print_stack(context c)
{
    rputs("\nframe trace: \n");
    frame_trace(pointer_from_u64(c[FRAME_X29]));

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

extern void (*syscall)(context f);

NOTRACE
void synchronous_handler(void)
{
    cpuinfo ci = current_cpu();
    context f = get_running_frame(ci);
    u32 esr = esr_from_frame(f);

    int_debug("caught exception, EL%d, esr 0x%x\n", f[FRAME_EL], esr);

    if (field_from_u64(esr, ESR_EC) == ESR_EC_SVC_AARCH64 && (esr & ESR_IL) &&
        field_from_u64(esr, ESR_ISS_IMM16) == 0) {
        f[FRAME_VECTOR] = f[FRAME_X8];
        set_running_frame(ci, frame_from_kernel_context(get_kernel_context(ci)));
        switch_stack_1(get_running_frame(ci), syscall, f); /* frame is top of stack */
        halt("%s: syscall returned\n", __func__);
    }

    /* fault handlers likely act on cpu state, so don't change it */
    fault_handler fh = pointer_from_u64(f[FRAME_FAULT_HANDLER]);
    if (fh) {
        context retframe = apply(fh, f);
        if (retframe)
            frame_return(retframe);
        if (is_current_kernel_context(f))
            f[FRAME_FULL] = false;      /* no longer saving frame for anything */
        runloop();
    } else {
        console("\nno fault handler for frame ");
        print_frame(f);
        print_stack(f);
        vm_exit(VM_EXIT_FAULT);
    }
}

NOTRACE
void irq_handler(void)
{
    cpuinfo ci = current_cpu();
    context f = get_running_frame(ci);
    u64 i;

    int_debug("%s: enter\n", __func__);

    /* re-enqueue interrupted user thread */
    if (ci->state == cpu_user && !shutting_down) {
        int_debug("int sched %F\n", f[FRAME_RUN]);
        schedule_frame(f);
    }

    while ((i = gic_dispatch_int()) != INTID_NO_PENDING) {
        int_debug("[%2d] # %d, state %s, EL%d, frame %p, elr 0x%lx, spsr_esr 0x%lx\n",
                  ci->id, i, state_strings[ci->state], f[FRAME_EL],
                  f, f[FRAME_ELR], f[FRAME_ESR_SPSR]);

        if (i >= GIC_MAX_INT)
            halt("dispatched interrupt %d exceeds GIC_MAX_INT\n", i);

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

    if (is_current_kernel_context(f))
        f[FRAME_FULL] = false;
    int_debug("   calling runloop\n");
    runloop();
}

NOTRACE
void serror_handler(void)
{
    console("\nserror exception caught\n");
    cpuinfo ci = current_cpu();
    context f = get_running_frame(ci);
    print_frame(f);
    print_stack(f);
    vm_exit(VM_EXIT_FAULT);
}

NOTRACE
void invalid_handler(void)
{
    halt("%s\n", __func__);
}

static id_heap ipi_vector_heap;
static id_heap msi_vector_heap;
static id_heap mmio_vector_heap;
static heap int_general;

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

void register_interrupt(int vector, thunk t, const char *name)
{
    boolean initialized = !list_empty(&handlers[vector]);
    int_debug("%s: vector %d, thunk %p (%F), name %s%s\n",
              __func__, vector, t, t, name, initialized ? ", shared" : "");

    inthandler h = allocate(int_general, sizeof(struct inthandler));
    assert(h != INVALID_ADDRESS);
    h->t = t;
    h->name = name;
    list_insert_before(&handlers[vector], &h->l);

    if (!initialized) {
        gic_set_int_priority(vector, 0);
        if (vector >= gic_msi_vector_base &&
            vector < (gic_msi_vector_base + gic_msi_vector_num))
            gic_set_int_config(vector, GICD_ICFGR_EDGE);
        gic_clear_pending_int(vector);
        gic_enable_int(vector);
    }
}

void unregister_interrupt(int vector)
{
    int_debug("%s: vector %d\n", __func__, vector);
    gic_disable_int(vector);
    if (list_empty(&handlers[vector]))
        halt("%s: no handler registered for vector %d\n", __func__, vector);
    list_foreach(&handlers[vector], l) {
        inthandler h = struct_from_list(l, inthandler, l);
        int_debug("   remove handler %s (%F)\n", h->name, h->t);
        list_delete(&h->l);
        deallocate(int_general, h, sizeof(struct inthandler));
    }
}

extern void *exception_vectors;

closure_function(0, 0, void, arm_timer)
{
    // This assert failed once under KVM...not clear if it's a valid assumption...
    // assert(read_psr(CNTV_CTL_EL0) & CNTV_CTL_EL0_ISTATUS);
    write_psr(CNTV_CTL_EL0, 0);
}

closure_struct(arm_timer, _timer);

void init_interrupts(kernel_heaps kh)
{
    int_general = heap_locked(kh);
    handlers = allocate_zero(int_general, GIC_MAX_INT * sizeof(handlers[0]));
    assert(handlers != INVALID_ADDRESS);
    for (int i = 0; i < GIC_MAX_INT; i++)
        list_init(&handlers[i]);

    /* set exception vector table base */
    register u64 v = u64_from_pointer(&exception_vectors);
    asm volatile("dsb sy; msr vbar_el1, %0" :: "r"(v));

    /* initialize interrupt controller */
    init_gic();

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
    gic_set_int_config(GIC_TIMER_IRQ, GICD_ICFGR_LEVEL);
    gic_set_int_priority(GIC_TIMER_IRQ, 0);
    gic_set_int_target(GIC_TIMER_IRQ, 1);
    register_interrupt(GIC_TIMER_IRQ, init_closure(&_timer, arm_timer), "arm timer");
}
