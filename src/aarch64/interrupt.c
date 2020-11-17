#include <kernel.h>
#include <page.h>
#include <symtab.h>
#include <gic.h>

//#define INT_DEBUG
#ifdef INT_DEBUG
#define int_debug(x, ...) do {log_printf("  INT", x, ##__VA_ARGS__);} while(0)
#else
#define int_debug(x, ...)
#endif

#define INTERRUPT_VECTOR_START 32 /* end of exceptions; defined by architecture */
#define MAX_INTERRUPT_VECTORS  256 /* as defined by architecture; we may have less */

static const char *interrupt_names[MAX_INTERRUPT_VECTORS] = {
    "dummy",
};

static thunk *handlers;
extern u32 n_interrupt_vectors;
extern u32 interrupt_vector_size;
extern void * interrupt_vectors;

static char* textoreg[FRAME_N_GPREG] = {
    "  x0", "  x1", "  x2", "  x3", "  x4", "  x5", "  x6", "  x7",
    "  x8", "  x9", " x10", " x11", " x12", " x13", " x14", " x15",
    " x16", " x17", " x18", " x19", " x20", " x21", " x22", " x23",
    " x24", " x25", " x26", " x27", " x28", " x29", " x30", "  sp" };

void install_fallback_fault_handler(fault_handler h)
{
    // XXX reconstruct
    for (int i = 0; i < MAX_CPUS; i++) {
        cpuinfo_from_id(i)->kernel_context->frame[FRAME_FAULT_HANDLER] = u64_from_pointer(h);
    }
}

static void print_far_if_valid(u32 iss)
{
    if ((iss & ESR_ISS_DATA_ABRT_FnV) == 0) {
        register u64 far;
        asm("mrs %0, FAR_EL1" : "=r"(far));
        console("\n       far: ");
        print_u64_with_sym(far);
    }
}

void print_frame(context f)
{
    u64 v = f[FRAME_VECTOR];
    console(" interrupt: ");
    print_u64(v);
    if (v < INTERRUPT_VECTOR_START) {
        console(" (");
        console((char *)interrupt_names[v]);
        console(")");
    }
    console("\n     frame: ");
    print_u64_with_sym(u64_from_pointer(f));
    console("\n      spsr: ");
    print_u64(f[FRAME_ESR_SPSR] & MASK(32));
    console("\n       esr: ");
    u32 esr = f[FRAME_ESR_SPSR] >> 32;
    print_u64(esr);

    int esr_ec = field_from_u64(esr, ESR_EC);
    u32 iss = field_from_u64(esr, ESR_ISS);
    switch (esr_ec) {
    case ESR_EC_UNKNOWN:
        console(" unknown");
        break;
    case ESR_EC_ILL_EXEC:
        console(" illegal execution");
        break;
    case ESR_EC_INST_ABRT_LEL:
    case ESR_EC_INST_ABRT:
        console(" instruction abort in ");
        console(esr_ec == ESR_EC_INST_ABRT_LEL ? "el0" : "el1");
        print_far_if_valid(iss);
        /* ... */
        break;
    case ESR_EC_PC_ALIGN_FAULT:
        console(" pc alignment");
        break;
    case ESR_EC_DATA_ABRT_LEL:
    case ESR_EC_DATA_ABRT:
        console(" data abort in ");
        console(esr_ec == ESR_EC_DATA_ABRT_LEL ? "el0" : "el1");
        console(iss & ESR_ISS_DATA_ABRT_WnR ? " write" : " read");
        if (iss & ESR_ISS_DATA_ABRT_CM)
            console(" cache");
        print_far_if_valid(iss);
        break;
    case ESR_EC_SP_ALIGN_FAULT:
        console(" sp alignment");
        break;
    case ESR_EC_SERROR_INT:
        console(" serror interrupt");
        break;
    }

    console("\n       elr: ");
    print_u64_with_sym(f[FRAME_ELR]);
    console("\n\n");

    for (int j = 0; j < FRAME_N_GPREG; j++) {
        console("      ");
        console(textoreg[j]);
        console(": ");
        print_u64_with_sym(f[j]);
        console("\n");        
    }
}

#define STACK_TRACE_DEPTH       128
void print_stack(context c)
{
    console("\nstack trace:\n");
    u64 *x = pointer_from_u64(c[FRAME_SP]);
//    u64 *top = pointer_from_u64(c[FRAME_STACK_TOP]);
    for (u64 i = 0; i < STACK_TRACE_DEPTH && ((void*)x) < pointer_from_u64(0xffff000000020000ull); i++) {
        print_u64(u64_from_pointer(x));
        console(":   ");
        print_u64_with_sym(*x++);
        console("\n");
    }
    console("\n");
}

extern void (*syscall)(context f);

NOTRACE
void synchronous_handler(void)
{
    cpuinfo ci = current_cpu();
    context f = ci->running_frame;

#if 0
    early_debug("\ncaught exception, el ");
    early_debug_u64(f[FRAME_EL]);
    early_debug("\n\n");
    print_frame(f);
    print_stack(f);
#endif

    u32 esr = esr_from_frame(f);

    if (field_from_u64(esr, ESR_EC) == ESR_EC_SVC_AARCH64 && (esr & ESR_IL) &&
        field_from_u64(esr, ESR_ISS_IMM16) == 0) {
        f[FRAME_VECTOR] = f[FRAME_X8];
        ci->running_frame = ci->kernel_context->frame;
        switch_stack_1(ci->running_frame, syscall, f); /* frame is top of stack */
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
        while(1);
    }
}

NOTRACE
void irq_handler(void)
{
    cpuinfo ci = current_cpu();
    context f = ci->running_frame;
    u64 i;

    int_debug("%s: enter\n", __func__);

    while ((i = gic_dispatch_int()) != INTID_NO_PENDING) {
        int_debug("[%2d] # %d (%s), state %s, el %d, frame %p, elr 0x%lx, spsr_esr 0x%lx\n",
                  ci->id, i, interrupt_names[i], state_strings[ci->state], f[FRAME_EL],
                  f, f[FRAME_ELR], f[FRAME_ESR_SPSR]);

        if (handlers[i]) {
            int_debug("   invoking handler %F\n", handlers[i]);
            ci->state = cpu_interrupt;
            apply(handlers[i]);
            int_debug("   eoi %d\n", i);
            gic_eoi(i);
        }
    }

    if (is_current_kernel_context(f))
        f[FRAME_FULL] = false;
    int_debug("   calling runloop\n");
    runloop();
}

NOTRACE
void serror_handler(void)
{
    halt("%s\n", __func__);
}

NOTRACE
void invalid_handler(void)
{
    halt("%s\n", __func__);
}

static id_heap interrupt_vector_heap;

u64 allocate_interrupt(void)
{
    return allocate_u64((heap)interrupt_vector_heap, 1);
}

void deallocate_interrupt(u64 irq)
{
    deallocate_u64((heap)interrupt_vector_heap, irq, 1);
}

boolean reserve_interrupt(u64 irq)
{
    return id_heap_set_area(interrupt_vector_heap, irq, 1, true, true);
}

void register_interrupt(int vector, thunk t, const char *name)
{
    int_debug("%s: vector %d, thunk %p (%F), name %s\n",
              __func__, vector, t, t, name);
    if (handlers[vector])
        halt("%s: handler for vector %d already registered (%p)\n",
             __func__, vector, handlers[vector]);
    handlers[vector] = t;
    interrupt_names[vector] = name;

    gic_set_int_priority(vector, 0);
    gic_clear_pending_int(vector);
    gic_enable_int(vector);
}

void unregister_interrupt(int vector)
{
    gic_disable_int(vector);
    if (!handlers[vector])
        halt("%s: no handler registered for vector %d\n", __func__, vector);
    handlers[vector] = 0;
    interrupt_names[vector] = 0;
}

extern void *exception_vectors;

void init_interrupts(kernel_heaps kh)
{
    heap general = heap_general(kh);
    handlers = allocate_zero(general, MAX_INTERRUPT_VECTORS * sizeof(thunk));
    assert(handlers != INVALID_ADDRESS);
    interrupt_vector_heap = create_id_heap(general, general, INTERRUPT_VECTOR_START,
                                           MAX_INTERRUPT_VECTORS - INTERRUPT_VECTOR_START, 1);
    assert(interrupt_vector_heap != INVALID_ADDRESS);

    /* set exception vector table base */
    register u64 v = u64_from_pointer(&exception_vectors);
    asm volatile("dsb sy; msr vbar_el1, %0" :: "r"(v));

    /* initialize interrupt controller */
    init_gic();
}
