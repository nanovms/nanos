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

#if 0
NOTRACE
void common_handler()
{
    cpuinfo ci = current_cpu();
    context f = ci->running_frame;
    int i = f[FRAME_VECTOR];

    if (i >= n_interrupt_vectors) {
        console("\nexception for invalid interrupt vector\n");
        goto exit_fault;
    }
    return;
  exit_fault:
    halt("terminate on common handler fault\n");
}
#endif

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
    print_u64(f[FRAME_SPSR_ESR] & MASK(32));
    console("\n       esr: ");
    u32 esr = f[FRAME_SPSR_ESR] >> 32;
    print_u64(esr);

    int esr_ec = field_from_u64(esr, ESR_EC);
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
        /* ... */
        break;
    case ESR_EC_PC_ALIGN_FAULT:
        console(" pc alignment");
        break;
    case ESR_EC_DATA_ABRT_LEL:
    case ESR_EC_DATA_ABRT:
        console(" data abort in ");
        console(esr_ec == ESR_EC_DATA_ABRT_LEL ? "el0" : "el1");

        u32 iss = field_from_u64(esr, ESR_ISS);
        console(iss & ESR_ISS_DATA_ABRT_WnR ? " write" : " read");
        if (iss & ESR_ISS_DATA_ABRT_CM)
            console(" cache");

        if ((iss & ESR_ISS_DATA_ABRT_FnV) == 0) {
            register u64 far;
            asm("mrs %0, FAR_EL1" : "=r"(far));
            console("\n       far: ");
            print_u64_with_sym(far);
        }
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

NOTRACE
void synchronous_handler(void)
{
    early_debug("\ncaught exception:\n\n");
    cpuinfo ci = current_cpu();
    context f = ci->running_frame;

    print_frame(f);
    print_stack(f);
    while(1);
}

NOTRACE
void irq_handler(void)
{
    rprintf("%s\n", __func__);
}

NOTRACE
void serror_handler(void)
{
    rprintf("%s\n", __func__);
}

NOTRACE
void invalid_handler(void)
{
    rprintf("%s\n", __func__);
}

static heap interrupt_vector_heap;

u64 allocate_interrupt(void)
{
    return allocate_u64(interrupt_vector_heap, 1);
}

void deallocate_interrupt(u64 irq)
{
    deallocate_u64(interrupt_vector_heap, irq, 1);
}

void register_interrupt(int vector, thunk t, const char *name)
{
    if (handlers[vector])
        halt("%s: handler for vector %d already registered (%p)\n",
             __func__, vector, handlers[vector]);
    handlers[vector] = t;
    interrupt_names[vector] = name;

    // XXX make interface?
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
//    cpuinfo ci = current_cpu();

    handlers = allocate_zero(general, MAX_INTERRUPT_VECTORS * sizeof(thunk));
    assert(handlers != INVALID_ADDRESS);
    interrupt_vector_heap = (heap)create_id_heap(general, general, INTERRUPT_VECTOR_START,
                                                 MAX_INTERRUPT_VECTORS - INTERRUPT_VECTOR_START, 1);
    assert(interrupt_vector_heap != INVALID_ADDRESS);

    /* set exception vector table base */
    register u64 v = u64_from_pointer(&exception_vectors);
    asm volatile("dsb sy; msr vbar_el1, %0" :: "r"(v));

    /* initialize interrupt controller */
    rprintf("initialize gic\n");
    init_gic();
    rprintf("done\n");
}
