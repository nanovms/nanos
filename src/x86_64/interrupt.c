#include <kernel.h>
#include <kvm_platform.h>
#include <region.h>
#include <apic.h>
#include <symtab.h>
#include <drivers/acpi.h>

//#define INT_DEBUG
#ifdef INT_DEBUG
#define int_debug(x, ...) do {tprintf(sym(int), 0, x, ##__VA_ARGS__);} while(0)
#else
#define int_debug(x, ...)
#endif

#define INTERRUPT_VECTOR_START 32 /* end of exceptions; defined by architecture */
#define MAX_INTERRUPT_VECTORS  256 /* as defined by architecture; we may have less */

typedef struct inthandler {
    struct list l;
    thunk t;
    const char *name;
} *inthandler;

static const char *interrupt_names[MAX_INTERRUPT_VECTORS] = {
    "Divide by 0",
    "Reserved",
    "NMI Interrupt",
    "Breakpoint (INT3)",
    "Overflow (INTO)",
    "Bounds range exceeded (BOUND)",
    "Invalid opcode (UD2)",
    "Device not available (WAIT/FWAIT)",
    "Double fault",
    "Coprocessor segment overrun",
    "Invalid TSS",
    "Segment not present",
    "Stack-segment fault",
    "General protection fault",
    "Page fault",
    "Reserved",
    "x87 FPU error",
    "Alignment check",
    "Machine check",
    "SIMD Floating-Point Exception",
    "reserved 14",
    "reserved 15",
    "reserved 16",
    "reserved 17",
    "reserved 18",
    "reserved 19",
    "reserved 1a",
    "reserved 1b",
    "reserved 1c",
    "reserved 1d",
    "reserved 1e",
    "reserved 1f"};

static char* textoreg[] = {
    "   rax", //0
    "   rbx", //1
    "   rcx", //2
    "   rdx", //3
    "   rsi", //4
    "   rdi", //5
    "   rbp", //6
    "   rsp", //7
    "    r8", //8
    "    r9", //9
    "   r10", //10
    "   r11", //11
    "   r12", //12
    "   r13", //13
    "   r14", //14
    "   r15", //15
    "   rip", //16
    "rflags", //17
    "    ss", //18
    "    cs", //19
    "    ds", //20
    "    es", //21
    "fsbase", //22
    "gsbase", //23
    "vector", //24
};

static inline char *register_name(u64 s)
{
    return textoreg[s];
}

BSS_RO_AFTER_INIT static u64 *idt;

static inline void *idt_from_interrupt(int interrupt)
{
    return pointer_from_u64((u64_from_pointer(idt) + 2 * sizeof(u64) * interrupt));
}

/* XXX Sigh...the noinline is a workaround for an issue where a clang
   build on macos is somehow leading to incorrect IDT entries. This
   needs more investigation.

   https://github.com/nanovms/nanos/issues/1060
*/
static void __attribute__((noinline)) write_idt(int interrupt, u64 offset, u64 ist)
{
    u64 selector = 0x08;
    u64 type_attr = 0x8e;
    u64 *target = idt_from_interrupt(interrupt);

    if (interrupt == 3)
        type_attr = 0xee; /* allow int3 from cpl 3 */
    target[0] = ((selector << 16) | (offset & MASK(16)) | /* 31 - 0 */
                 (((offset >> 16) & MASK(16)) << 48) | (type_attr << 40) | (ist << 32)); /* 63 - 32 */
    target[1] = offset >> 32;   /*  95 - 64 */
}

BSS_RO_AFTER_INIT static thunk *handlers;
BSS_RO_AFTER_INIT u32 spurious_int_vector;

extern void *text_start;
extern void *text_end;

static void print_stack(context_frame c)
{
    rputs("\nframe trace:\n");
    print_frame_trace(pointer_from_u64(c[FRAME_RBP]));

    rputs("\nstack trace:\n");
    u64 *sp = pointer_from_u64(c[FRAME_RSP]);
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
    u64 v = f[FRAME_VECTOR];
    rputs("lastvector: ");
    print_u64(v);
    if (v < INTERRUPT_VECTOR_START) {
        rputs(" (");
        rputs((char *)interrupt_names[v]);
        rputs(")");
    }
    rputs("\n     frame: ");
    print_u64_with_sym(u64_from_pointer(f));
    if (ctx->type >= CONTEXT_TYPE_UNDEFINED && ctx->type < CONTEXT_TYPE_MAX) {
        rputs("\n      type: ");
        rputs(context_type_strings[ctx->type]);
    }
    rputs("\nactive_cpu: ");
    print_u64(ctx->active_cpu);
    rputs("\n stack top: ");
    print_u64(f[FRAME_STACK_TOP]);

    if (v == 13 || v == 14) {
	rputs("\nerror code: ");
	print_u64(f[FRAME_ERROR_CODE]);
    }

    // page fault
    if (v == 14)  {
        rputs("\n   address: ");
        print_u64_with_sym(f[FRAME_CR2]);
    }

    rputs("\n\n");
    for (int j = 0; j < 24; j++) {
        rputs(register_name(j));
        rputs(": ");
        print_u64_with_sym(f[j]);
        rputs("\n");
    }
    print_stack(f);
}

extern u32 n_interrupt_vectors;
extern u32 interrupt_vector_size;
extern void * interrupt_vectors;

NOTRACE
void common_handler()
{
    /* XXX yes, this will be a problem on a machine check or other
       fault while in an int handler...need to fix in interrupt_common */
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    context_frame f = ctx->frame;
    int i = f[FRAME_VECTOR];

    if (i >= n_interrupt_vectors) {
        console("\nexception for invalid interrupt vector\n");
        goto exit_fault;
    }

    // if we were idle, we are no longer
    bitmap_set_atomic(idle_cpu_mask, ci->id, 0);

    int_debug("[%02d] # %d (%s), state %s, frame %p, rip 0x%lx, cr2 0x%lx\n",
              ci->id, i, interrupt_names[i], state_strings[ci->state],
              f, f[FRAME_RIP], f[FRAME_CR2]);

    int saved_state = ci->state;

    if (i == spurious_int_vector)
        frame_return(f);        /* direct return, no EOI */

    if (ci->state == cpu_interrupt) {
        console("\nexception during interrupt handling\n");
        goto exit_fault;
    }

    if (f[FRAME_FULL]) {
        console("\nframe ");
        print_u64(u64_from_pointer(f));
        console(" already full\n");
        goto exit_fault;
    }
    f[FRAME_FULL] = true;
    context_reserve_refcount(ctx);

    /* invoke handler if available, else general fault handler */
    if (handlers[i]) {
        ci->state = cpu_interrupt;
        apply(handlers[i]);
        if (i >= INTERRUPT_VECTOR_START)
            lapic_eoi();

        /* enqueue interrupted user thread */
        if (is_thread_context(ctx) && !(shutting_down & SHUTDOWN_ONGOING)) {
            int_debug("int sched thread %p\n", ctx);
            context_schedule_return(ctx);
        }
    } else {
        fault_handler fh = ctx->fault_handler;
        if (fh) {
            context retctx = apply(fh, ctx);
            if (retctx) {
                context_release_refcount(retctx);
                frame_return(retctx->frame);
            }
            if (is_syscall_context(ctx))
                /* This indicates an unhandled fault on a user page from
                   within a syscall. We need to abandon the syscall at this
                   point and let the thread run so it may receive the
                   appropriate signal. The frame is left full so that future
                   context dumps will report the actual processor state when
                   the exception occurred. */
                runloop();
            assert(!is_kernel_context(ctx));
        } else {
            console("\nno fault handler\n");
            goto exit_fault;
        }
    }

    /* For now we will frame return directly to syscall and kernel
       contexts. We could explore inserting bh processing prior to the return
       (the bh handlers are supposed to be reentrant - however I suspect some
       non-irq-bh tasks migrated over from runqueue during the kernel lock
       removal transition and need to be moved back), but without a full trip
       through runloop it's not clear how beneficial this would be. Or the
       context could be optionally scheduled if some condition is met,
       e.g. some limit of consecutive frame returns without a call to runloop
       is reached. */

    if (is_kernel_context(ctx) || is_syscall_context(ctx)) {
        context_release_refcount(ctx);
        if (saved_state != cpu_idle) {
            ci->state = cpu_kernel;
            frame_return(f);
        }
        f[FRAME_FULL] = false;      /* no longer saving frame for anything */
    }
    runloop();
  exit_fault:
    console("cpu ");
    print_u64(ci->id);
    console(", state ");
    console(state_strings[ci->state]);
    console(", vector ");
    print_u64(i);
    console("\n");
    dump_context(ctx);
    vm_exit(VM_EXIT_FAULT);
}

BSS_RO_AFTER_INIT static id_heap interrupt_vector_heap;
BSS_RO_AFTER_INIT static heap int_general;

u64 allocate_interrupt(void)
{
    u64 res = allocate_u64((heap)interrupt_vector_heap, 1);
    assert(res != INVALID_PHYSICAL);
    return res;
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
    if (handlers[vector])
        halt("%s: handler for vector %d already registered (%p)\n",
             __func__, vector, handlers[vector]);
    handlers[vector] = t;
    interrupt_names[vector] = name;
}

void unregister_interrupt(int vector)
{
    if (!handlers[vector])
        halt("%s: no handler registered for vector %d\n", __func__, vector);
    handlers[vector] = 0;
    interrupt_names[vector] = 0;
}

closure_function(1, 0, void, shirq_handler,
                 list, handlers)
{
    list_foreach(bound(handlers), l) {
        inthandler h = struct_from_list(l, inthandler, l);
        int_debug("   invoking handler %s (%F)\n", h->name, h->t);
        apply(h->t);
    }
}

u64 allocate_shirq(void)
{
    u64 v = allocate_interrupt();
    list handlers = allocate(int_general, sizeof(struct list));
    assert(handlers != INVALID_ADDRESS);
    list_init(handlers);
    thunk t = closure(int_general, shirq_handler, handlers);
    assert(t != INVALID_ADDRESS);
    register_interrupt(v, t, "shirq");
    return v;
}

void register_shirq(int v, thunk t, const char *name)
{
    if (!handlers[v])
        halt("%s: vector %d not allocated\n", __func__, v);
    list shirq_handlers = closure_member(shirq_handler, handlers[v], handlers);
    inthandler handler = allocate(int_general, sizeof(struct inthandler));
    assert(handler != INVALID_ADDRESS);
    handler->t = t;
    handler->name = name;
    list_push_back(shirq_handlers, &handler->l);
}

static inline void write_tss_u64(struct cpuinfo_machine *cpu, int offset, u64 val)
{
    u64 *vec = (u64 *)(u64_from_pointer(&cpu->tss) + offset);
    *vec = val;
}

void set_ist(struct cpuinfo_machine *cpu, int i, u64 sp)
{
    assert(i > 0 && i <= 7);
    write_tss_u64(cpu, 0x24 + (i - 1) * 8, sp);
}

void init_interrupts(kernel_heaps kh)
{
    heap general = heap_general(kh);

    /* Read ACPI tables for MADT access */
    init_acpi_tables(kh);

    /* Exception handlers */
    handlers = allocate_zero(general, n_interrupt_vectors * sizeof(thunk));
    assert(handlers != INVALID_ADDRESS);
    interrupt_vector_heap = create_id_heap(general, heap_locked(kh), INTERRUPT_VECTOR_START,
                                           n_interrupt_vectors - INTERRUPT_VECTOR_START, 1, true);
    assert(interrupt_vector_heap != INVALID_ADDRESS);

    int_general = general;

    /* IDT setup */
    heap backed = (heap)heap_page_backed(kh);
    idt = allocate(backed, backed->pagesize);
    assert(idt != INVALID_ADDRESS);

    /* Rely on ISTs in lieu of TSS stack switch. */
    u64 vector_base = u64_from_pointer(&interrupt_vectors);
    for (int i = 0; i < INTERRUPT_VECTOR_START; i++)
        write_idt(i, vector_base + i * interrupt_vector_size, IST_EXCEPTION);

    for (int i = INTERRUPT_VECTOR_START; i < n_interrupt_vectors; i++)
        write_idt(i, vector_base + i * interrupt_vector_size, IST_INTERRUPT);

    u8 idt_desc[10] = {0};
    *(u16*)idt_desc = 2 * sizeof(u64) * n_interrupt_vectors - 1;
    *(u64*)(idt_desc + sizeof(u16)) = u64_from_pointer(idt);
    asm volatile("lidt %0": : "m"(*(u64*)idt_desc));

    u64 v = allocate_interrupt();
    assert(v != INVALID_PHYSICAL);
    spurious_int_vector = v;

    /* APIC initialization */
    init_apic(kh);
}

void triple_fault(void)
{
    disable_interrupts();
    /* zero table limit to induce triple fault */
    u8 idt_desc[10] = {0};
    *(u64*)(idt_desc + sizeof(u16)) = u64_from_pointer(idt);
    asm volatile("lidt %0; int3": : "m"(*(u64*)idt_desc));
    while (1);
}

void __attribute__((noreturn)) __stack_chk_fail(void)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    rprintf("stack check failed on cpu %d\n", ci->id);
    dump_context(ctx);
    vm_exit(VM_EXIT_FAULT);
}
