#include <kernel.h>
#include <kvm_platform.h>
#include <page.h>
#include <region.h>
#include <apic.h>

//#define INT_DEBUG
#ifdef INT_DEBUG
#define int_debug(x, ...) do {log_printf("  INT", x, ##__VA_ARGS__);} while(0)
#else
#define int_debug(x, ...)
#endif

#define INTERRUPT_VECTOR_START 32 /* end of exceptions; defined by architecture */
#define MAX_INTERRUPT_VECTORS  256 /* as defined by architecture; we may have less */

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

static u64 *idt;

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

    target[0] = ((selector << 16) | (offset & MASK(16)) | /* 31 - 0 */
                 (((offset >> 16) & MASK(16)) << 48) | (type_attr << 40) | (ist << 32)); /* 63 - 32 */
    target[1] = offset >> 32;   /*  95 - 64 */
}

static thunk *handlers;
u32 spurious_int_vector;

extern void *text_start;
extern void *text_end;
void __print_stack_with_rbp(u64 *rbp)
{
    for (unsigned int frame = 0; frame < 16; frame ++) {
        if ((u64) rbp < 4096ULL)
            break;

        if (!validate_virtual(rbp, sizeof(u64)) ||
            !validate_virtual(rbp + 1, sizeof(u64)))
            break;

        u64 rip = rbp[1];
        if (rip == 0)
            break;
        rbp = (u64 *) rbp[0];
        print_u64_with_sym(rip);
        console("\n");
    }
}

void print_stack_from_here(void)
{
    u64 rbp;
    asm("movq %%rbp, %0" : "=r" (rbp));
    __print_stack_with_rbp((u64 *)rbp);
}

#define STACK_TRACE_DEPTH       24
void print_stack(context c)
{
    console("\nframe trace:\n");
    __print_stack_with_rbp(pointer_from_u64(c[FRAME_RBP]));

    console("\nstack trace:\n");
    u64 *x = pointer_from_u64(c[FRAME_RSP]);
    for (u64 i = 0; i < STACK_TRACE_DEPTH; i++) {
        print_u64_with_sym(*(x+i));
        console("\n");
    }
    console("\n");
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
    console("\n");    

    if (v == 13 || v == 14) {
	console("error code: ");
	print_u64(f[FRAME_ERROR_CODE]);
	console("\n");
    }

    // page fault
    if (v == 14)  {
        console("   address: ");
        print_u64_with_sym(f[FRAME_CR2]);
        console("\n");
    }
    
    console("\n");
    for (int j = 0; j < 24; j++) {
        console(register_name(j));
        console(": ");
        print_u64_with_sym(f[j]);
        console("\n");        
    }
}

void install_fallback_fault_handler(fault_handler h)
{
    // XXX reconstruct
    for (int i = 0; i < MAX_CPUS; i++) {
        cpuinfo_from_id(i)->kernel_context->frame[FRAME_FAULT_HANDLER] = u64_from_pointer(h);
    }
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
    context f = ci->running_frame;
    int i = f[FRAME_VECTOR];

    if (i >= n_interrupt_vectors) {
        console("\nexception for invalid interrupt vector\n");
        goto exit_fault;
    }

    // if we were idle, we are no longer
    atomic_clear_bit(&idle_cpu_mask, ci->id);

    int_debug("[%2d] # %d (%s), state %s, frame %p, rip 0x%lx, cr2 0x%lx\n",
              ci->id, i, interrupt_names[i], state_strings[ci->state],
              f, f[FRAME_RIP], f[FRAME_CR2]);

    /* enqueue an interrupted user thread, unless the page fault handler should take care of it */
    // what about bh?
    if (ci->state == cpu_user && i >= INTERRUPT_VECTOR_START) {
        int_debug("int sched %F\n", f[FRAME_RUN]);
        schedule_frame(f);        // racy enqueue from interrupt level? we weren't interrupting the kernel...
    }

    if (i == spurious_int_vector)
        frame_return(f);        /* direct return, no EOI */

    /* Unless there's some reason to handle a page fault in interrupt
       mode, this should always be terminal.

       This really should include kernel mode, too, but we're for the
       time being allowing the kernel to take page faults...which
       really isn't sustainable unless we want fine-grained locking
       around the vmaps and page tables. Validating user buffers will
       get rid of this requirement (and allow us to add the check for
       cpu_kernel here too).
    */
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

    /* invoke handler if available, else general fault handler */
    if (handlers[i]) {
        ci->state = cpu_interrupt;
        apply(handlers[i]);
        if (i >= INTERRUPT_VECTOR_START)
            lapic_eoi();
    } else {
        /* fault handlers likely act on cpu state, so don't change it */
        fault_handler fh = pointer_from_u64(f[FRAME_FAULT_HANDLER]);
        if (fh) {
            context retframe = apply(fh, f);
            if (retframe)
                frame_return(retframe);
        } else {
            console("\nno fault handler for frame ");
            print_u64(u64_from_pointer(f));
            /* make a half attempt to identify it short of asking unix */
            /* we should just have a name here */
            if (is_current_kernel_context(f))
                console(" (kernel frame)");
            console("\n");
            goto exit_fault;
        }
    }
    if (is_current_kernel_context(f))
        f[FRAME_FULL] = false;      /* no longer saving frame for anything */
    runloop();
  exit_fault:
    console("cpu ");
    print_u64(ci->id);
    console(", state ");
    console(state_strings[ci->state]);
    console(", vector ");
    print_u64(i);
    console("\n");
    print_frame(f);
    print_stack(f);
    apic_ipi(TARGET_EXCLUSIVE_BROADCAST, 0, shutdown_vector);
    vm_exit(VM_EXIT_FAULT);
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
}

void unregister_interrupt(int vector)
{
    if (!handlers[vector])
        halt("%s: no handler registered for vector %d\n", __func__, vector);
    handlers[vector] = 0;
    interrupt_names[vector] = 0;
}

#define TSS_SIZE                0x68

extern volatile void * TSS;
static inline void write_tss_u64(int cpu, int offset, u64 val)
{
    u64 * vec = (u64 *)(u64_from_pointer(&TSS) + (TSS_SIZE * cpu) + offset);
    *vec = val;
}

void set_ist(int cpu, int i, u64 sp)
{
    assert(i > 0 && i <= 7);
    write_tss_u64(cpu, 0x24 + (i - 1) * 8, sp);
}

void init_interrupts(kernel_heaps kh)
{
    heap general = heap_general(kh);
    cpuinfo ci = current_cpu();

    /* Exception handlers */
    handlers = allocate_zero(general, n_interrupt_vectors * sizeof(thunk));
    assert(handlers != INVALID_ADDRESS);
    interrupt_vector_heap = (heap)create_id_heap(general, general, INTERRUPT_VECTOR_START,
                                                 n_interrupt_vectors - INTERRUPT_VECTOR_START, 1);
    assert(interrupt_vector_heap != INVALID_ADDRESS);

    /* Separate stack to keep exceptions in interrupt handlers from
       trashing the interrupt stack */
    set_ist(0, IST_EXCEPTION, u64_from_pointer(ci->exception_stack));

    /* External interrupts (> 31) */
    set_ist(0, IST_INTERRUPT, u64_from_pointer(ci->int_stack));

    /* IDT setup */
    idt = allocate(heap_backed(kh), heap_backed(kh)->pagesize);

    /* Rely on ISTs in lieu of TSS stack switch. */
    u64 vector_base = u64_from_pointer(&interrupt_vectors);
    for (int i = 0; i < INTERRUPT_VECTOR_START; i++)
        write_idt(i, vector_base + i * interrupt_vector_size, IST_EXCEPTION);
    
    for (int i = INTERRUPT_VECTOR_START; i < n_interrupt_vectors; i++)
        write_idt(i, vector_base + i * interrupt_vector_size, IST_INTERRUPT);

    void *idt_desc = idt_from_interrupt(n_interrupt_vectors); /* placed after last entry */
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
    void *idt_desc = idt_from_interrupt(n_interrupt_vectors);
    *(u16*)idt_desc = 0;
    asm volatile("lidt %0; int3": : "m"(*(u64*)idt_desc));
    while (1);
}
