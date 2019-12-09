#include <runtime.h>
#include <x86_64.h>
#include <kvm_platform.h>
#include <page.h>
#include <region.h>
#include <apic.h>

#define INTERRUPT_VECTOR_START 32 /* end of exceptions; defined by architecture */
static char *interrupts[] = {
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

static inline char *interrupt_name(u64 s)
{
    return s < INTERRUPT_VECTOR_START ? interrupts[s] : "";
}

static char* textoreg[] = {
    "  rax", //0
    "  rbx", //1
    "  rcx", //2
    "  rdx", //3
    "  rsi", //4
    "  rdi", //5
    "  rbp", //6
    "  rsp", //7
    "   r8",  //8
    "   r9",  //9
    "  r10", //10
    "  r11", //11
    "  r12", //12
    "  r13", //13
    "  r14", //14
    "  r15", //15
    "  rip", //16
    "flags", //17
    "   ss",  //18
    "   cs",  //19
    "   ds",  //20
    "   es",  //21
    "   fs",  //22
    "   gs",  //23
    "vector", // 24
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

static void write_idt(int interrupt, u64 offset, u64 ist)
{
    u64 selector = 0x08;
    u64 type_attr = 0x8e;
    u64 *target = idt_from_interrupt(interrupt);

    target[0] = ((selector << 16) | (offset & MASK(16)) | /* 31 - 0 */
                 (((offset >> 16) & MASK(16)) << 48) | (type_attr << 40) | (ist << 32)); /* 63 - 32 */
    target[1] = offset >> 32;   /*  95 - 64 */
}

static thunk *handlers;
context running_frame;

char * find_elf_sym(u64 a, u64 *offset, u64 *len);

void print_u64_with_sym(u64 a)
{
    char * name;
    u64 offset, len;

    print_u64(a);

    name = find_elf_sym(a, &offset, &len);
    if (name) {
	console("\t(");
	console(name);
	console(" + ");
	print_u64(offset);
        console("/");
        print_u64(len);
	console(")");
    }
}

extern void *text_start;
extern void *text_end;
void __print_stack_with_rbp(u64 *rbp)
{
    for (unsigned int frame = 0; frame < 32; frame ++) {
        if ((u64) rbp < 4096ULL)
            break;

        if (!validate_virtual(rbp, sizeof(u64)) ||
            !validate_virtual(rbp + 1, sizeof(u64)))
            break;

        u64 rip = rbp[1];
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
    console(interrupt_name(v));
    console("\n");
    console("interrupt: ");
    print_u64(v);
    console("\n");
    console("frame: ");
    print_u64_with_sym(u64_from_pointer(f));
    console("\n");    

    if (v == 13 || v == 14) {
	console("error code: ");
	print_u64(f[FRAME_ERROR_CODE]);
	console("\n");
    }

    // page fault
    if (v == 14)  {
        console("address: ");
        print_u64_with_sym(f[FRAME_CR2]);
        console("\n");
    }
    
    for (int j = 0; j < 24; j++) {
        console(register_name(j));
        console(": ");
        print_u64_with_sym(f[j]);
        console("\n");        
    }
}

context miscframe;              /* for context save on interrupt */
context intframe;               /* for context save on exception within interrupt */
context bhframe;

void kernel_sleep()
{
    running_frame = miscframe;
    enable_interrupts();
    __asm__("hlt");
    disable_interrupts();
}

void install_fallback_fault_handler(fault_handler h)
{
    assert(miscframe);
    assert(intframe);
    miscframe[FRAME_FAULT_HANDLER] = u64_from_pointer(h);
    intframe[FRAME_FAULT_HANDLER] = u64_from_pointer(h);
    bhframe[FRAME_FAULT_HANDLER] = u64_from_pointer(h);
}

void * bh_stack_top;

extern u32 n_interrupt_vectors;
extern u32 interrupt_vector_size;
extern void * interrupt_vectors;

NOTRACE
void common_handler()
{
    int i = running_frame[FRAME_VECTOR];
    boolean in_bh = running_frame == bhframe;
    boolean in_inthandler = running_frame == intframe;
    boolean in_usermode = (!in_inthandler && !in_bh) &&
        (running_frame[FRAME_SS] == 0 || running_frame[FRAME_SS] == 0x13);

    if (in_inthandler) {
        console("exception during interrupt handling\n");
    }

    if ((i < n_interrupt_vectors) && handlers[i]) {
        frame_push(intframe);   /* catch any spurious exceptions during int handling */
        apply(handlers[i]);
        lapic_eoi();
        frame_pop();
    } else {
        fault_handler f = pointer_from_u64(running_frame[FRAME_FAULT_HANDLER]);

        if (f == 0) {
            rprintf ("no fault handler\n");
            print_frame(running_frame);
            print_stack(running_frame);
            vm_exit(VM_EXIT_FAULT);
        }
        if (i < 25) {
            running_frame = apply(f, running_frame);
        }
    }

    /* if we crossed privilege levels, reprogram SS and CS */
    if (in_usermode) {
        running_frame[FRAME_SS] = 0x23;
        running_frame[FRAME_CS] = 0x1b;
    }

    /* if the interrupt didn't occur during bottom half or int handler
       execution, switch context to bottom half processing */
    if (!in_bh && !in_inthandler) {
        frame_push(bhframe);
        switch_stack(bh_stack_top, process_bhqueue);
    }
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

void register_interrupt(int vector, thunk t)
{
    if (handlers[vector])
        halt("%s: handler for vector %d already registered (%p)\n",
             __func__, vector, handlers[vector]);
    handlers[vector] = t;
}

void unregister_interrupt(int vector)
{
    if (!handlers[vector])
        halt("%s: no handler registered for vector %d\n", __func__, vector);
    handlers[vector] = 0;
}

#define FAULT_STACK_PAGES       8
#define SYSCALL_STACK_PAGES     8

extern volatile void * TSS;
static inline void write_tss_u64(int offset, u64 val)
{
    u64 * vec = (u64 *)(u64_from_pointer(&TSS) + offset);
    *vec = val;
}

static void set_ist(int i, u64 sp)
{
    assert(i > 0 && i <= 7);
    write_tss_u64(0x24 + (i - 1) * 8, sp);
}

context allocate_frame(heap h)
{
    context f = allocate_zero(h, FRAME_MAX * sizeof(u64));
    assert(f != INVALID_ADDRESS);
    return f;
}

void * allocate_stack(heap pages, int npages)
{
    void * base = allocate_zero(pages, pages->pagesize * npages);
    if (base == INVALID_ADDRESS)
        return base;
    return base + pages->pagesize * npages - STACK_ALIGNMENT;
}

void * syscall_stack_top;

#define IST_INTERRUPT 1         /* for all interrupts */
#define IST_PAGEFAULT 2         /* page fault specific */

void start_interrupts(kernel_heaps kh)
{
    heap general = heap_general(kh);
    heap pages = heap_pages(kh);

    /* Exception handlers */
    handlers = allocate_zero(general, n_interrupt_vectors * sizeof(thunk));
    assert(handlers != INVALID_ADDRESS);

    /* Alternate frame storage */
    miscframe = allocate_frame(general);
    intframe = allocate_frame(general);
    bhframe = allocate_frame(general);

    /* Page fault alternate stack */
    void * fault_stack_top = allocate_stack(pages, FAULT_STACK_PAGES);
    assert(fault_stack_top != INVALID_ADDRESS);
    set_ist(IST_PAGEFAULT, u64_from_pointer(fault_stack_top));

    /* Interrupt handlers run on their own stack. */
    void * int_stack_top = allocate_stack(pages, INT_STACK_PAGES);
    assert(int_stack_top != INVALID_ADDRESS);
    set_ist(IST_INTERRUPT, u64_from_pointer(int_stack_top));

    /* Syscall stack */
    syscall_stack_top = allocate_stack(pages, SYSCALL_STACK_PAGES);
    assert(syscall_stack_top != INVALID_ADDRESS);

    /* Bottom half stack */
    bh_stack_top = allocate_stack(pages, BH_STACK_PAGES);
    assert(bh_stack_top != INVALID_ADDRESS);

    interrupt_vector_heap = create_id_heap(general, INTERRUPT_VECTOR_START,
                                           n_interrupt_vectors - INTERRUPT_VECTOR_START, 1);
    assert(interrupt_vector_heap != INVALID_ADDRESS);

    /* IDT setup */
    idt = allocate(pages, pages->pagesize);

    u64 vector_base = u64_from_pointer(&interrupt_vectors);
    for (int i = 0; i < INTERRUPT_VECTOR_START; i++)
        write_idt(i, vector_base + i * interrupt_vector_size, i == 0xe ? IST_PAGEFAULT : 0);
    
    for (int i = INTERRUPT_VECTOR_START; i < n_interrupt_vectors; i++)
        write_idt(i, vector_base + i * interrupt_vector_size, IST_INTERRUPT);

    void *idt_desc = idt_from_interrupt(n_interrupt_vectors); /* placed after last entry */
    *(u16*)idt_desc = 2 * sizeof(u64) * n_interrupt_vectors - 1;
    *(u64*)(idt_desc + sizeof(u16)) = u64_from_pointer(idt);
    asm("lidt %0": : "m"(*(u64*)idt_desc));

    /* APIC initialization */
    init_apic(kh);
}
