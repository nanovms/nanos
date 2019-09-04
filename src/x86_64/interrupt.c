#include <runtime.h>
#include <x86_64.h>
#include <kvm_platform.h>
#include <page.h>
#include <region.h>

// coordinate with crt0
extern u32 interrupt_size;
extern void *interrupt0, *interrupt1;
static u64 *idt;

#define APIC_APICID 0x20
#define APIC_APICVER 0x30
#define APIC_TASKPRIOR 0x80
#define APIC_EOI 0x0B0
#define APIC_LDR 0x0D0
#define APIC_DFR 0x0E0
#define APIC_SPURIOUS 0x0F0
#define APIC_ESR 0x280
#define APIC_ICRL 0x300
#define APIC_ICRH 0x310
#define APIC_LVT_TMR 0x320
#define APIC_LVT_PERF 0x340
#define APIC_LVT_LINT0 0x350
#define APIC_LVT_LINT1 0x360
#define APIC_LVT_ERR 0x370
#define APIC_TMRINITCNT 0x380
#define APIC_TMRCURRCNT 0x390
#define APIC_TMRDIV 0x3E0
#define APIC_LAST 0x38F
#define APIC_DISABLE 0x10000
#define APIC_SW_ENABLE 0x100
#define APIC_CPUFOCUS 0x200
#define APIC_NMI 4<<8
#define TMR_PERIODIC 0x20000
#define TMR_TSC_DEADLINE 0x40000
#define TMR_BASEDIV (1<< 20)
    
#define APIC_LVT_INTMASK 0x00010000

// tuplify these mapping
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


// we build the actual idt dynamically because the address
// is scattered all over the 16 bytes, and it looks pretty
// difficult, but maybe not impossible, to construct a relocation
// to fill it in (by aligning the handler base, assigning
// it a section, etc)


char *interrupt_name(u64 s)
{
    return s < 32 ? interrupts[s] : "";
}


void write_idt(u64 *idt, int interrupt, void *hv, u64 ist)
{
    // huh, idt entries are virtual 
    u64 h = u64_from_pointer(hv); 
    u64 selector = 0x08;
    u64 type_attr = 0x8e;
        
    u64 *target = (void *)(u64)(idt + 2*interrupt);
        
    target[0] = (h & MASK(16)) | (selector << 16) | (ist << 32) | (type_attr << 40)|
        (((h>>16) & MASK(16))<<48);
    target[1] = h >> 32; // rest must be zero
}

// tuplify and synthesize
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

char *register_name(u64 s)
{
    return(textoreg[s]);
}

static thunk *handlers;
context running_frame;

void *apic_base = (void *)0xfee00000;

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

static inline void apic_write(int reg, u32 val)
{
    *(u32 *)(apic_base + reg) = val;
}

static inline u32 apic_read(int reg)
{
    return *(u32 *)(apic_base + reg);
}

static inline void apic_set(int reg, u32 v)
{
    apic_write(reg, apic_read(reg) | v);
}

static inline void apic_clear(int reg, u32 v)
{
    apic_write(reg, apic_read(reg) & ~v);
}

void lapic_eoi()
{
    write_barrier();
    apic_write(APIC_EOI, 0);
    write_barrier();
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

    if ((i < interrupt_size) && handlers[i]) {
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

heap interrupt_vectors;

// actually allocate the virtual  - put in the tree
static void enable_lapic(heap pages)
{
    // there is an msr that moves the physical
    u64 lapic = 0xfee00000;
    
    map(u64_from_pointer(apic_base), lapic, PAGESIZE, PAGE_DEV_FLAGS, pages);
    
    // turn on the svr, then enable three lines
    apic_write(APIC_SPURIOUS, *(unsigned int *)(apic_base + APIC_SPURIOUS) | APIC_SW_ENABLE);
    apic_write(APIC_LVT_LINT0, APIC_DISABLE);
    apic_write(APIC_LVT_LINT1, APIC_DISABLE);
    apic_write(APIC_LVT_ERR, allocate_u64(interrupt_vectors, 1));
}


void register_interrupt(int vector, thunk t)
{
    handlers[vector] = t;
}

static u32 apic_timer_cal_sec;

/* ugh, don't want to slow down the boot this much...see if we can
   trim this some more */
#define CALIBRATE_DURATION_MS 10
void calibrate_lapic_timer()
{
    apic_write(APIC_TMRINITCNT, -1u);
    kern_sleep(milliseconds(10));
    u32 delta = -1u - apic_read(APIC_TMRCURRCNT);
    apic_set(APIC_LVT_TMR, APIC_LVT_INTMASK);
    apic_timer_cal_sec = (1000 / CALIBRATE_DURATION_MS) * delta;
}

void lapic_runloop_timer(timestamp interval)
{
    /* interval * apic_timer_cal_sec / second */
    u32 cnt = (((u128)interval) * apic_timer_cal_sec) >> 32;
    apic_clear(APIC_LVT_TMR, APIC_LVT_INTMASK);
    apic_write(APIC_TMRINITCNT, cnt);
}

static CLOSURE_0_0(int_ignore, void);
static void int_ignore(void) {}

void configure_lapic_timer(heap h)
{
    apic_write(APIC_TMRDIV, 3 /* 16 */);
    int v = allocate_u64(interrupt_vectors, 1);
    apic_write(APIC_LVT_TMR, v); /* one shot */
    register_interrupt(v, closure(h, int_ignore));
    calibrate_lapic_timer();
}

extern u32 interrupt_size;

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
    // these are simple enough it would be better to just
    // synthesize them
    int delta = (u64)&interrupt1 - (u64)&interrupt0;
    void *start = &interrupt0;
    heap general = heap_general(kh);
    heap pages = heap_pages(kh);

    /* exception handlers */
    handlers = allocate_zero(general, interrupt_size * sizeof(thunk));
    assert(handlers != INVALID_ADDRESS);

    /* alternate frame storage */
    miscframe = allocate_frame(general);
    intframe = allocate_frame(general);
    bhframe = allocate_frame(general);

    /* Page fault alternate stack. */
    void * fault_stack_top = allocate_stack(pages, FAULT_STACK_PAGES);
    assert(fault_stack_top != INVALID_ADDRESS);
    set_ist(IST_PAGEFAULT, u64_from_pointer(fault_stack_top));

    /* Interrupt handlers run on their own stack. */
    void * int_stack_top = allocate_stack(pages, INT_STACK_PAGES);
    assert(int_stack_top != INVALID_ADDRESS);
    set_ist(IST_INTERRUPT, u64_from_pointer(int_stack_top));

    /* syscall stack - this can be replaced later by a per-thread kernel stack */
    syscall_stack_top = allocate_stack(pages, SYSCALL_STACK_PAGES);
    assert(syscall_stack_top != INVALID_ADDRESS);

    /* Bottom half stack */
    bh_stack_top = allocate_stack(pages, BH_STACK_PAGES);
    assert(bh_stack_top != INVALID_ADDRESS);

    // architectural - end of exceptions
    u32 vector_start = 0x20;
    interrupt_vectors = create_id_heap(general, vector_start, interrupt_size - vector_start, 1);
    // assuming contig gives us a page aligned, page padded identity map
    idt = allocate(pages, pages->pagesize);

    for (int i = 0; i < 32; i++)
        write_idt(idt, i, start + i * delta, i == 0xe ? IST_PAGEFAULT : 0);
    
    for (int i = 32; i < interrupt_size; i++)
        write_idt(idt, i, start + i * delta, IST_INTERRUPT);

    u16 *dest = (u16 *)(idt + 2*interrupt_size);
    dest[0] = 16*interrupt_size -1;
    
    *(u64 *)(dest + 1) = (u64)idt;// physical_from_virtual(idt);
    asm("lidt %0": : "m"(*dest));
    enable_lapic(pages);
    if (using_lapic_timer())
        configure_lapic_timer(general);
}
