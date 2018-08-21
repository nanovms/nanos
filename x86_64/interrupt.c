#include <runtime.h>
#include <kvm_platform.h>

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
#define TMR_BASEDIV (1<< 20)
    
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
    return(interrupts[s]);
}


void write_idt(u64 *idt, int interrupt, void *hv)
{
    // huh, idt entries are virtual 
    u64 h = u64_from_pointer(hv); 
    u64 selector = 0x08;
    u64 ist = 0; // this is a stask switch through the tss
    u64 type_attr = 0x8e;
        
    u64 *target = (void *)(u64)(idt + 2*interrupt);
        
    target[0] = (h & MASK(16)) | (selector << 16) | (ist << 32) | (type_attr << 40)|
        (((h>>16) & MASK(16))<<48);
    target[1] = h >> 32; // rest must be zero
}

// tuplify and synthesize
static char* textoreg[] = {
    "rax", //0 
    "rbx", //1
    "rcx", //2
    "rdx", //3
    "rsi", //4
    "rdi", //5
    "rbp", //6
    "rsp", //7
    "r8",  //8
    "r9",  //9
    "r10", //10
    "r11", //11
    "r12", //12
    "r13", //13
    "r14", //14
    "r15", //15
    "rip", //16
    "flags", //17        
    "vector", //18
};

char *register_name(u64 s)
{
    return(textoreg[s]);
}

static thunk *handlers;
u64 *frame;

void *apic_base = (void *)0xfee00000;

void lapic_eoi()
{
    write_barrier();
    *(unsigned int *)(apic_base +0xb0) = 0;
    write_barrier();    
}

char * find_elf_sym(u64 a, u64 *offset);

void print_u64_with_sym(u64 a)
{
    char * name;
    u64 offset;

    print_u64(a);

    name = find_elf_sym(a, &offset);
    if (name) {
	console("\t(");
	console(name);
	console(" + ");
	print_u64(offset);
	console(")");
    }
}

void print_stack(context c)
{
    u64 frames = 20;
    u64 *x = pointer_from_u64(c[FRAME_RSP]);
    // really until page aligned?
    console("stack \n");
    for (u64 i= frames ;i > 0; i--) {
        print_u64_with_sym(*(x+i));
        console("\n");
    }
}

void print_frame(context f)
{
    u64 v = f[FRAME_VECTOR];
    //        console(interrupt_name(v));
    console("interrupt: ");
    print_u64_with_sym(v);
    console("\n");
    console("frame: ");
    print_u64_with_sym(u64_from_pointer(f));
    console("\n");    
    
    // page fault
    if (v == 14)  {
        u64 fault_address;
        mov_from_cr("cr2", fault_address);
        console("address: ");
        print_u64_with_sym(fault_address);
        console("\n");
    }
    
    for (int j = 0; j< 18; j++) {
        console(register_name(j));
        console(": ");
        print_u64_with_sym(f[j]);
        console("\n");        
    }
}

void common_handler()
{
    int i = frame[FRAME_VECTOR];
    u64 z;

    if ((i < interrupt_size) && handlers[i]) {
        // should we switch to the 'kernel process'?
        apply(handlers[i]);
        lapic_eoi();
    } else {
        fault_handler f = pointer_from_u64(frame[FRAME_FAULT_HANDLER]);

        if (f == 0) {
            rprintf ("no fault handler\n");
            print_frame(frame);
            print_stack(frame);
            QEMU_HALT();
        }
        if (i < 25) frame = apply(f, frame);
    }
}

static heap interrupt_vectors;

void allocate_msi(int slot, int msi_slot, thunk h)
{
    int v = allocate_u64(interrupt_vectors, 1);
    handlers[v] = h;
    msi_map_vector(slot, msi_slot, v);
}

// actually allocate the virtual  - put in the tree
void enable_lapic(heap pages)
{
    // there is an msr that moves the physical
    u64 lapic = 0xfee00000;
    
    map(u64_from_pointer(apic_base), lapic, PAGESIZE, pages);
    // xxx - no one is listening
    create_region(u64_from_pointer(apic_base), PAGESIZE, REGION_VIRTUAL);
    
    // turn on the svr, then enable three lines
    *(unsigned int *)(apic_base + APIC_SPURIOUS) = *(unsigned int *)(apic_base + APIC_SPURIOUS) | APIC_SW_ENABLE;

    *(u32 *)(apic_base + APIC_LVT_LINT0)= APIC_DISABLE;
    *(u32 *)(apic_base + APIC_LVT_LINT1)= APIC_DISABLE;
    *(u32 *)(apic_base + APIC_LVT_ERR)= allocate_u64(interrupt_vectors, 1);
}


void register_interrupt(int vector, thunk t)
{
    handlers[vector] = t;
}

void configure_timer(time rate, thunk t)
{
    *(u32 *)(apic_base+APIC_TMRDIV) = 3;
    int v = allocate_u64(interrupt_vectors, 1);
    *(u32 *)(apic_base+APIC_LVT_TMR) = v | TMR_PERIODIC;
    // calibrate rdtsc using kvm info
    *(u32 *)(apic_base + APIC_TMRINITCNT) = 10 * 1000*1000*8;
    handlers[v] = t;
    // 3 is 10 ms .. apparently, says who?

}

extern u32 interrupt_size;
 
void start_interrupts(heap pages, heap general, heap contiguous)
{
    // these are simple enough it would be better to just
    // synthesize them
    int delta = (u64)&interrupt1 - (u64)&interrupt0;
    void *start = &interrupt0;
    handlers = allocate_zero(general, interrupt_size * sizeof(thunk));
    // architectural - end of exceptions
    u32 vector_start = 0x20;
    interrupt_vectors = create_id_heap(general, vector_start, interrupt_size - vector_start, 1);
    // assuming contig gives us a page aligned, page padded identity map
    idt = allocate(pages, pages->pagesize);
    frame = allocate(pages, pages->pagesize);

    for (int i = 0; i < interrupt_size; i++) 
        write_idt(idt, i, start + i * delta);
    
    u16 *dest = (u16 *)(idt + 2*interrupt_size);
    dest[0] = 16*interrupt_size -1;
    
    *(u64 *)(dest + 1) = (u64)idt;// physical_from_virtual(idt);
    asm("lidt %0": : "m"(*dest));
    enable_lapic(pages);
}
