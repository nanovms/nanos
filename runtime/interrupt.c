#include <sruntime.h>


// coordinate with crt0
extern u32 interrupt_size;
extern void *interrupt0, *interrupt1;
static u64 *idt;

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
    "reserved 1f",
    "timer", // 0x20
    "vq0", // 0x21
    "vq1", // 0x22
    "vq2"};    // 0x23


// we build the actual idt dynamically because the address
// is scattered all over the 16 bytes, and it looks pretty
// difficult, but maybe not impossible, to construct a relocation
// to fill it in (by aligning the handler base, assigning
// it a section, etc)



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

static char* textoreg[] = {
    "rax", //0 - if we could share an ennumeration with nasm
    "rbx", //1
    "rcx", //2
    "rdx", //3
    "rbp", //4
    "rsp", //5
    "rsi", //6
    "rdi", //7
    "r8",  //8
    "r9",  //9
    "r10", //10
    "r11", //11
    "r12", //12
    "r13", //13
    "r14", //14
    "r15", //15
    "vector", //16
    "rip", //17
    "flags", //18
};

u64 * frame;

static thunk *handlers;

void *apic_base = (void *)0xfee00000;

void lapic_eoi()
{
    *(unsigned int *)(apic_base +0xb0) = 0;
}

void common_handler()
{
    int i = frame[16];
    u64 z;
    
    if ((i < interrupt_size) && handlers[i]) {
        apply(handlers[i]);
        lapic_eoi();
    } else {
        if (i < 25) {
            console(interrupts[frame[16]]);
            console("\n");        
        } 
        for (int j = 0; j< 18; j++) {
            console(textoreg[j]);
            console(": ");
            print_u64(frame[j]);
            console("\n");        
        }

        u64 *stack = pointer_from_u64(frame[FRAME_RSP]);
        for (int j = 0; (frame[FRAME_RSP] + 8*j)  & MASK(20); j++) {
            print_u64((frame[FRAME_RSP] + 8*j)  & MASK(20));
            console (" ");
            print_u64(stack[j]);
            console("\n");        
        }
        QEMU_HALT();
    }
}

static u8 unused_msi = 0x1;
static u8 unused_vector = 34;

u8 allocate_msi(thunk h)
{
    // allocators
    int v = unused_vector++;
    int m = unused_msi++;
    handlers[v] = h;
    msi_map_vector(m, v);
    return m; 
}

void enable_lapic(heap pages)
{
    // there is an msr that moves the physical
    u64 lapic = 0xfee00000;
    
    // actually allocate the virtual 
    map(u64_from_pointer(apic_base), lapic, PAGESIZE, pages);
    create_region(u64_from_pointer(apic_base), PAGESIZE, REGION_VIRTUAL);
    
    // turn on the svr, then enable three lines
    // - this could be a little more symbolic
    *(unsigned int *)(apic_base +0xf0) = *(unsigned int *)(apic_base +0xf0) | 0x100;

    *(unsigned int *)(apic_base + 0x350)= 0x020; //lint0 - int 32
    *(unsigned int *)(apic_base + 0x360)= 0x400; //lint1 - nmi
    *(unsigned int *)(apic_base + 0x370)= 0x022; //error - int 34
}


void register_interrupt(int vector, thunk t)
{
    handlers[vector] = t;
}

void start_interrupts(heap pages, heap general, heap contiguous)
{
    // these are simple enough it would be better to just
    // synthesize them
    int delta = (u64)&interrupt1 - (u64)&interrupt0;
    void *start = &interrupt0;
    handlers = allocate_zero(general, interrupt_size * sizeof(thunk));

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
