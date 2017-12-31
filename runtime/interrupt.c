#include <runtime.h>

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



void write_handler(u64 *idt, int interrupt, void *hv)
{
    u64 h = vtop(hv);
    u64 selector = 0x08;
    u64 ist = 0; // this is a stask switch through the tss
    u64 type_attr = 0x8e;
        
    u64 *target = (void *)(u64)(idt + 2*interrupt);
        
    target[0] = (h & MASK(16)) | (selector << 16) | (ist << 32) | (type_attr << 40)|
        (((h>>16) & MASK(16))<<48);
    target[1] = h >> 32; // rest must be zero
}

void common_handler()
{
    console("interrupt1o!\n");
}

void lapic_eoi()
{
    *(unsigned int *)0xfee000b0= 0;
}

void enable_lapic()
{
    // turn on the svr, then enable three lines
    // - this could be a little more symbolic
    *(unsigned int *)0xfee000f0 = *(unsigned int *)0xfee000f0 | 0x100;

    *(unsigned int *)0xfee00350= 0x020; //lint0 - int 32
    *(unsigned int *)0xfee00360= 0x400; //lint1 - nmi
    *(unsigned int *)0xfee00370= 0x022; //error - int 34
}

// coordinate with crt0
extern u32 interrupt_size;
extern void *interrupt0, *interrupt1;

static u64 *idt;

void start_interrupts()
{
    int delta = (u64)&interrupt1 - (u64)&interrupt0;
    void *start = &interrupt0;

    // assuming contig gives us identity map
    idt = allocate(contiguous, contiguous->pagesize);

    for (int i = 0; i < interrupt_size; i++) 
        write_handler(idt, i, start + i * delta);
    u16 *dest = (u16 *)(idt + 2*interrupt_size);
    dest[0] = 16*interrupt_size -1;
    *(u32 *)(dest + 1) = (u64)idt;

    asm("lidt %0": : "m"(*dest));
    enable_lapic();
    enable_interrupts();
}
