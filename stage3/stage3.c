#include <runtime.h>

extern u64 cpuid();
extern u64 read_msr(u64);
extern void write_msr(u64, u64);
extern u64 read_xmsr(u64);
extern void write_xmsr(u64, u64);
extern void syscall_enter();
extern u64 *frame;
extern void *_binary_test_bin_start;

#define EFER_MSR 0xc0000080
#define EFER_SCE 1
#define STAR_MSR 0xc0000081
#define LSTAR_MSR 0xc0000082
#define SFMASK_MSR 0xc0000084

// could really take the args directly off the function..maybe dispatch in
// asm
u64 syscall()
{
    console("syscall ");
    print_u64(frame[FRAME_VECTOR]);
    console(" ");
    print_u64(frame[FRAME_RIP]);
    console(" ");
    print_u64(frame[FRAME_RDI]);
    console(" ");
    print_u64(frame[FRAME_RSI]);        
    console(" ");
    print_u64(frame[FRAME_RDX]);        
    console("\n");
    return (0);
}

// make a write msr
void install_handler()
{
    u64 cs  = 0x08;
    u64 ss  = 0x10;

    // ooh baby, virtual
    write_msr(LSTAR_MSR, u64_from_pointer(syscall_enter));
    // 48 is sysret cs, and ds is cs + 16...so fix the gdt for return
    // 32 is syscall cs, and ds is cs + 8
    write_msr(STAR_MSR, (cs<<48) | (cs<<32));
    write_msr(SFMASK_MSR, 0);
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
}


void startup(heap pages, heap general)
{
    console("stage3\n");
    void *base = &_binary_test_bin_start;
    Elf64_Ehdr *elfh = base;

    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = elfh->e_phoff + base + i * elfh->e_phentsize;
        if (p->p_type == PT_LOAD) {
            int ssize = pad(p->p_memsz, PAGESIZE);
            map(p->p_vaddr, physical_from_virtual(base+p->p_offset), ssize, pages);
            void *start = base + p->p_offset;
            // need to allocate the bss here
            for (u8 *x =  start + p->p_filesz; x < (u8 *)start + p->p_memsz; x++)
                *x = 0;
        }
    }

    u64 c = cpuid();
    console("cpuid: ");
    print_u64(c);
    console("\n");
    
    
    install_handler();
    
    char arg[] = "program";
    char arg2[] = "program";    

    // only if cpuid & 1<<60
    //    u64 k = read_xmsr(0);
    //    k |= 7; // avx, sse, x87...x87?
    //    write_xmsr(0, k);    
    // not really
    map (0x10000, PHYSICAL_INVALID, 2*4096, pages);
    // push pointers to X=Y environment thingies
    __asm__ ("push %0"::"m"(arg2));    
    __asm__ ("push %0"::"m"(arg));
    __asm__ ("push $2");
    __asm__ ("jmp *%0": :"m"(elfh->e_entry));
}

