#include <runtime.h>
#include <syscall_arch.h>

extern u64 cpuid();
extern u64 read_msr(u64);
extern void write_msr(u64, u64);
extern u64 read_xmsr(u64);
extern void write_xmsr(u64, u64);
extern void syscall_enter();
extern u64 *frame;

#define EFER_MSR 0xc0000080
#define EFER_SCE 1
#define STAR_MSR 0xc0000081
#define LSTAR_MSR 0xc0000082
#define SFMASK_MSR 0xc0000084

extern void *_ldso_start;
extern void *_program_start;

// could really take the args directly off the function..maybe dispatch in
// asm
u64 syscall()
{
    int call = frame[FRAME_VECTOR];
    switch (call) {
    case SYS_write:
        {
            char *x = pointer_from_u64(frame[FRAME_RSI]);
            for (int i = 0; i< frame[FRAME_RDX]; i++)
                serial_out(x[i]);
        }
        break;
    case SYS_open:
        {
            char *x = pointer_from_u64(frame[FRAME_RDI]);
            console("open ");
            console(x);
            console("\n");
            return 3;
        }
    case SYS_fstat:
        console("fstat ");
        print_u64(frame[FRAME_RDI]);
        console("\n");
        return 0;
        
        
    default:
        console("syscall ");
        print_u64(frame[FRAME_VECTOR]);
        console(" ");
        print_u64(frame[FRAME_RDI]);
        console(" ");
        print_u64(frame[FRAME_RSI]);        
        console(" ");
        print_u64(frame[FRAME_RDX]);        
        console("\n");
        return (0);
    }
}

void set_syscall_handler(void *syscall_entry)
{
    u64 cs  = 0x08;
    u64 ss  = 0x10;

    // ooh baby, virtual
    write_msr(LSTAR_MSR, u64_from_pointer(syscall_entry));
    // 48 is sysret cs, and ds is cs + 16...so fix the gdt for return
    // 32 is syscall cs, and ds is cs + 8
    write_msr(STAR_MSR, (cs<<48) | (cs<<32));
    write_msr(SFMASK_MSR, 0);
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
}

// returns entry address.. need the base of the elf also
void *load_elf(void *base, u64 offset, heap pages)
{
    Elf64_Ehdr *elfh = base;

    // ld.so cant be loaded at its ph location, 0
    // also - write a virtual address space allocator that
    // maximizes sparsity
    // xxx looks like a page table setup problem?

    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = elfh->e_phoff + base + i * elfh->e_phentsize;
        if (p->p_type == PT_LOAD) {
            //            map(p->p_vaddr, physical_from_virtual(base+p->p_offset), ssize, pages);
            // unaligned segment? uncool bro
            u64 vbase = (p->p_vaddr & ~MASK(PAGELOG)) + offset;
            int ssize = pad(p->p_memsz + (p->p_vaddr & MASK(PAGELOG)), PAGESIZE);
            map(vbase, physical_from_virtual((void *)(base+p->p_offset)), ssize, pages);            
            void *start = (void *)vbase + p->p_filesz + (p->p_vaddr & MASK(PAGELOG));
            int bss_size = p->p_memsz-p->p_filesz;
            // xxx - need to allocate the bss here
            console("bss: ");
            print_u64(start);
            console(" ");
            print_u64(bss_size);
            console("\n");
            runtime_memset(start, 0, bss_size);
        }
    }
    u64 entry = elfh->e_entry;
    entry += offset; // see above
    return pointer_from_u64(entry);
}

void startup(heap pages, heap general)
{
    console("stage3\n");
 
    u64 c = cpuid();
    console("cpuid: ");
    print_u64(c);
    console("\n");
    
    set_syscall_handler(syscall_enter);

    // vm space allocation
    void *ldso = load_elf(&_ldso_start,0x400000000, pages);
    void *user_entry = load_elf(&_program_start,0, pages);    

    // only if cpuid & 1<<60
    //    u64 k = read_xmsr(0);
    //    k |= 7; // avx, sse, x87...x87?
    //    write_xmsr(0, k);    
    // not really - but this should work, it currently
    // goes off into nowhere
    //   map (0x10000, PHYSICAL_INVALID, 2*4096, pages);
    // push pointers to X=Y environment thingies

    Elf64_Ehdr *elfh = (Elf64_Ehdr *)&_program_start;
    console("starting loader\n");
    void (*dl_main)(void *, u64, void*, void *) = ldso;
    // idk why dl cant do this..but ok
    Elf64_Phdr *p = elfh->e_phoff + (void *)elfh;
    // where does that go

    void *auxp = 0;
    char *envp[]= {"foo=1", "bar=2", 0};
    char *cargv[] = {"program", "arg1"};
    int cargc = 2;

    __asm__("push %0"::"m"(auxp));
    for (int i = 0; envp[i]; i++)
        __asm__("push %0"::"m"(envp[i]));
    __asm__("push 0");
    __asm__("push %0"::"m"(envp));
    __asm__("push %0"::"m"(cargv));
    __asm__("push %0"::"m"(cargc));
    __asm__("jmp %0"::"m"(ldso));
}

