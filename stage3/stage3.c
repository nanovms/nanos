#include <runtime.h>
#include <system.h>
#include <system_structs.h>

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
extern void *_fs_start;
extern void *_fs_end;

buffer filesystem;
heap general;

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

// returns entry address.. need the base of the elf also for ld.so
// bss is allocated virtual and double mapped. should pass
// a physical allocator
void *load_elf(void *base, u64 offset, heap pages, heap bss)
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
            void *bss_start = (void *)vbase + p->p_filesz + (p->p_vaddr & MASK(PAGELOG));
            u32 bss_size = p->p_memsz-p->p_filesz;
            u32 already_pad = PAGESIZE - bss_size & MASK(PAGELOG);
            if ((bss_size > already_pad)) {
                u32 new_pages = pad(bss_size, PAGESIZE);
                u64 phy = physical_from_virtual(allocate(bss, new_pages));
                map(u64_from_pointer(bss_start), phy, new_pages, pages);
            }            
            runtime_memset(bss_start, 0, bss_size);
        }
    }
    u64 entry = elfh->e_entry;
    entry += offset; // see above
    return pointer_from_u64(entry);
}

void startup(heap pages, heap g2, heap contiguous)
{
    // baah, globals..this is just here because of a buffer required by unix emulation - system
    process p = create_process(g2);
    thread t = create_thread(p);
    u64 c = cpuid();
    
    set_syscall_handler(syscall_enter);

    filesystem = allocate(g2, sizeof(struct buffer));
    filesystem->contents = &_fs_start;
    filesystem->length = filesystem->end = &_fs_end - &_fs_start;
    filesystem->start = 0;

    
    // vm space allocation
    void *ldso = load_elf(&_ldso_start,0x400000000, pages, contiguous);
    void *user_entry = load_elf(&_program_start,0, pages, contiguous);
    
    Elf64_Ehdr *elfh = (Elf64_Ehdr *)&_program_start;


    // extract this stuff (args, env, auxp) from the 'filesystem'    
    struct {u64 tag; u64 val;} auxp[] = {
        {AT_PHDR, elfh->e_phoff + u64_from_pointer(elfh)},
        {AT_PHENT, elfh->e_phentsize},
        {AT_PHNUM, elfh->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_ENTRY, u64_from_pointer(user_entry)}};
    char *envp[]= {"foo=1", "bar=2"};
    char *cargv[] = {"program", "arg1"};
    int cargc = sizeof(cargv)/sizeof(void *);
    int i;

    // this should actually effect the exec...set this
    // up on the threads stack
    run(t);
    
    rprintf("envp: %d\n", sizeof(envp)/sizeof(void *));
    rprintf("eauxnvp: %d\n", sizeof(auxp)/(2*sizeof(u64)));

    __asm__("push $0"); // end of auxp
    __asm__("push $0");

    for (int i = 0; i< sizeof(auxp)/(2*sizeof(u64)); i++) {
        __asm__("push %0"::"m"(auxp[i].val));
        __asm__("push %0"::"m"(auxp[i].tag));
    } 
    
    __asm__("push $0"); // end of envp

    for (int i = 0; i< sizeof(envp)/sizeof(void *); i++)
        __asm__("push %0"::"m"(envp[i]));

    __asm__("push $0"); // end of argv
        
    for (int i = 0; i < cargc; i++)
        __asm__("push %0"::"m"(cargv[i]));

    __asm__("push %0"::"m"(cargc));
    __asm__("jmp *%0"::"m"(ldso));
    // intead of jump
    run(t); // 
}

