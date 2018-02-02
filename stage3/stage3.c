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


u8 userspace_random_seed[16];

void startup(heap pages, heap general, heap contiguous)
{

    u64 c = cpuid();
    
    set_syscall_handler(syscall_enter);

    filesystem = allocate(general, sizeof(struct buffer));
    filesystem->contents = &_fs_start;
    filesystem->length = filesystem->end = &_fs_end - &_fs_start;
    filesystem->start = 0;

    process p = create_process(general, pages, contiguous, filesystem);
    thread t = create_thread(p);
    
    // vm space allocation
    // take these from the filesystem
    // look up the interpreter from the program header like we're supposed to
    void *ldso = load_elf(&_ldso_start,0x400000000, pages, contiguous);
    void *user_entry = load_elf(&_program_start,0, pages, contiguous);

    rprintf("ldso start: %p\n", ldso);
    // get virtual load address - passing the backing confuses ld.so
    Elf64_Ehdr *elfh = (Elf64_Ehdr *)&_program_start;
    void *va;
    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = elfh->e_phoff + ((void *)&_program_start) + i * elfh->e_phentsize;
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = pointer_from_u64(p->p_vaddr);
    }
    
    map(0, PHYSICAL_INVALID, PAGESIZE, pages);

    u8 seed = 0x3e;
    for (int i = 0; i< sizeof(userspace_random_seed); i++)
        userspace_random_seed[i] = (seed<<3) ^ 0x9e;
    
    // extract this stuff (args, env, auxp) from the 'filesystem'    
    struct {u64 tag; u64 val;} auxp[] = {
        {AT_PHDR, elfh->e_phoff + u64_from_pointer(va)},
        {AT_PHENT, elfh->e_phentsize},
        {AT_PHNUM, elfh->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_RANDOM, u64_from_pointer(userspace_random_seed)},        
        {AT_ENTRY, u64_from_pointer(user_entry)}};
    char *envp[]= {"foo=1", "bar=2"};
    char *cargv[] = {"program", "arg1"};
    int cargc = sizeof(cargv)/sizeof(void *);
    int i;

    // this should actually effect the exec...set this
    // up on the threads stack
    run(t);

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

