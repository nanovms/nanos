#include <sruntime.h>
#include <system.h>

u8 userspace_random_seed[16];

typedef struct virtual_address_allocator {
    heap h;
    u64 offset;
} *virtual_address_allocator; 
    
static u64 virtual_address_allocate(heap h)
{
    virtual_address_allocator v = (virtual_address_allocator) h;
    u64 result = v->offset;
    v->offset += (1ull<<32ull);
    return result;
}

void startup(heap pages, heap general, heap physical, node filesystem)
{

    u64 c = cpuid();
    
    set_syscall_handler(syscall_enter);

    process p = create_process(general, pages, physical, filesystem);
    thread t = create_thread(p);

    buffer program_name = storage_buffer(general, filesystem, staticvector(staticbuffer("program")));
    void *pstart;
    u64 plength;
    if (!storage_resolve(filesystem, split(general, program_name, '/'), &pstart, &plength ))
        halt("no program entry %b\n", program_name);

    void *user_entry = load_elf(pstart,0, pages, physical);        
    void *ldso;
    vector elf_interpreter;
    
    Elf64_Ehdr *elfh = (Elf64_Ehdr *)pstart;
    void *va;
    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = pstart + elfh->e_phoff + (i * elfh->e_phentsize);
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = pointer_from_u64(p->p_vaddr);
        if (p->p_type == PT_INTERP) {
        }
    }
    
    if (storage_resolve(filesystem, elf_interpreter, &ldso, &plength)){
        // use virtual allocator
        ldso = load_elf(ldso, 0x400000000, pages, physical);
    } else {
        halt("no such elf interpreter %b\n", elf_interpreter);
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

    __asm__("push $0"); // end of auxp
    __asm__("push $0");

    for (int i = 0; i< sizeof(auxp)/(2*sizeof(u64)); i++) {
        __asm__("push %0"::"m"(auxp[i].val));
        __asm__("push %0"::"m"(auxp[i].tag));
    } 
    
    __asm__("push $0"); // end of envp
    storage_foreach(filesystem, staticvector(staticbuffer("environment")), name, value) {
        buffer b = allocate_buffer(general, buffer_length(name)+buffer_length(value)+2);        
        buffer_write(b, name->contents, buffer_length(name));
        push_character(b, '=');
        buffer_write(b, value->contents, buffer_length(value));
        push_character(b, 0);
        void *z = b->contents;
        __asm__("push %0"::"m"(z));
    }

    __asm__("push $0"); // end of argv
    int argc=0;
    storage_vector_foreach(filesystem, "/args", i, v) {
        buffer b = allocate_buffer(general, buffer_length(v) + 1);
        buffer_write(b, b->contents, b->length);
        push_character(b, 0);
        argc++;
        void *z = b->contents;
        __asm__("push %0"::"m"(z));
    }
    __asm__("push %0"::"m"(argc));
    
    t->frame[FRAME_RIP] = u64_from_pointer(ldso);
    run(t);
}

