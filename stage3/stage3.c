#include <sruntime.h>
#include <unix.h>
#include <pci.h>
#include <virtio.h>

u8 userspace_random_seed[16];

typedef struct aux {u64 tag; u64 val;} *aux;

static void build_exec_stack(buffer s, heap general, vector argv, node env, vector auxp)
{
    int length = vector_length(argv) + table_elements(env) +  2 * vector_length(auxp) + 4;
    s->start = s->end = s->length - length *8;
    buffer_write_le64(s, vector_length(argv));
    buffer i;
    vector_foreach(i, argv) {
        push_character(i, 0); // destructive
        buffer_write_le64(s, u64_from_pointer(i->contents));
    }
    buffer_write_le64(s, 0);
    
    table_foreach(env, n, v) 
        buffer_write_le64(s, u64_from_pointer(aprintf(general, "%b=%b\0\n", n, v)));
    buffer_write_le64(s, 0);
    
    aux a;
    vector_foreach(a, auxp) {
        buffer_write_le64(s, a->val);
        buffer_write_le64(s, a->tag);
    }
    buffer_write_le64(s, 0);
    buffer_write_le64(s, 0);
}

thread exec_elf(node fs, vector path, heap general, heap physical, heap pages)
{
    // i guess this is part of fork if we're following the unix model
    process p = create_process(general, pages, physical, fs);
    thread t = create_thread(p);
    // error handling
    struct buffer ex;
    node_contents(resolve_path(fs, path), &ex);    
    void *user_entry = load_elf(&ex, 0, pages, physical);        
    void *va;

    // extra elf munging
    Elf64_Ehdr *elfh = (Elf64_Ehdr *)buffer_ref(&ex, 0);

    struct aux auxp[] = {
        {AT_PHDR, elfh->e_phoff + u64_from_pointer(va)},
        {AT_PHENT, elfh->e_phentsize},
        {AT_PHNUM, elfh->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_RANDOM, u64_from_pointer(userspace_random_seed)},        
        {AT_ENTRY, u64_from_pointer(user_entry)}};

    // also pick up the maximum load address for the brk
    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = (void *)elfh + elfh->e_phoff + (i * elfh->e_phentsize);
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = pointer_from_u64(p->p_vaddr);
        if (p->p_type == PT_INTERP) {
            char *n = (void *)elfh + p->p_offset;
            // xxx - assuming leading slash
            buffer nb = alloca_wrap_buffer(n+1, runtime_strlen(n)-1);
            // virtual allocator..file not found
            struct buffer ldso;

            node_contents(resolve_path(fs, split(general, nb, '/')), &ldso);
            user_entry = load_elf(&ldso, 0x400000000, pages, physical);
        }
    }
    
    t->frame[FRAME_RIP] = u64_from_pointer(user_entry);
    map(0, INVALID_PHYSICAL, PAGESIZE, pages);
    
    // use runtime random
    u8 seed = 0x3e;
    for (int i = 0; i< sizeof(userspace_random_seed); i++)
        userspace_random_seed[i] = (seed<<3) ^ 0x9e;
    
    vector a = allocate_vector(general, 10);
    for (int i = 0; i< sizeof(auxp)/(2*sizeof(u64)); i++) vector_push(a, auxp+i);
    // general virtual address space allocation
    buffer s = alloca_wrap_buffer(0xa00000000, 2*1024*1024);
    map(u64_from_pointer(s->contents), allocate_u64(physical, s->length), s->length, pages);
    
    build_exec_stack(s, general, 
                     node_vector(general, resolve_path(fs, build_vector(general, sym(argv)))),
                     resolve(resolve(fs, sym(environment)), sym(files)),
                     a);
    
    // build stack leaves buffer start at the base of the stack
    t->frame[FRAME_RSP] = u64_from_pointer(buffer_ref(s, 0));
    return t;
}


        
void startup(heap pages, heap general, heap physical, node root)
{
    u64 c = cpuid();
    console("stage3\n");
    init_unix(general);
    struct buffer program_name, interp_name;
    node n = resolve(root, sym(program));
    struct buffer p;
    node_contents(n, &p);
    void *k = allocate(general, 512);
    storage_read(k, 0, 512, 0);
        
    // elem first 
    thread t = exec_elf(root, build_vector(general, split(general, &p, '/')), general, physical, pages);
    run(t);
    halt("program exit");
}

