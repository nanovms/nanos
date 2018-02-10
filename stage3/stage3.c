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

void *load_file(node filesystem, heap general, buffer name)
{
    void *pstart;
    name->start = 0;
    vector pnv = split(general, name, '/');
    vector_pop(pnv);
    u64 plength;
    node n = storage_resolve(filesystem, pnv);
    if (!node_contents(n, &pstart, &plength)) {
        rprintf("couldn't load file %b\n", name);
    }
    return pstart;
}

static void push(buffer b, u64 w)
{
    *(u64 *)(b->contents+b->start+b->end - sizeof(u64)) = w;
    b->end -= sizeof(u64);
}

void startup(heap pages, heap general, heap physical, node filesystem)
{
    console("startup\n");
    u64 c = cpuid();

    init_system(general);
    process p = create_process(general, pages, physical, filesystem);
    thread t = create_thread(p);

    // wrap this in exec()
    struct buffer program_name, interp_name;
    node n = storage_resolve(filesystem, build_vector(general, staticbuffer("program")));
    if (!node_contents(n, &program_name.contents, &program_name.end)) halt("bad program file\n");
    void *pstart = load_file(filesystem, general, &program_name);
    void *user_entry = load_elf(pstart, 0, pages, physical);        
    void *va;

    Elf64_Ehdr *elfh = (Elf64_Ehdr *)pstart;
    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = pstart + elfh->e_phoff + (i * elfh->e_phentsize);
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = pointer_from_u64(p->p_vaddr);
        if (p->p_type == PT_INTERP) {
            interp_name.contents = pstart + p->p_offset;
            interp_name.end = runtime_strlen(interp_name.contents);
            interp_name.start = 0;
        }
    }
    console("frame\n");
    rprintf("frame %p\n", t->frame);
    void *ldso = load_file(filesystem, general, &interp_name);
    t->frame[FRAME_RIP] = u64_from_pointer(load_elf(ldso, 0x400000000, pages, physical));
    console("constructing arglist\n");
    
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

    struct buffer s;
    s.start = 0;
    s.contents = pointer_from_u64(0xa00000000);
    s.end = s.length = 2*1024*1024;
    map(u64_from_pointer(s.contents), allocate_u64(physical, s.length), s.length, pages);

    push(&s, 0); // end of auxp
    push(&s, 0);    
    
    for (int i = 0; i< sizeof(auxp)/(2*sizeof(u64)); i++) {
        push(&s, auxp[i].val);
        push(&s, auxp[i].tag);
    } 

    push(&s, 0); // end of envp
    node env = storage_resolve(filesystem, build_vector(general, staticbuffer("environment")));
    if (!is_empty(env)) {
        env = storage_lookup_node(env, staticbuffer("files"));
        storage_foreach(env, name, value) {
            rprintf("environment %b %b\n", name, value);
            buffer b = allocate_buffer(general, buffer_length(name)+buffer_length(value)+2);        
            buffer_write(b, name->contents, buffer_length(name));
            push_character(b, '=');
            buffer_write(b, value->contents, buffer_length(value));
            push_character(b, 0);
            push(&s, u64_from_pointer(b->contents)); 
        }
    } else {
        rprintf("no environment\n");
    }

    push(&s, 0); // end of envp
    u64 argc=0;
    node args = storage_resolve(filesystem, build_vector(general, staticbuffer("args")));
    args = storage_lookup_node(args, staticbuffer("files"));
    storage_vector_foreach(args, i, v) {
        buffer b = allocate_buffer(general, buffer_length(v) + 1);
        buffer_write(b, b->contents, b->length);
        push_character(b, 0);
        argc++;
        push(&s, u64_from_pointer(b->contents));         
    }
    push(&s, u64_from_pointer(argc));
    console("what?\n");
    t->frame[FRAME_RSP] = u64_from_pointer(s.contents + s.end);
    rprintf("Entry: %p %p\n", t->frame[FRAME_RIP], t->frame[FRAME_RSP]);
    run(t);
}

