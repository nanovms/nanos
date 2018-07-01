#include <unix_internal.h>
#include <elf64.h>

static void build_exec_stack(buffer s, heap general, vector argv, tuple env, vector auxp)
{
    int length = vector_length(argv) + table_elements(env) +  2 * vector_length(auxp) + 6;
    s->start = s->end = s->length - length *8;
    buffer_write_le64(s, vector_length(argv));
    tuple i;
    vector_foreach(argv, i) 
        buffer_write_le64(s, u64_from_pointer(aprintf(general, "%b\0\n", contents(i))->contents));
    
    buffer_write_le64(s, 0);

    table_foreach(env, n, v) {
        buffer binding = aprintf(general, "%b=%b\0\n", symbol_string(n), contents(v));
        buffer_write_le64(s, u64_from_pointer(binding->contents));
    }
    buffer_write_le64(s, 0);

    aux a;
    vector_foreach(auxp, a) {
        buffer_write_le64(s, a->tag);
        buffer_write_le64(s, a->val);
    }
    buffer_write_le64(s, 0);
    buffer_write_le64(s, 0);
}

process exec_elf(buffer ex, heap general, heap physical, heap pages, heap virtual, tuple fs)
{
    process p = create_process(general, pages, physical, fs);
    thread t = create_thread(p);
    void *user_entry = load_elf(ex, 0, pages, physical);
    void *actual_entry = user_entry;
    void *va;

    // extra elf munging
    Elf64_Ehdr *elfh = (Elf64_Ehdr *)buffer_ref(ex, 0);


    // also pick up the maximum load address for the brk
    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = (void *)elfh + elfh->e_phoff + (i * elfh->e_phentsize);
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = pointer_from_u64(p->p_vaddr);
        if (p->p_type == PT_INTERP) {
            char *n = (void *)elfh + p->p_offset;
            // xxx - assuming leading slash
            buffer nb = alloca_wrap_buffer(n, runtime_strlen(n));
            // file not found
            tuple ldso = resolve_path(fs, split(general, nb, '/'));
            u64 where = allocate_u64(virtual, HUGE_PAGESIZE);
            buffer c = table_find(ldso, sym(contents));
            user_entry = load_elf(c, where, pages, physical);
        }
    }

    u8 userspace_random_seed[16];

    struct aux auxp[] = {
        {AT_PHDR, elfh->e_phoff + u64_from_pointer(va)},
        {AT_PHENT, elfh->e_phentsize},
        {AT_PHNUM, elfh->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_RANDOM, u64_from_pointer(userspace_random_seed)},        
        {AT_ENTRY, u64_from_pointer(actual_entry)}};
    
    t->frame[FRAME_RIP] = u64_from_pointer(user_entry);
    map(0, INVALID_PHYSICAL, PAGESIZE, pages);
    
    // use runtime random
    u8 seed = 0x3e;
    for (int i = 0; i< sizeof(userspace_random_seed); i++)
        userspace_random_seed[i] = (seed<<3) ^ 0x9e;
    
    vector aux = allocate_vector(general, 10);
    for (int i = 0; i< sizeof(auxp)/(2*sizeof(u64)); i++) 
        vector_push(aux, auxp+i);

    u64 stack_size = 2*1024*1024;
    void *user_stack = allocate(virtual, stack_size);
    buffer s = alloca_wrap_buffer(user_stack, stack_size);       
    map(u64_from_pointer(user_stack), allocate_u64(physical, stack_size), stack_size, pages);

    build_exec_stack(s,
                     general,
                     tuple_vector(general, children(resolve_cstring(fs, "arguments"))),
                     children(resolve_cstring(fs, "environment")),
                     aux);

    t->frame[FRAME_RSP] = u64_from_pointer(buffer_ref(s, 0));
    // move outside?
#if NET && GDB
    if (resolve_cstring(fs, "gdb")) {
        console ("gdb!\n");
        init_tcp_gdb(general, p, 1234);
    } else
#endif
    {
        rprintf ("user entry: %p\n", user_entry);
        enqueue(runqueue, t->run);
    }
    return p;    
}

