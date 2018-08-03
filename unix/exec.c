#include <unix_internal.h>
#include <elf64.h>

#define spush(__s, __w) *((--(__s))) = (u64)(__w)

#define ppush(__s, __b, __f, ...) ({buffer_clear(__b);\
            bprintf(b, __f, __VA_ARGS__);                               \
            u64 len = pad(buffer_length(b), 64)>>6;                     \
            __s -= len;                                                 \
            runtime_memcpy(s, buffer_ref(b, 0), buffer_length(b));\
            (char *)__s;})

static void build_exec_stack(heap sh, thread t, Elf64_Ehdr * e, void *start, u64 va, tuple process_root)
{
    rprintf ("build exec stack %p %v\n", process_root, transient);
    buffer b = allocate_buffer(transient, 128);
    vector arguments = tuple_vector(transient, table_find(process_root, sym(arguments)));
    tuple environment = table_find(process_root, sym(environment));
    u64 stack_size = 2*MB;
    u64 pointer = stack_size;
    u64 *s = allocate(sh, stack_size);
    s += stack_size >> 6;

    spush(s, random_u64());
    spush(s, random_u64());
    struct aux auxp[] = {
        {AT_PHDR, e->e_phoff + va},
        {AT_PHENT, e->e_phentsize},
        {AT_PHNUM, e->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_RANDOM, u64_from_pointer(s)},
        {AT_ENTRY, u64_from_pointer(start)}};
    
    int auxplen = sizeof(auxp)/(2*sizeof(u64));
    int argc = vector_length(arguments);    
    char **argv = alloca(argc * sizeof(u64));
    int envc = table_elements(environment);
    char **envp = alloca(envc * sizeof(u64));
    buffer a;
    vector_foreach(arguments, a)  argv[argc++] = ppush(s, b, "%b\0", a);
    table_foreach(environment, n, v)  envp[envc++] = ppush(s, b, "%b=%b\0", symbol_string(n), v);
    spush(s, 0);
    spush(s, 0);
    
    for (int i = 0; i< auxplen; i++) {
        spush(s, auxp[i].val);
        spush(s, auxp[i].tag);
    }
    spush(s, 0);
    for (int i = 0; i< envc; i++) spush(s, envp[i]);
    spush(s, 0);
    for (int i = argc - 1 ; i >= 0; i--) spush(s, argv[i]);
    spush(s, argc);

    t->frame[FRAME_RSP] = u64_from_pointer(s);
}

void start_process(thread t, void *start)
{
    t->frame[FRAME_RIP] = u64_from_pointer(start);
    
    // move outside?
#if NET && GDB
    if (resolve_cstring(fs, "gdb")) {
        console ("gdb!\n");
        init_tcp_gdb(general, p, 1234);
    } else
#endif
    {
        rprintf ("enq\n");
        enqueue(runqueue, t->run);
    }
}

static CLOSURE_0_1(load_interp_fail, void, status);
static void load_interp_fail(status s)
{
    console("interp fail\n");
    halt("read interp failed %v\n", s);
}


CLOSURE_4_1(load_interp_complete, void, thread, heap, heap, heap, buffer);
void load_interp_complete(thread t, heap virtual, heap pages, heap physical, buffer b)
{
    u64 where = allocate_u64(virtual, HUGE_PAGESIZE);
    start_process(t, load_elf(b, where, pages, physical));
}


// thats...alot of heaps
process exec_elf(buffer ex,
                 tuple md,
                 tuple root,
                 heap general,
                 heap physical,
                 heap pages,
                 heap virtual,
                 heap backed,
                 filesystem fs)
{
    // is process md always root?
    process proc = create_process(general, pages, physical, md, fs);
    thread t = create_thread(proc);
    void *start = load_elf(ex, 0, pages, physical);
    u64 va;
    boolean interp = false;
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(ex, 0);

    // also pick up the maximum load address for the brk
    foreach_phdr(e, p) {
        // umm, this is passed in aux but..there might be more than one, and p_offset
        // isn't necessarily 0
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = p->p_vaddr;
    }
    
    build_exec_stack(backed, t, e, start, va, md);

        
    foreach_phdr(e, p) {
        if (p->p_type == PT_INTERP) {
            char *n = (void *)e + p->p_offset;
            tuple interp = resolve_path(root, split(general, alloca_wrap_buffer(n, runtime_strlen(n)), '/'));
            if (!interp) 
                halt("couldn't find program interpreter %s\n", n);
            filesystem_read_entire(fs, interp, backed,
                                   closure(general, load_interp_complete, t, virtual, pages, physical),
                                   closure(general, load_interp_fail));
            return proc;
        }
    }
    start_process(t, start);
    return proc;    
}

