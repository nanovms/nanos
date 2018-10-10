#include <unix_internal.h>
#include <elf64.h>
#include <gdb.h>

#define sp(__f) __f[FRAME_RSP]
#define spush(__f, __w) *(u64 *)(sp(__f) = sp(__f) - sizeof(u64)) = (u64)(__w)

#define ppush(__f, __b, __format, ...) ({buffer_clear(__b);             \
            bprintf(b, __format, __VA_ARGS__);                          \
            u64 len = pad(buffer_length(b), 64)>>3;                     \
            sp(__f) = sp(__f) - len;                                    \
            runtime_memcpy(pointer_from_u64(sp(__f)), buffer_ref(b, 0), buffer_length(b)); \
            (char *)pointer_from_u64(sp(__f));})

static void build_exec_stack(context f, heap sh, thread t, Elf64_Ehdr * e, void *start, u64 va, tuple process_root)
{
    buffer b = allocate_buffer(transient, 128);
    vector arguments = vector_from_tuple(transient, table_find(process_root, sym(arguments)));
    tuple environment = table_find(process_root, sym(environment));

    print_u64(sp(f));
    spush(f, random_u64());
    spush(f, random_u64());
    struct aux auxp[] = {
        {AT_PHDR, e->e_phoff + va},
        {AT_PHENT, e->e_phentsize},
        {AT_PHNUM, e->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_RANDOM, u64_from_pointer(sp(f))},
        {AT_ENTRY, u64_from_pointer(start)}};
    
    int auxplen = sizeof(auxp)/(2*sizeof(u64));
    int argc = 0;
    char **argv = stack_allocate(vector_length(arguments) * sizeof(u64));
    int envc = table_elements(environment);
    char **envp = stack_allocate(envc * sizeof(u64));
    buffer a;
    vector_foreach(arguments, a)  argv[argc++] = ppush(f, b, "%b\0", a);
    table_foreach(environment, n, v)  envp[envc++] = ppush(f, b, "%b=%b\0", symbol_string(n), v);
    spush(f, 0);
    spush(f, 0);
    for (int i = 0; i< auxplen; i++) {
        spush(f, auxp[i].val);
        spush(f, auxp[i].tag);
    }
    spush(f, 0);
    for (int i = 0; i< envc; i++) spush(f, envp[i]);
    spush(f, 0);
    for (int i = argc - 1 ; i >= 0; i--) spush(f, argv[i]);
    spush(f, argc);
}

void start_process(thread t, void *start)
{
    t->frame[FRAME_RIP] = u64_from_pointer(start);
    if (table_find(t->p->process_root, sym(gdb))) {
        console ("gdb!\n");
        init_tcp_gdb(heap_general(get_kernel_heaps()), t->p, 1234);
    } else {
        t->sleep_by = 0;
        enqueue(runqueue, t->run);
    }
}

static CLOSURE_0_1(load_interp_fail, void, status);
static void load_interp_fail(status s)
{
    console("interp fail\n");
    halt("read interp failed %v\n", s);
}


CLOSURE_2_1(load_interp_complete, void, thread, kernel_heaps, buffer);
void load_interp_complete(thread t, kernel_heaps kh, buffer b)
{
    u64 where = allocate_u64(heap_virtual_huge(kh), HUGE_PAGESIZE);
    start_process(t, load_elf(b, where, heap_pages(kh), heap_physical(kh)));
}

process exec_elf(buffer ex, process kp)
{
    // is process md always root?
    // set cwd
    unix_heaps uh = kp->uh;
    kernel_heaps kh = (kernel_heaps)uh;
    tuple root = kp->process_root;
    filesystem fs = kp->fs;
    process proc = create_process(uh, root, fs);

    u64 stack_size = 128*KB;
    void *s = allocate(kh->backed, stack_size);
    s += stack_size;
    thread t = create_thread(proc, s);
    void *start = load_elf(ex, 0, heap_pages(kh), heap_physical(kh));
    u64 va;
    boolean interp = false;
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(ex, 0);

    proc->brk = 0;

    foreach_phdr(e, p) {
        // umm, this is passed in aux but..there might be more than one, and p_offset
        // isn't necessarily 0...i guess this the the 'base' for dynamic
        // and aslr objects i.e. load_elf offset
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = p->p_vaddr;
        proc->brk  = pointer_from_u64(MAX(u64_from_pointer(proc->brk), pad(p->p_vaddr + p->p_memsz, PAGESIZE)));
    }
    build_exec_stack((context)t, heap_backed(kh), t, e, start, va, root);
            
    foreach_phdr(e, p) {
        if (p->p_type == PT_INTERP) {
            char *n = (void *)e + p->p_offset;
            tuple interp = resolve_path(root, split(heap_general(kh), alloca_wrap_buffer(n, runtime_strlen(n)), '/'));
            if (!interp) 
                halt("couldn't find program interpreter %s\n", n);
            filesystem_read_entire(fs, interp, heap_backed(kh),
                                   closure(heap_general(kh), load_interp_complete, t, kh),
                                   closure(heap_general(kh), load_interp_fail));
            return proc;
        }
    }
    start_process(t, start);
    // xxx - in some environments with some programs this causes
    // rtrie insert to blow the stack. fix rtrie.
    //    add_elf_syms(heap_general(kh), ex);
    return proc;    
}

