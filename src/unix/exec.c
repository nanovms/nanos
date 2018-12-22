#include <unix_internal.h>
#include <elf64.h>
#include <gdb.h>

//#define EXEC_DEBUG
#ifdef EXEC_DEBUG
#define exec_debug(x, ...) do {log_printf("EXEC", x, ##__VA_ARGS__);} while(0)
#else
#define exec_debug(x, ...)
#endif

#define DEFAULT_PROG_ADDR       0x400000

#define spush(__s, __w) *((--(__s))) = (u64)(__w)

#define ppush(__s, __b, __f, ...) ({buffer_clear(__b);\
            bprintf(__b, __f, __VA_ARGS__);                               \
            __s -= pad((buffer_length(__b) + 1) * 8, 64)>>6;              \
            runtime_memcpy(__s, buffer_ref(__b, 0), buffer_length(__b));  \
            ((char *)__s)[buffer_length(__b)] = '\0';                     \
            (char *)__s;})

static void build_exec_stack(heap sh, thread t, Elf64_Ehdr * e, void *start, u64 va, tuple process_root)
{
    exec_debug("build exec stack start %p, root %v\n", start, process_root);
    buffer b = allocate_buffer(transient, 128);
    vector arguments = vector_from_tuple(transient, table_find(process_root, sym(arguments)));
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
    int argc = 0;
    char **argv = stack_allocate(vector_length(arguments) * sizeof(u64));
    int envc = table_elements(environment);
    char **envp = stack_allocate(envc * sizeof(u64));
    envc = 0;
    buffer a;
    int argv_len = 0;
    vector_foreach(arguments, a) {
        argv_len += buffer_length(a) + 1;
    }
    s -= pad(argv_len * 8, 64)>>6;
    char *p = (char *) s;
    vector_foreach(arguments, a) {
        int len = buffer_length(a);
        runtime_memcpy(p, buffer_ref(a, 0), len);
        p[len] = '\0';
        argv[argc++] = p;
        p += len + 1;
    }
    table_foreach(environment, n, v)  envp[envc++] = ppush(s, b, "%b=%b", symbol_string(n), v);
    spush(s, 0);
    spush(s, 0);
    
    for (int i = 0; i< auxplen; i++) {
        spush(s, auxp[i].val);
        spush(s, auxp[i].tag);
    }
    spush(s, 0);
    for (int i = envc - 1; i >= 0; i--) spush(s, envp[i]);
    spush(s, 0);
    for (int i = argc - 1; i >= 0; i--) spush(s, argv[i]);
    spush(s, argc);

    t->frame[FRAME_RSP] = u64_from_pointer(s);
}

void start_process(thread t, void *start)
{
    t->frame[FRAME_RIP] = u64_from_pointer(start);
    
    if (table_find(t->p->process_root, sym(gdb))) {
        console ("gdb!\n");
        init_tcp_gdb(heap_general(get_kernel_heaps()), t->p, 9090);
    } else {
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
    thread t = create_thread(proc);
    tuple interp = 0;
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(ex, 0);

    proc->brk = 0;

    exec_debug("exec_elf enter\n");

    u64 load_start = infinity;
    u64 load_end = 0;
    foreach_phdr(e, p) {
        if (p->p_type == PT_INTERP) {
            char *n = (void *)e + p->p_offset;
            interp = resolve_path(root, split(heap_general(kh), alloca_wrap_buffer(n, runtime_strlen(n)), '/'));
            if (!interp) 
                halt("couldn't find program interpreter %s\n", n);
        } else if (p->p_type == PT_LOAD) {
            if (p->p_vaddr < load_start)
                load_start = p->p_vaddr;
            u64 segend = p->p_vaddr + p->p_memsz;
            if (segend > load_end)
                load_end = segend;
        }
    }

    if (interp)
        exec_debug("interp: %t\n", interp);

    u64 load_offset = 0;
    if (e->e_type == ET_DYN && interp) {
        /* Have some PIE */
        load_offset = DEFAULT_PROG_ADDR;
        if (table_find(root, sym(aslr))) {
            /* XXX Make random_u64() suck less.
               XXX Replace 27 with limit derived from kernel start. */
            load_offset += (random_u64() & ~MASK(PAGELOG)) & MASK(27);
        }
        exec_debug("placing PIE at 0x%P\n", load_offset);
        load_start += load_offset;
        load_end += load_offset;
    }

    exec_debug("load start 0x%P, end 0x%P, offset 0x%P\n",
               load_start, load_end, load_offset);
    void * entry = load_elf(ex, load_offset, heap_pages(kh), heap_physical(kh));
    proc->brk = pointer_from_u64(pad(load_end, PAGESIZE));
    exec_debug("entry 0x%P, brk 0x%p\n", entry, proc->brk);
    build_exec_stack(heap_backed(kh), t, e, entry, load_start, root);

    if (interp) {
        exec_debug("reading interp...\n");
        filesystem_read_entire(fs, interp, heap_backed(kh),
                               closure(heap_general(kh), load_interp_complete, t, kh),
                               closure(heap_general(kh), load_interp_fail));
        return proc;
    }

    exec_debug("starting process...\n");
    start_process(t, entry);
    // xxx - in some environments with some programs this causes
    // rtrie insert to blow the stack. fix rtrie.
    //    add_elf_syms(heap_general(kh), ex);
    return proc;    
}

