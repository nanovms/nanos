#include <unix_internal.h>
#include <elf64.h>
#include <gdb.h>
#include <symtab.h>
#include <filesystem.h>

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
            __s -= pad((buffer_length(__b) + 1), STACK_ALIGNMENT) >> 3;   \
            runtime_memcpy(__s, buffer_ref(__b, 0), buffer_length(__b));  \
            ((char *)__s)[buffer_length(__b)] = '\0';                     \
            (char *)__s;})

closure_function(4, 2, boolean, environment_each,
                 char **, envp, int *, envc, u64 **, s, buffer, b,
                 value, n, value, v)
{
    assert(is_symbol(n));
    bound(envp)[(*bound(envc))++] = ppush((*bound(s)), bound(b), "%b=%b", symbol_string(n), v);
    return true;
}

static void build_exec_stack(process p, thread t, Elf64_Ehdr * e, void *start,
        u64 va, tuple process_root, boolean aslr)
{
    exec_debug("build_exec_stack start %p, tid %d, va 0x%lx\n", start, t->tid, va);

    /* allocate process stack at top of first 2gb of address space */
    u64 stack_start = 0x80000000 - PROCESS_STACK_SIZE;
    if (aslr)
        stack_start = (stack_start - PROCESS_STACK_ASLR_RANGE) +
            get_aslr_offset(PROCESS_STACK_ASLR_RANGE);

#ifdef __x86_64__
    assert(id_heap_set_area(p->virtual32, stack_start, PROCESS_STACK_SIZE, true, true));
#endif
    p->stack_map = allocate_vmap(p->vmaps, irangel(stack_start, PROCESS_STACK_SIZE),
                                 ivmap(VMAP_FLAG_WRITABLE, 0, 0, 0));
    assert(p->stack_map != INVALID_ADDRESS);

    u64 * s = pointer_from_u64(stack_start);
    u64 sphys = allocate_u64((heap)heap_physical(get_kernel_heaps()), PROCESS_STACK_SIZE);
    assert(sphys != INVALID_PHYSICAL);

    exec_debug("stack allocated at %p, size 0x%lx, phys 0x%lx\n", s, PROCESS_STACK_SIZE, sphys);
    map(u64_from_pointer(s), sphys, PROCESS_STACK_SIZE,
        pageflags_writable(pageflags_default_user()));

    s += PROCESS_STACK_SIZE >> 3;

    // argv ASCIIZ strings
    vector arguments = vector_from_tuple(transient, get(process_root, sym(arguments)));
    if (!arguments)
        arguments = allocate_vector(transient, 1);

    if (vector_length(arguments) == 0) {
        value p = get(process_root, sym(program));
        assert(p);
        vector_push(arguments, p);
    }

    char **argv = stack_allocate(vector_length(arguments) * sizeof(u64));
    buffer a;
    int argv_len = 0;
    vector_foreach(arguments, a) {
        argv_len += buffer_length(a) + 1;
    }
    s -= pad(argv_len, STACK_ALIGNMENT) >> 3;
    int argc = 0;
    char * sp = (char *) s;
    vector_foreach(arguments, a) {
        int len = buffer_length(a);
        runtime_memcpy(sp, buffer_ref(a, 0), len);
        sp[len] = '\0';
        argv[argc++] = sp;
        sp += len + 1;
    }
    deallocate_vector(arguments);

    // envp ASCIIZ strings
    char **envp = 0;
    int envc = 0;
    tuple environment = get_tuple(process_root, sym(environment));
    if (environment) {
        envp = stack_allocate(tuple_count(environment) * sizeof(u64));
        buffer b = allocate_buffer(transient, 128);
        iterate(environment, stack_closure(environment_each, envp, &envc, &s, b));
    }

    // stack padding
    if ((envc + 1 + argc + 1 + 1) % 2 == 1) {
        spush(s, 0);
    }

    // auxiliary vector
    struct aux auxp[] = {
        {AT_NULL, 0},
        {AT_PHDR, e->e_phoff + va},
        {AT_PHENT, e->e_phentsize},
        {AT_PHNUM, e->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_RANDOM, u64_from_pointer(s)},
        {AT_ENTRY, u64_from_pointer(start)},
#ifdef __aarch64__
        /* This is aarch64 specific because it's needed for arm .so search paths */
        {AT_HWCAP, get_cpu_capabilities()},
#endif
        {AT_SYSINFO_EHDR, p->vdso_base}
    };
    for (int i = 0; i < sizeof(auxp) / sizeof(auxp[0]); i++) {
        spush(s, auxp[i].val);
        spush(s, auxp[i].tag);
    }

    // envp
    spush(s, 0);
    for (int i = envc - 1; i >= 0; i--)
        spush(s, envp[i]);

    // argv
    spush(s, 0);
    for (int i = argc - 1; i >= 0; i--)
        spush(s, argv[i]);

    // argc
    spush(s, argc);

    // stack should be 16-byte aligned
    assert(pad(u64_from_pointer(s), STACK_ALIGNMENT) == u64_from_pointer(s));

    frame_set_stack(thread_frame(t), u64_from_pointer(s));
}

void start_process(thread t, void *start)
{
    thread_frame(t)[SYSCALL_FRAME_PC] = u64_from_pointer(start);
    if (get(t->p->process_root, sym(gdb))) {
        rputs("NOTE: in-kernel gdb is a work in progress\n");
        init_tcp_gdb(heap_locked(get_kernel_heaps()), t->p, 9090);
    } else {
        schedule_thread(t);
    }
}

closure_function(0, 1, void, load_interp_fail,
                 status, s)
{
    rputs("interp fail\n");
    closure_finish();
    halt("read interp failed %v\n", s);
}

closure_function(3, 4, u64, exec_elf_map,
                 process, p, kernel_heaps, kh, u32, allowed_flags,
                 u64, vaddr, u64, paddr, u64, size, pageflags, flags)
{
    kernel_heaps kh = bound(kh);
    u64 vmflags = 0;
    if (pageflags_is_exec(flags))
        vmflags |= VMAP_FLAG_EXEC;
    if (pageflags_is_writable(flags))
        vmflags |= VMAP_FLAG_WRITABLE;

    range r = irangel(vaddr, size);
    boolean is_bss = paddr == INVALID_PHYSICAL;
    exec_debug("%s: add to vmap: %R vmflags 0x%lx%s\n",
               __func__, r, vmflags, is_bss ? " bss" : "");
    assert(allocate_vmap(bound(p)->vmaps, r, ivmap(vmflags, bound(allowed_flags), 0, 0)) !=
            INVALID_ADDRESS);
    if (is_bss) {
        /* bss */
        paddr = allocate_u64((heap)heap_physical(kh), size);
        assert(paddr != INVALID_PHYSICAL);
    }
    map(vaddr, paddr, size, pageflags_user(pageflags_minpage(flags)));
    if (is_bss)
        zero(pointer_from_u64(vaddr), size);
    return vaddr;
}

closure_function(2, 1, status, load_interp_complete,
                 thread, t, kernel_heaps, kh,
                 buffer, b)
{
    thread t = bound(t);
    kernel_heaps kh = bound(kh);

    exec_debug("interpreter load complete, reading elf\n");
    u64 where = process_get_virt_range(t->p, HUGE_PAGESIZE);
    assert(where != INVALID_PHYSICAL);
    void * start = load_elf(b, where, stack_closure(exec_elf_map, t->p, kh, 0));
    exec_debug("starting process tid %d, start %p\n", t->tid, start);
    start_process(t, start);
    closure_finish();
    return STATUS_OK;
}

closure_function(1, 1, boolean, trace_notify,
                 process, p,
                 value, v)
{
    bound(p)->trace = !!v;      /* allow any value for true */
    return true;
}

process exec_elf(buffer ex, process kp)
{
    // is process md always root?
    unix_heaps uh = kp->uh;
    kernel_heaps kh = (kernel_heaps)uh;
    tuple root = kp->process_root;
    filesystem fs = kp->root_fs;
    process proc = create_process(uh, root, fs);
    thread t = create_thread(proc);
    tuple interp = 0;
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(ex, 0);
    boolean aslr = get(root, sym(noaslr)) == 0;

    proc->brk = 0;

    exec_debug("exec_elf enter\n");

    range load_range = irange(infinity, 0);
    foreach_phdr(e, p) {
        if (p->p_type == PT_INTERP) {
            char *n = (void *)e + p->p_offset;
            interp = resolve_path(root, split(heap_locked(kh), alloca_wrap_buffer(n, runtime_strlen(n)), '/'));
            if (!interp) 
                halt("couldn't find program interpreter %s\n", n);
        } else if (p->p_type == PT_LOAD) {
            if (p->p_vaddr < load_range.start)
                load_range.start = p->p_vaddr;
            u64 segend = p->p_vaddr + p->p_memsz;
            if (segend > load_range.end)
                load_range.end = segend;
        }
    }

    exec_debug("range of loadable segments prior to adjustment: %R\n", load_range);

    if (interp)
        exec_debug("interp: %v\n", interp);

    u64 load_offset = 0;
    if (e->e_type == ET_DYN && interp) {
        /* Have some PIE */
        load_offset = DEFAULT_PROG_ADDR;
        if (aslr) {
            load_offset += get_aslr_offset(PROCESS_PIE_LOAD_ASLR_RANGE);
        }
        exec_debug("placing PIE at 0x%lx\n", load_offset);
        load_range = range_add(load_range, load_offset);
    }

    if (load_range.end > PROCESS_ELF_LOAD_END) {
        halt("exec_elf failed: elf segment load range (%R) exceeds hard limit 0x%lx\n",
             load_range, PROCESS_ELF_LOAD_END);
    }

    exec_debug("offset 0x%lx, range after adjustment: %R, span 0x%lx\n",
               load_offset, load_range, range_span(load_range));
    u32 allowed_flags = proc_is_exec_protected(proc) ? 0 :
            (VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC);
    void * entry = load_elf(ex, load_offset, stack_closure(exec_elf_map, proc, kh, allowed_flags));

    u64 brk_offset = aslr ? get_aslr_offset(PROCESS_HEAP_ASLR_RANGE) : 0;
    u64 brk = pad(load_range.end, PAGESIZE) + brk_offset;
    proc->brk = pointer_from_u64(brk);
    proc->heap_base = brk;
    proc->heap_map = allocate_vmap(proc->vmaps, irange(brk, brk),
        ivmap(VMAP_FLAG_WRITABLE, 0, 0, 0));
    assert(proc->heap_map != INVALID_ADDRESS);
    exec_debug("entry %p, brk %p (offset 0x%lx)\n", entry, proc->brk, brk_offset);

    /* XXX temporarily disable because it breaks ftrace. Will need to 
       eventually deal with this for issue #1269 */
    //current_cpu()->current_thread = (nanos_thread)t;
    build_exec_stack(proc, t, e, entry, load_range.start, root, aslr);

    if (get(proc->process_root, sym(ingest_program_symbols))) {
        exec_debug("ingesting symbols...\n");
        add_elf_syms(ex, load_offset);
        exec_debug("...done\n");
    }

    register_root_notify(sym(trace), closure(heap_locked(kh), trace_notify, proc));

    if (interp) {
        exec_debug("reading interp...\n");
        filesystem_read_entire(fs, interp, (heap)heap_page_backed(kh),
                               closure(heap_locked(kh), load_interp_complete, t, kh),
                               closure(heap_locked(kh), load_interp_fail));
        return proc;
    }

    /* current needs to be valid for further setup */

    // really? if so, we could make a dummy syscall_context
    // set_current_thread(&t->thrd);

    string cwd = get_string(root, sym(cwd));
    if (cwd) {
        buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
        fs_status fss = filesystem_chdir(proc, cstring(cwd, tmpbuf));
        if (fss != FS_STATUS_OK)
            halt("unable to change cwd to \"%b\"; %s\n", cwd, string_from_fs_status(fss));
    }

    exec_debug("starting process...\n");
    start_process(t, entry);
    return proc;    
}

