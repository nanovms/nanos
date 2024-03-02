#include <unix_internal.h>
#include <elf64.h>
#include <gdb.h>
#include <symtab.h>
#include <filesystem.h>
#include <ltrace.h>

//#define EXEC_DEBUG
#ifdef EXEC_DEBUG
#define exec_debug(x, ...) do {tprintf(sym(exec), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define exec_debug(x, ...)
#endif

#define DEFAULT_PROG_ADDR       0x400000

static void *stack_prealloc(void *start, u64 size)
{
    u64 sphys = allocate_u64((heap)heap_physical(get_kernel_heaps()), size);
    assert(sphys != INVALID_PHYSICAL);
    start -= size;
    exec_debug("stack prealloc at %p, size 0x%lx, phys 0x%lx\n", start, size, sphys);
    map(u64_from_pointer(start), sphys, size, pageflags_writable(pageflags_default_user()));
    return start;
}

#define check_s(__s, __a) do { if ((void*)(__s) < (__a))                \
            (__a) = stack_prealloc((__a), pad((__a) - (void*)(__s), PAGESIZE)); } while(0);

#define spush(__s, __a, __w) do { (__s)--; check_s((__s), (__a)); *(__s) = (u64)(__w); } while(0)

#define ppush(__s, __a, __b, __f, ...) ({buffer_clear(__b);             \
            bprintf((__b), (__f), __VA_ARGS__);                         \
            (__s) -= pad((buffer_length(__b) + 1), STACK_ALIGNMENT) >> 3; \
            check_s((__s), (__a));                                      \
            runtime_memcpy((__s), buffer_ref((__b), 0), buffer_length(__b)); \
            ((char *)(__s))[buffer_length(__b)] = '\0';                 \
            (char *)(__s);})

closure_function(5, 2, boolean, environment_each,
                 char **, envp, int *, envc, u64 **, s, void **, a, buffer, b,
                 value n, value v)
{
    assert(is_symbol(n));
    bound(envp)[(*bound(envc))++] = ppush(*bound(s), *bound(a), bound(b), "%b=%b", symbol_string(n), v);
    return true;
}

closure_function(1, 2, boolean, fill_arguments_each,
                 vector, r,
                 value a, value v)
{
    u64 i;
    if (!u64_from_attribute(a, &i)) {
        msg_err("arguments attribute %v is not an index\n", a);
        return false;
    }
    vector_set(bound(r), i, v);
    return true;
}

static void build_exec_stack(process p, thread t, Elf64_Ehdr * e, void *start,
        u64 va, u64 interp_load_addr, tuple process_root, boolean aslr)
{
    exec_debug("build_exec_stack start %p, tid %d, va 0x%lx\n", start, t->tid, va);

    /* allocate process stack at top of 32-bit address space */
    u64 stack_start = 0x100000000 - PROCESS_STACK_SIZE;
    if (aslr)
        stack_start = (stack_start - PROCESS_STACK_ASLR_RANGE) +
            get_aslr_offset(PROCESS_STACK_ASLR_RANGE);

    p->stack_map = allocate_vmap(p, irangel(stack_start, PROCESS_STACK_SIZE),
                                 ivmap(VMAP_FLAG_STACK | VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE,
                                       0, 0, 0, 0));
    assert(p->stack_map != INVALID_ADDRESS);

    u64 *s = (pointer_from_u64(stack_start) + PROCESS_STACK_SIZE);
    void *as = stack_prealloc((void*)s, PROCESS_STACK_PREALLOC_SIZE);

    /* 16 bytes of random data for userspace (e.g. SSP guard init) */
    for (int i = 0; i < 2; i++) {
        s -= sizeof(u64);
        *(u64 *)s = random_u64();
    }
    u64 *randbuf = s;

    // argv ASCIIZ strings
    value arg_value = get(process_root, sym(arguments));
    vector arguments;
    if (is_vector(arg_value)) {
        arguments = arg_value;
    } else {
        if (is_tuple(arg_value)) {
            arguments = allocate_vector(transient, tuple_count(arg_value));
            if (!iterate(arg_value, stack_closure(fill_arguments_each, arguments)))
                halt("failed to parse program arguments\n");
        } else if (!arg_value) {
            arguments = allocate_vector(transient, 1);
        } else {
            halt("program arguments must be a vector or tuple\n");
        }
    }
    if (vector_length(arguments) == 0) {
        value p = get(process_root, sym(program));
        assert(p);
        vector_push(arguments, p);
    }

    char **argv = stack_allocate(vector_length(arguments) * sizeof(u64));
    buffer a;
    int argv_len = 0;
    vector_foreach(arguments, a) {
        if (a)
            argv_len += buffer_length(a) + 1;
    }
    s -= pad(argv_len, STACK_ALIGNMENT) >> 3;
    check_s(s, as);
    int argc = 0;
    char * sp = (char *) s;
    p->saved_args_begin = sp;
    vector_foreach(arguments, a) {
        if (!a)
            continue;
        int len = buffer_length(a);
        runtime_memcpy(sp, buffer_ref(a, 0), len);
        sp[len] = '\0';
        argv[argc++] = sp;
        sp += len + 1;
    }
    p->saved_args_end = sp;
    if (arguments != arg_value)
        deallocate_vector(arguments);

    // envp ASCIIZ strings
    char **envp = 0;
    int envc = 0;
    tuple environment = get_tuple(process_root, sym(environment));
    if (environment) {
        envp = stack_allocate(tuple_count(environment) * sizeof(u64));
        buffer b = allocate_buffer(transient, 128);
        iterate(environment, stack_closure(environment_each, envp, &envc, &s, &as, b));
    }

    // stack padding
    if ((envc + 1 + argc + 1 + 1) % 2 == 1) {
        spush(s, as, 0);
    }

    // auxiliary vector
    struct aux auxp[] = {
        {AT_NULL, 0},
        {AT_PHDR, e->e_phoff + va},
        {AT_PHENT, e->e_phentsize},
        {AT_PHNUM, e->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_BASE, interp_load_addr},
        {AT_RANDOM, u64_from_pointer(randbuf)},
        {AT_ENTRY, u64_from_pointer(start)},
#ifdef __aarch64__
        /* This is aarch64 specific because it's needed for arm .so search paths */
        {AT_HWCAP, get_cpu_capabilities()},
#endif
#if defined(__x86_64__)
        {AT_HWCAP2, get_hwcap2()},
#endif
        {AT_SYSINFO_EHDR, p->vdso_base}
    };
    for (int i = 0; i < sizeof(auxp) / sizeof(auxp[0]); i++) {
        spush(s, as, auxp[i].val);
        spush(s, as, auxp[i].tag);
    }
    runtime_memcpy(p->saved_aux, s, MIN(sizeof(auxp), sizeof(p->saved_aux)));

    // envp
    spush(s, as, 0);
    for (int i = envc - 1; i >= 0; i--)
        spush(s, as, envp[i]);

    // argv
    spush(s, as, 0);
    for (int i = argc - 1; i >= 0; i--)
        spush(s, as, argv[i]);

    // argc
    spush(s, as, argc);

    // stack should be 16-byte aligned
    assert(pad(u64_from_pointer(s), STACK_ALIGNMENT) == u64_from_pointer(s));

    frame_set_stack(thread_frame(t), u64_from_pointer(s));
}

void start_process(thread t, void *start)
{
    thread_frame(t)[SYSCALL_FRAME_PC] = u64_from_pointer(start);
    thread_frame(t)[FRAME_FULL] = true;
    thread_reserve(t);
    if (get(t->p->process_root, sym(gdb))) {
        rputs("NOTE: in-kernel gdb is a work in progress\n");
        init_tcp_gdb(heap_locked(get_kernel_heaps()), t->p, 9090);
    } else {
        schedule_thread(t);
    }
}

closure_function(4, 5, boolean, static_map,
                 process, p, kernel_heaps, kh, u32, allowed_flags, buffer, b,
                 u64 vaddr, u64 offset, u64 data_size, u64 bss_size, pageflags flags)
{
    exec_debug("%s: vaddr 0x%lx, offset 0x%lx, data_size 0x%lx, bss_size 0x%lx, flags 0x%lx\n",
               func_ss, vaddr, offset, data_size, bss_size, flags);
    u64 map_start = vaddr & ~PAGEMASK;
    data_size += vaddr & PAGEMASK;

    u64 tail_copy = bss_size > 0 ? data_size & PAGEMASK : 0;
    if (tail_copy > 0)
        data_size -= tail_copy;
    else
        data_size = pad(data_size, PAGESIZE);

    offset &= ~PAGEMASK;
    if (data_size > 0) {
        u64 paddr = physical_from_virtual(buffer_ref(bound(b), offset));
        u64 vmflags = VMAP_FLAG_READABLE | VMAP_FLAG_PROG;
        if (pageflags_is_exec(flags))
            vmflags |= VMAP_FLAG_EXEC;
        if (pageflags_is_writable(flags))
            vmflags |= VMAP_FLAG_WRITABLE;
        range r = irangel(map_start, data_size);
        exec_debug("   add %s to vmap: %R vmflags 0x%lx, paddr 0x%lx\n",
                   pageflags_is_exec(flags) ? ss("text") : ss("data"), r, vmflags, paddr);
        struct vmap k = ivmap(vmflags, bound(allowed_flags), 0, 0, 0);
        if (allocate_vmap(bound(p), r, k) == INVALID_ADDRESS)
            goto alloc_fail;
        map(map_start, paddr, data_size, pageflags_user(pageflags_minpage(flags)));
        map_start += data_size;
    }
    if (bss_size > 0) {
        u64 maplen = pad(bss_size + tail_copy, PAGESIZE);
        u64 paddr = allocate_u64((heap)heap_physical(bound(kh)), maplen);
        if (paddr == INVALID_PHYSICAL)
            goto alloc_fail;
        map(map_start, paddr, maplen, pageflags_user(pageflags_minpage(flags)));
        u64 vmflags = VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE | VMAP_FLAG_BSS;
        range r = irangel(map_start, maplen);
        exec_debug("   add bss vmap: %R vmflags 0x%lx\n", r, vmflags);
        struct vmap k = ivmap(vmflags, bound(allowed_flags), 0, 0, 0);
        if (allocate_vmap(bound(p), r, k) == INVALID_ADDRESS)
            goto alloc_fail;
        if (tail_copy > 0) {
            void *src = buffer_ref(bound(b), offset + data_size);
            exec_debug("   tail copy at 0x%lx, %ld bytes, offset 0x%lx, from %p\n",
                       map_start, tail_copy, data_size, src);
            runtime_memcpy(pointer_from_u64(map_start), src, tail_copy);
        }
        exec_debug("   zero at 0x%lx, len 0x%lx\n", map_start + tail_copy, maplen - tail_copy);
        zero(pointer_from_u64(map_start + tail_copy), maplen - tail_copy);
    }
    return true;
  alloc_fail:
    msg_err("failed to allocate interp vmap\n");
    return false;
}

closure_function(4, 5, boolean, faulting_map,
                 process, p, kernel_heaps, kh, u32, allowed_flags, fsfile, f,
                 u64 vaddr, u64 offset, u64 data_size, u64 bss_size, pageflags flags)
{
    exec_debug("%s: vaddr 0x%lx, offset 0x%lx, data_size 0x%lx, bss_size 0x%lx, flags 0x%lx\n",
               func_ss, vaddr, offset, data_size, bss_size, flags);
    u64 map_start = vaddr & ~PAGEMASK;
    if (data_size > 0) {
        offset &= ~PAGEMASK;
        data_size += vaddr & PAGEMASK;
        u64 data_map_size = pad(data_size, PAGESIZE);
        u64 tail_bss = MIN(data_map_size - data_size, bss_size);
        u64 vmflags = VMAP_FLAG_READABLE | VMAP_FLAG_PROG;
        if (pageflags_is_exec(flags))
            vmflags |= VMAP_FLAG_EXEC;
        if (pageflags_is_writable(flags))
            vmflags |= VMAP_FLAG_WRITABLE;
        if (tail_bss > 0)
            vmflags |= VMAP_FLAG_TAIL_BSS;
        range r = irangel(map_start, data_map_size);
        exec_debug("%s: add %s to vmap: %R vmflags 0x%lx, offset 0x%lx, data_size 0x%lx, tail_bss 0x%lx\n",
                   func_ss, pageflags_is_exec(flags) ? ss("text") : ss("data"),
                   r, vmflags, offset, data_size, tail_bss);
        struct vmap k = ivmap(vmflags, bound(allowed_flags), offset,
                              fsfile_get_cachenode(bound(f)), 0);
        if (tail_bss > 0)
            k.bss_offset = data_size;
        if (allocate_vmap(bound(p), r, k) == INVALID_ADDRESS)
            goto alloc_fail;
        map_start += data_map_size;
        bss_size -= tail_bss;
    }
    if (bss_size > 0) {
        u64 vmflags = VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE | VMAP_FLAG_BSS;
        range r = irangel(map_start, pad(bss_size, PAGESIZE));
        exec_debug("%s: add bss vmap: %R vmflags 0x%lx\n", func_ss, r, vmflags);
        struct vmap k = ivmap(vmflags, bound(allowed_flags), 0, 0, 0);
        if (allocate_vmap(bound(p), r, k) == INVALID_ADDRESS)
            goto alloc_fail;
    }
    return true;
  alloc_fail:
    msg_err("failed to allocate vmap\n");
    return false;
}

closure_function(7, 2, void, load_interp_complete,
                 thread, t, kernel_heaps, kh, buffer, b, fsfile, f, u64, load_addr, boolean, static_map, boolean, ingest_symbols,
                 status s, bytes length)
{
    thread t = bound(t);
    process p = t->p;
    kernel_heaps kh = bound(kh);
    buffer b = bound(b);

    if (!is_ok(s))
        halt("read interp failed %v\n", s);
    exec_debug("interpreter load complete, length %ld, reading elf\n", length);
    buffer_produce(b, length);
    u64 where = bound(load_addr);
    if (bound(ingest_symbols)) {
        exec_debug("ingesting interp symbols\n");
        add_elf_syms(b, where);
    }
    elf_map_handler emh;
    if (bound(static_map))
        emh = stack_closure(static_map, p, kh, 0, b);
    else
        emh = stack_closure(faulting_map, p, kh, 0, bound(f));
    void *start = load_elf(b, where, emh);
    if (!bound(static_map))
        deallocate_buffer(b);
    exec_debug("starting process tid %d, start %p\n", t->tid, start);
    start_process(t, start);
    closure_finish();
}

closure_function(1, 1, boolean, trace_notify,
                 process, p,
                 value v)
{
    bound(p)->trace = trace_get_flags(v);
    return true;
}

static void exec_elf_finish(buffer ex, fsfile f, process kp,
                            range load_range, sstring interp_path, boolean ingest_symbols,
                            status_handler complete)
{
    status s = STATUS_OK;
    unix_heaps uh = kp->uh;
    tuple root = kp->process_root;
    filesystem fs = kp->root_fs;
    kernel_heaps kh = (kernel_heaps)uh;
    process proc = create_process(uh, root, fs);
    thread t = create_thread(proc, proc->pid);
    fsfile interp;
    u64 interp_load_addr;
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(ex, 0);
    boolean aslr = get(root, sym(noaslr)) == 0;
    heap general = heap_locked(kh);

    exec_debug("exec_elf enter\n");

    if (!sstring_is_null(interp_path)) {
        interp = fsfile_open(interp_path);
        if (!interp) {
            s = timm("result", "couldn't find program interpreter %s", interp_path);
            goto out;
        }
        interp_load_addr = process_get_virt_range(proc, HUGE_PAGESIZE, PROCESS_VIRTUAL_MMAP_RANGE);
        exec_debug("interp: %p\n", interp);
    } else {
        interp = 0;
        interp_load_addr = 0;
    }
    exec_debug("range of loadable segments prior to adjustment: %R\n", load_range);

    u64 load_offset = 0;
    if (e->e_type == ET_DYN) {
        /* Have some PIE */
        load_offset = DEFAULT_PROG_ADDR;
        if (aslr) {
            load_offset += get_aslr_offset(PROCESS_PIE_LOAD_ASLR_RANGE);
        }
        exec_debug("placing PIE at 0x%lx\n", load_offset);
        load_range = range_add(load_range, load_offset);
    }

    if (load_range.end > PROCESS_ELF_LOAD_END) {
        s = timm("result", "exec_elf failed: elf segment load range (%R) exceeds hard limit 0x%lx",
             load_range, PROCESS_ELF_LOAD_END);
        goto out;
    }

    exec_debug("offset 0x%lx, range after adjustment: %R, span 0x%lx\n",
               load_offset, load_range, range_span(load_range));
    u32 allowed_flags = proc_is_exec_protected(proc) ? 0 :
            (VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC);
    elf_map_handler emh;
    boolean static_map = get(proc->process_root, sym(ltrace)) ||
        get(proc->process_root, sym(static_map_program));
    if (static_map)
        emh = stack_closure(static_map, proc, kh, allowed_flags, ex);
    else
        emh = stack_closure(faulting_map, proc, kh, allowed_flags, f);
    void * entry = load_elf(ex, load_offset, emh);
    u64 brk_offset = aslr ? get_aslr_offset(PROCESS_HEAP_ASLR_RANGE) : 0;
    u64 brk = pad(load_range.end, PAGESIZE) + brk_offset;
    proc->brk = pointer_from_u64(brk);
    proc->heap_base = brk;
    proc->heap_map = allocate_vmap(proc, irange(brk, brk),
                                   ivmap(VMAP_FLAG_HEAP | VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE,
                                         0, 0, 0, 0));
    assert(proc->heap_map != INVALID_ADDRESS);
    exec_debug("entry %p, brk %p (offset 0x%lx)\n", entry, proc->brk, brk_offset);

    /* XXX temporarily disable because it breaks ftrace. Will need to 
       eventually deal with this for issue #1269 */
    //current_cpu()->current_thread = (nanos_thread)t;
    build_exec_stack(proc, t, e, entry, load_range.start, interp_load_addr, root, aslr);

    if (ingest_symbols) {
        exec_debug("ingesting program symbols\n");
        add_elf_syms(ex, load_offset);
    }

    value ltrace = get(proc->process_root, sym(ltrace));
    if (ltrace) {
        exec_debug("initializing ltrace...\n");
        ltrace_init(ltrace, ex, load_offset);
    }

    register_root_notify(sym(trace), closure(heap_locked(kh), trace_notify, proc));

    if (interp) {
        program_set_perms(root, interp->md);
        exec_debug("reading interp...\n");
        /* check if we neeed a full program read */
        boolean load_entire = static_map || ingest_symbols;
        u64 length = load_entire ? fsfile_get_length(interp) : ELF_PROGRAM_LOAD_MIN_SIZE;
        buffer b = allocate_buffer(general, pad(length, PAGESIZE));
        assert(b != INVALID_ADDRESS);
        io_status_handler sh = closure(general, load_interp_complete, t, kh, b,
                                       interp, interp_load_addr, static_map, ingest_symbols);
        filesystem_read_linear(interp, buffer_ref(b, 0), irangel(0, length), sh);
        goto out;
    }

    string cwd = get_string(root, sym(cwd));
    if (cwd) {
        fs_status fss = filesystem_chdir(proc, buffer_to_sstring(cwd));
        if (fss != FS_STATUS_OK) {
            s = timm("result", "unable to change cwd to \"%b\"; %s", cwd, string_from_fs_status(fss));
            goto out;
        }
    }

    if (!static_map)
        deallocate_buffer(ex);
    exec_debug("starting process tid %d, start %p\n", t->tid, entry);
    start_process(t, entry);
  out:
    apply(complete, s);
}

static boolean elf_check_extend(u64 req_len, fsfile f, buffer b, io_status_handler self)
{
    u64 curr = buffer_length(b);
    exec_debug("%s: req_len %ld, curr %ld\n", func_ss, req_len, curr);
    if (req_len <= curr)
        return false;
    u64 readlen = req_len - curr;
    assert(buffer_extend(b, readlen));
    exec_debug("%s: curr %ld, readlen %ld\n", func_ss, curr, readlen);
    filesystem_read_linear(f, buffer_ref(b, curr), irangel(curr, readlen), self);
    return true;
}

closure_function(4, 2, void, exec_elf_read,
                 fsfile, f, buffer, b, process, kp, status_handler, complete,
                 status s, bytes length)
{
    fsfile f = bound(f);
    buffer b = bound(b);
    process kp = bound(kp);
    status_handler complete = bound(complete);
    exec_debug("%s: status %v, read %ld bytes\n", func_ss, s, length);
    if (!is_ok(s)) {
        apply(complete, timm_up(s, "result", "failed to read elf file"));
        closure_finish();
        return;
    }
    buffer_produce(b, length);
    exec_debug("buffer length %ld\n", buffer_length(b));
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(b, 0);
    sstring interp_path = sstring_null();
    boolean ingest_symbols = !!get(kp->process_root, sym(ingest_program_symbols));

    /* This procedure will repeat until we have all the ELF info we need. */
    range load_range = irange(infinity, 0);
    foreach_phdr(e, p) {
        if ((p->p_type == PT_INTERP) && (p->p_filesz > 0)) {
            interp_path = isstring((void *)e + p->p_offset,
                                   p->p_filesz - 1  /* the last byte is the string terminator */);
            exec_debug("interp offset p->p_offset %ld, p->p_filesz %ld\n", p->p_offset, p->p_filesz);
            if (elf_check_extend(p->p_offset + p->p_filesz, f, b, (io_status_handler)closure_self()))
                return;
        } else if (p->p_type == PT_LOAD) {
            if (p->p_vaddr < load_range.start)
                load_range.start = p->p_vaddr;
            u64 segend = p->p_vaddr + p->p_memsz;
            if (segend > load_range.end)
                load_range.end = segend;
        }
    }
    if (ingest_symbols) {
        if (elf_check_extend(e->e_shoff + (e->e_shnum * e->e_shentsize), f, b,
                             (io_status_handler)closure_self()))
            return;
        u64 req_size = 0;
        foreach_shdr(e, shdr) {
            if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_STRTAB) {
                u64 sz = shdr->sh_offset + shdr->sh_size;
                if (sz > req_size)
                    req_size = sz;
            }
        }
        if (elf_check_extend(req_size, f, b, (io_status_handler)closure_self()))
            return;
    }
    exec_debug("finished reading ELF data, buffer length %ld\n", buffer_length(b));
    closure_finish();
    exec_elf_finish(b, f, kp, load_range, interp_path, ingest_symbols, complete);
}

void exec_elf(process kp, string program_path, status_handler complete)
{
    exec_debug("%s: path \"%b\", complete %p (%F)\n", func_ss, program_path, complete, complete);
    kernel_heaps kh = (kernel_heaps)(kp->uh);
    heap general = heap_locked(kh);
    tuple root = kp->process_root;
    fsfile f = fsfile_open(buffer_to_sstring(program_path));
    if (!f) {
        apply(complete, timm("result", "unable to open program file %v", program_path));
        return;
    }

    /* any of these options force a full program read */
    boolean static_map = get(root, sym(ltrace)) || get(root, sym(static_map_program));
    u64 length = static_map ? fsfile_get_length(f) : ELF_PROGRAM_LOAD_MIN_SIZE;
    u64 alloc = pad(length, PAGESIZE);
    buffer b = allocate_buffer(general, alloc);
    if (b == INVALID_ADDRESS) {
        apply(complete, timm("result", "unable to allocate memory for program read"));
        return;
    }
    if (static_map && alloc > length) {
        /* clear area past unaligned end */
        zero(buffer_ref(b, length), alloc - length);
    }
    io_status_handler sh = closure(general, exec_elf_read, f, b, kp, complete);
    filesystem_read_linear(f, buffer_ref(b, 0), irange(0, length), sh);
}
