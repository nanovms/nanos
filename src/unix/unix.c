#include <unix_internal.h>
#include <ftrace.h>
#include <gdb.h>
#include <filesystem.h>
#include <drivers/console.h>
#include <ltrace.h>

//#define PF_DEBUG
#ifdef PF_DEBUG
#define pf_debug(x, ...) do {tprintf(sym(fault), 0, "tid %02d " x "\n", \
                                     current ? current->tid : -1, ##__VA_ARGS__);} while(0)
#else
#define pf_debug(x, ...) thread_trace(current, TRACE_PAGE_FAULT, x, ##__VA_ARGS__);
#endif

#define MAX_PROCESSES 2
process processes[MAX_PROCESSES];

BSS_RO_AFTER_INIT static unix_heaps u_heap;

unix_heaps get_unix_heaps()
{
    return u_heap;
}

u64 allocate_fd(process p, void *f)
{
    process_lock(p);
    u64 fd = allocate_u64((heap)p->fdallocator, 1);
    if (fd == INVALID_PHYSICAL) {
        msg_err("fail; maxed out\n");
        goto out;
    }
    if (!vector_set(p->files, fd, f)) {
        deallocate_u64((heap)p->fdallocator, fd, 1);
        fd = INVALID_PHYSICAL;
    }
  out:
    process_unlock(p);
    return fd;
}

u64 allocate_fd_gte(process p, u64 min, void *f)
{
    process_lock(p);
    u64 fd = id_heap_alloc_gte(p->fdallocator, 1, min);
    if (fd == INVALID_PHYSICAL) {
        msg_err("failed\n");
    }
    else {
        if (!vector_set(p->files, fd, f)) {
            deallocate_u64((heap)p->fdallocator, fd, 1);
            fd = INVALID_PHYSICAL;
        }
    }
    process_unlock(p);
    return fd;
}

void deallocate_fd(process p, int fd)
{
    process_lock(p);
    assert(vector_set(p->files, fd, 0)); 
    deallocate_u64((heap)p->fdallocator, fd, 1);
    process_unlock(p);
}

define_closure_function(1, 1, void, fdesc_io_complete,
                        struct fdesc *, f,
                        sysreturn, rv)
{
    fdesc_put(bound(f));
    apply(syscall_io_complete, rv);
}

void init_fdesc(heap h, fdesc f, int type)
{
    zero(f, sizeof(*f));
    init_closure(&f->io_complete, fdesc_io_complete, f);
    f->refcnt = 1;
    f->type = type;
    f->ns = allocate_notify_set(h);
    spin_lock_init(&f->lock);
}

void release_fdesc(fdesc f)
{
    deallocate_notify_set(f->ns);
}

boolean copy_from_user(const void *uaddr, void *kaddr, u64 len)
{
    if (!validate_user_memory(uaddr, len, false))
        return false;
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx)) {
        runtime_memcpy(kaddr, uaddr, len);
        context_clear_err(ctx);
        return true;
    }
    return false;
}

boolean copy_to_user(void *uaddr, const void *kaddr, u64 len)
{
    if (!validate_user_memory(uaddr, len, true))
        return false;
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx)) {
        runtime_memcpy(uaddr, kaddr, len);
        context_clear_err(ctx);
        return true;
    }
    return false;
}

void deliver_fault_signal(u32 signo, thread t, u64 vaddr, s32 si_code)
{
    struct siginfo s = {
        .si_signo = signo,
         /* man sigaction: "si_errno is generally unused on Linux" */
        .si_errno = 0,
        .si_code = si_code,
        .sifields.sigfault = {
            .addr = vaddr,
        }
    };

    char *signame = "SIGSEGV";
    switch (signo) {
    case SIGSEGV:
        signame = "SIGSEGV";
        break;
    case SIGBUS:
        signame = "SIGBUS";
        break;
    case SIGFPE:
        signame = "SIGFPE";
        break;
    case SIGILL:
        signame = "SIGILL";
        break;
    case SIGTRAP:
        signame = "SIGTRAP";
        break;
    default:
        halt("%s: unexpected signal number %d\n", __func__, signo);
    }
    pf_debug("delivering %s to thread %d; vaddr 0x%lx si_code %d", signame,
        t->tid, vaddr, si_code);
    deliver_signal_to_thread(t, &s);
}

const char *string_from_mmap_type(int type)
{
    return type == VMAP_MMAP_TYPE_ANONYMOUS ? "anonymous" :
        (type == VMAP_MMAP_TYPE_FILEBACKED ? "filebacked" :
         "unknown");
}

#define format_protection_violation(vaddr, ctx, vm, str)        \
    "page_protection_violation%s\naddr 0x%lx, pc 0x%lx, "       \
    "error %s%s%s vm->flags (%s%s %s%s%s)\n",                   \
        str, vaddr, frame_fault_pc(ctx->frame),                 \
        is_write_fault(ctx->frame) ? "W" : "R",                 \
        is_usermode_fault(ctx->frame) ? "U" : "S",              \
        is_instruction_fault(ctx->frame) ? "I" : "D",           \
        (vm->flags & VMAP_FLAG_MMAP) ? "mmap " : "",            \
        string_from_mmap_type(vm->flags & VMAP_MMAP_TYPE_MASK), \
        (vm->flags & VMAP_FLAG_READABLE) ? "readable " : "",    \
        (vm->flags & VMAP_FLAG_WRITABLE) ? "writable " : "",    \
        (vm->flags & VMAP_FLAG_EXEC) ? "executable " : ""

static boolean handle_protection_fault(context ctx, u64 vaddr, vmap vm)
{
    /* vmap found, with protection violation set --> send prot violation */
    u64 flags = VMAP_FLAG_MMAP | VMAP_FLAG_WRITABLE;
    if (is_write_fault(ctx->frame) && (vm->flags & flags) == flags &&
        (vm->flags & VMAP_MMAP_TYPE_MASK) == VMAP_MMAP_TYPE_FILEBACKED) {
        /* copy on write */
        u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
        u64 node_offset = vm->node_offset + (vaddr_aligned - vm->node.r.start);
        pf_debug("copy-on-write for private map: vaddr 0x%lx, node %p, node_offset 0x%lx\n",
                 vaddr, vm->cache_node, node_offset);
        if (!pagecache_node_do_page_cow(vm->cache_node, node_offset, vaddr_aligned,
                                        pageflags_from_vmflags(vm->flags)))
            halt("cannot get physical page for vaddr 0x%lx, ctx %p; OOM\n", vaddr, ctx);
        return true;
    }

    if (is_thread_context(ctx)) {
        pf_debug(format_protection_violation(vaddr, ctx, vm, ""));
        deliver_fault_signal(SIGSEGV, (thread)ctx, vaddr, SEGV_ACCERR);
        return true;
    }
    return false;
}

define_closure_function(0, 1, context, unix_fault_handler,
                        context, ctx)
{
    const char *errmsg = 0;
    u64 fault_pc = frame_fault_pc(ctx->frame);
    boolean user = (current_cpu()->state == cpu_user);
    process p = struct_from_field(closure_self(), process, fault_handler);
    thread t = user ? (thread)ctx : 0;

    if (is_div_by_zero(ctx->frame)) {
        if (user) {
            deliver_fault_signal(SIGFPE, t, fault_pc, FPE_INTDIV);
            schedule_thread(t);
            return 0;
        } else {
            errmsg = "Divide by zero occurs in kernel mode";
            goto bug;
        }
    } else if (is_illegal_instruction(ctx->frame)) {
        if (user) {
            pf_debug("invalid opcode fault in user mode, rip 0x%lx", fault_pc);
            deliver_fault_signal(SIGILL, t, fault_pc, ILL_ILLOPC);
            schedule_thread(t);
            return 0;
        } else {
            errmsg = "Illegal instruction in kernel mode";
            goto bug;
        }
    } else if (is_trap(ctx->frame)) {
        if (user) {
            pf_debug("trap in user mode, rip 0x%lx", fault_pc);
            if (!ltrace_handle_trap(ctx->frame))
                deliver_fault_signal(SIGTRAP, t, fault_pc,
                                     is_breakpoint(ctx->frame) ? TRAP_BRKPT : TRAP_TRACE);
            schedule_thread(t);
            return 0;
        } else {
            errmsg = "Breakpoint in kernel mode";
            goto bug;
        }
    } else if (is_page_fault(ctx->frame)) {
        u64 vaddr = frame_fault_address(ctx->frame);
        vmap vm;
        if (vaddr >= MIN(p->mmap_min_addr, PAGESIZE) && vaddr < USER_LIMIT)
            vm = vmap_from_vaddr(p, vaddr);
        else
            vm = INVALID_ADDRESS;
        pf_debug("page fault, vaddr 0x%lx, vmap %p, ctx %p, type %d, pc 0x%lx",
                 vaddr, vm, ctx, ctx->type, fault_pc);
        if (vm == INVALID_ADDRESS) {
            /* We're assuming here that an unhandled fault on a user page from
               within a syscall context is actually a program bug - though
               there's a chance that a true kernel bug might materialize as a
               SEGV rather than a panic. */
            pf_debug("no vmap found");
            if (!user)
                goto error;
            deliver_fault_signal(SIGSEGV, t, vaddr, SEGV_MAPERR);

            /* schedule this thread to either run signal handler or terminate */
            schedule_thread(t);
            return 0;
        }

        if (is_pte_error(ctx->frame)) {
            /* no SEGV on reserved PTEs */
            errmsg = "bug: pte entries reserved or corrupt";
            dump_page_tables(vaddr, 8);
            goto bug;
        }

        if (is_instruction_fault(ctx->frame) && !user) {
            msg_err("kernel instruction fault\n");
            goto bug;
        }

        if (is_protection_fault(ctx->frame)) {
            if (handle_protection_fault(ctx, vaddr, vm)) {
                if (!is_thread_context(ctx))
                    return ctx;   /* direct return */
                schedule_thread(t);
                return 0;
            }
            goto error;
        }

        if (do_demand_page(p, ctx, vaddr, vm))
            return ctx;   /* direct return */
        else if (user) {
            pf_debug("demand page failed user mode, rip 0x%lx", fault_pc);
            deliver_fault_signal(SIGBUS, t, vaddr, BUS_ADRERR);
            schedule_thread(t);
            return 0;
        }
    }
    /* XXX arch dep */
#ifdef __x86_64__
    else if (ctx->frame[FRAME_VECTOR] == 13) {
        if (user) {
            pf_debug("general protection fault in user mode, rip 0x%lx", fault_pc);
            deliver_fault_signal(SIGSEGV, t, 0, SI_KERNEL);
            schedule_thread(t);
            return 0;
        }
    }
#endif

error:
    if (context_err_is_set(ctx)) {
        kernel_context kc = (kernel_context)ctx;
        err_frame_apply(kc->err_frame, ctx->frame);
        context_clear_err(ctx);
        return ctx;
    }
bug:
    // panic handling in a more central location?
    console_force_unlock();
    rprintf("\n%s\n", errmsg);
    rprintf("cpu: %d, context type: %d\n", current_cpu()->id, ctx->type);
    dump_context(ctx);
    ctx->frame[FRAME_FULL] = false;

    if (get(p->process_root, sym(fault))) {
        rputs("TODO: in-kernel gdb needs revisiting\n");
//        init_tcp_gdb(heap_locked(get_kernel_heaps()), p, 9090);
//        thread_sleep_uninterruptible();
    }
    /* XXX need a safe, polling storage driver to try to save crash dump here */
    vm_exit(VM_EXIT_FAULT);
}

void init_thread_fault_handler(thread t)
{
    t->context.fault_handler = (fault_handler)&t->p->fault_handler;
}

closure_function(0, 6, sysreturn, dummy_read,
                 void *, dest, u64, length, u64, offset_arg, context, ctx, boolean, bh, io_completion, completion)
{
    thread_log(current, "%s: dest %p, length %ld, offset_arg %ld",
	       __func__, dest, length, offset_arg);
    if (completion)
        apply(completion, 0);
    return 0;
}

closure_function(1, 2, sysreturn, std_close,
                 file, f,
                 context, ctx, io_completion, completion)
{
    unix_cache_free(get_unix_heaps(), file, bound(f));
    return io_complete(completion, 0);
}

closure_function(0, 6, sysreturn, stdout,
                 void*, d, u64, length, u64, offset, context, ctx, boolean, bh, io_completion, completion)
{
    sysreturn rv;
    if (fault_in_user_memory(d, length, false)) {
        console_write(d, length);
        klog_write(d, length);
        rv = length;
    } else {
        rv = -EFAULT;
    }
    if (completion)
        apply(completion, rv);
    return rv;
}

closure_function(0, 1, u32, std_output_events,
                 thread, t /* ignore */)
{
    return EPOLLOUT;
}

closure_function(0, 1, u32, std_input_events,
                 thread, t /* ignore */)
{
    return 0;
}

static boolean create_stdfiles(unix_heaps uh, process p)
{
    heap h = heap_locked((kernel_heaps)uh);
    file in = unix_cache_alloc(uh, file);
    file out = unix_cache_alloc(uh, file);
    file err = unix_cache_alloc(uh, file);
    if (!in || !out || !err) {
        msg_err("failed to allocate files\n");
        return false;
    }
    assert(allocate_fd(p, in) == 0);
    assert(allocate_fd(p, out) == 1);
    assert(allocate_fd(p, err) == 2);

    /* Writes to in, reads from out and err act as if handled by the
       out and in files respectively. */
    init_fdesc(h, &in->f, FDESC_TYPE_STDIO);
    in->f.close = closure(h, std_close, in);
    init_fdesc(h, &out->f, FDESC_TYPE_STDIO);
    out->f.close = closure(h, std_close, out);
    init_fdesc(h, &err->f, FDESC_TYPE_STDIO);
    err->f.close = closure(h, std_close, err);
    in->f.write = out->f.write = err->f.write = closure(h, stdout);
    in->f.read = out->f.read = err->f.read = closure(h, dummy_read);
    in->f.flags = out->f.flags = err->f.flags = O_RDWR;
    out->f.events = err->f.events = closure(h, std_output_events);
    in->f.events = closure(h, std_input_events);
    return true;
}

void init_unix_context(unix_context uc, int type, int size, queue free_ctx_q)
{
    init_kernel_context(&uc->kc, type, size, free_ctx_q);
    blockq_thread_init(uc);
}

static void process_context_pause(context ctx)
{
    process_context pc = (process_context)ctx;
    process p = pc->p;
    fetch_and_add(&p->stime, now(CLOCK_ID_MONOTONIC_RAW) - pc->start_time);
    timer_service(p->cpu_timers, proc_cputime(p));
    context_release_refcount(ctx);
}

static void process_context_resume(context ctx)
{
    process_context pc = (process_context)ctx;
    pc->start_time = now(CLOCK_ID_MONOTONIC_RAW);
    context_reserve_refcount(ctx);
}

process_context get_process_context(void)
{
    thread t = current;
    if (!t)
        return INVALID_ADDRESS;
    cpuinfo ci = current_cpu();
    process_context pc = dequeue_single(ci->free_process_contexts);
    if (pc != INVALID_ADDRESS) {
        refcount_set_count(&pc->uc.kc.context.refcount, 1);
        return pc;
    }
    pc = allocate((heap)heap_linear_backed(get_kernel_heaps()), PROCESS_CONTEXT_SIZE);
    if (pc == INVALID_ADDRESS)
        return pc;
    init_unix_context(&pc->uc, CONTEXT_TYPE_PROCESS, PROCESS_CONTEXT_SIZE,
                      ci->free_process_contexts);
    pc->p = t->p;
    context c = &pc->uc.kc.context;
    c->pause = process_context_pause;
    c->resume = process_context_resume;
    c->fault_handler = (fault_handler)&pc->p->fault_handler;
    return pc;
}

define_closure_function(0, 0, timestamp, process_now)
{
    process p = struct_from_field(closure_self(), process, now);
    return proc_cputime(p);
}

process create_process(unix_heaps uh, tuple root, filesystem fs)
{
    kernel_heaps kh = (kernel_heaps)uh;
    heap locked = heap_locked(kh);
    process p = allocate(locked, sizeof(struct process));
    assert(p != INVALID_ADDRESS); 

    spin_lock_init(&p->lock);
    p->uh = uh;
    p->brk = 0;
    p->pid = allocate_u64((heap)uh->processes, 1);
    assert(p->pid != INVALID_PHYSICAL);

    /* don't need these for kernel process */
    if (p->pid > 1) {
        mmap_process_init(p, root);
        init_vdso(p);
    } else {
        p->virtual = 0;
        p->vmaps = INVALID_ADDRESS;
    }
    filesystem_reserve(fs); /* because it hosts the current working directory */
    p->root_fs = p->cwd_fs = fs;
    p->cwd = fs->get_inode(fs, root);
    p->process_root = root;
    p->fdallocator = create_id_heap(locked, locked, 0, infinity, 1, false);
    p->files = allocate_vector(locked, 64);
    zero(p->files, sizeof(p->files));
    create_stdfiles(uh, p);
    init_threads(p);
    init_closure(&p->fault_handler, unix_fault_handler);
    p->syscalls = linux_syscalls;
    init_sigstate(&p->signals);
    zero(p->sigactions, sizeof(p->sigactions));
    p->posix_timer_ids = create_id_heap(locked, locked, 0, U32_MAX, 1, false);
    p->posix_timers = allocate_vector(locked, 8);
    p->itimers = allocate_vector(locked, 3);
    p->utime = p->stime = 0;
    p->cpu_timers = allocate_timerqueue(locked, init_closure(&p->now, process_now), "cpu time");
    assert(p->cpu_timers != INVALID_ADDRESS);
    p->aio_ids = create_id_heap(locked, locked, 0, S32_MAX, 1, false);
    p->aio = allocate_vector(locked, 8);
    p->trace = 0;
    p->trap = 0;
    if ((u64)p->pid - 1 < MAX_PROCESSES)
        processes[p->pid - 1] = p;
    return p;
}

void process_get_cwd(process p, filesystem *cwd_fs, inode *cwd)
{
    process_lock(p);
    *cwd_fs = p->cwd_fs;
    filesystem_reserve(*cwd_fs);
    *cwd = p->cwd;
    process_unlock(p);
}

timestamp proc_utime(process p)
{
    return p->utime;
}

timestamp proc_stime(process p)
{
    return p->stime;
}

timestamp thread_utime(thread t)
{
    return t->utime;
}

timestamp thread_stime(thread t)
{
    return t->stime;
}

void cputime_update(thread t, timestamp delta, boolean is_utime)
{
    if (t->cpu_timers)
        timer_service(t->cpu_timers, thread_cputime(t));
    process p = t->p;
    fetch_and_add(is_utime ? &p->utime : &p->stime, delta);
    timer_service(p->cpu_timers, proc_cputime(p));
}

define_closure_function(0, 1, u64, unix_mem_cleaner,
                        u64, clean_bytes)
{
    unix_heaps uh = struct_from_field(closure_self(), unix_heaps, mem_cleaner);
    u64 cleaned = cache_drain(uh->file_cache, clean_bytes, 0);
    if (cleaned < clean_bytes)
        cleaned += cache_drain(uh->pipe_cache, clean_bytes - cleaned, 0);
    if (cleaned < clean_bytes)
        cleaned += cache_drain(uh->socket_cache, clean_bytes - cleaned, 0);
    return cleaned;
}

process init_unix(kernel_heaps kh, tuple root, filesystem fs)
{
    heap h = heap_locked(kh);
    unix_heaps uh = allocate(h, sizeof(struct unix_heaps));

    /* a failure here means termination; just leak */
    if (uh == INVALID_ADDRESS)
	return INVALID_ADDRESS;

    u_heap = uh;
    uh->kh = *kh;
    uh->processes = locking_heap_wrapper(h, (heap)create_id_heap(h, h, 1, 65535, 1, false));
    uh->file_cache = allocate_objcache(h, (heap)heap_linear_backed(kh), sizeof(struct file),
                                       PAGESIZE, true);
    if (uh->file_cache == INVALID_ADDRESS)
	goto alloc_fail;
    if (!poll_init(uh))
	goto alloc_fail;
    if (!pipe_init(uh))
	goto alloc_fail;
    if (!unix_timers_init(uh))
        goto alloc_fail;
    if (ftrace_init(uh, fs))
	goto alloc_fail;
#ifdef LOCK_STATS
    lockstats_init(kh);
#endif
#ifdef NET
    if (!netsyscall_init(uh, root))
        goto alloc_fail;
#endif
    process kernel_process = create_process(uh, root, fs);
    dummy_thread = create_thread(kernel_process, kernel_process->pid);
    runtime_memcpy(dummy_thread->name, "dummy_thread",
        sizeof(dummy_thread->name));

    cpuinfo ci;
    vector_foreach(cpuinfos, ci) {
        syscall_context sc = allocate_syscall_context(ci);
        assert(sc != INVALID_ADDRESS);
        ci->m.syscall_context = &sc->uc.kc.context;
    }

    /* XXX remove once we have http PUT support */
    ftrace_enable();

    register_special_files(kernel_process);
    init_syscalls(kernel_process->process_root);
    register_file_syscalls(linux_syscalls);
#ifdef NET
    register_net_syscalls(linux_syscalls);
#endif

    register_signal_syscalls(linux_syscalls);
    register_mmap_syscalls(linux_syscalls);
    register_thread_syscalls(linux_syscalls);
    register_poll_syscalls(linux_syscalls);
    register_clock_syscalls(linux_syscalls);
    register_timer_syscalls(linux_syscalls);
    register_other_syscalls(linux_syscalls);
    configure_syscalls(kernel_process);

    tuple coredumplimit = get(root, sym(coredumplimit));
    if (coredumplimit && is_string(coredumplimit)) {
        buffer b = alloca_wrap((buffer)coredumplimit);
        u64 size;
        if (!parse_int(b, 10, &size))
            goto out;
        char suffix = (char)pop_u8(b);
        if ((suffix == 'k') || (suffix == 'K'))
            size *= KB;
        else if ((suffix == 'm') || (suffix == 'M'))
            size *= MB;
        else if ((suffix == 'g') || (suffix == 'G'))
            size *= GB;
        coredump_set_limit(size);
    }
    assert(mm_register_mem_cleaner(init_closure(&uh->mem_cleaner, unix_mem_cleaner)));
out:
    return kernel_process;
  alloc_fail:
    msg_err("failed to allocate kernel objects\n");
    return INVALID_ADDRESS;
}

closure_function(1, 2, void, shutdown_timeout,
                 struct timer, shutdown_timer,
                 u64, expiry, u64, overruns)
{
    closure_finish();
    if (overruns == timer_disabled)
        return;
    if (!shutting_down)
        kernel_shutdown(0);
}

void unix_shutdown(void)
{
    heap h = heap_locked(get_kernel_heaps());
    /* Skip kernel unix process for shutdown */
    for (int i = 1; i < MAX_PROCESSES; i++) {
        process p = processes[i];
        if (p == 0)
            continue;
        struct siginfo *si = allocate_zero(h, sizeof(struct siginfo));
        if (si == INVALID_ADDRESS) {
            kernel_shutdown(0);
            return;
        }
        si->si_signo = SIGTERM;
        deliver_signal_to_process(p, si);
    }
    struct timer shutdown_timer = {0};
    init_timer(&shutdown_timer);
    timer_handler th = closure(h, shutdown_timeout, shutdown_timer);
    register_timer(kernel_timers, &closure_member(shutdown_timeout, th, shutdown_timer), 
        CLOCK_ID_MONOTONIC, seconds(UNIX_SHUTDOWN_TIMEOUT_SECS), false, 0, th);
}

void program_set_perms(tuple root, tuple prog)
{
    if (get(root, sym(exec_protection)))
        set(prog, sym(exec), null_value);
    else if (!get(root, sym(program_overwrite)))
        set(prog, sym(readonly), null_value);
}

static void dump_heap_stats(buffer b, const char *name, heap h)
{
    bytes allocated = heap_allocated(h);
    bytes total = heap_total(h);
    if ((total != INVALID_PHYSICAL) && (total != 0)) {
        bprintf(b, " %s: total %ld, allocated %ld (%d%%)\n", name, total,
                allocated, 100 * allocated / total);
    } else {
        bprintf(b, " %s: allocated %ld\n", name, allocated);
    }
}

void dump_mem_stats(buffer b)
{
    unix_heaps uh = get_unix_heaps();
    kernel_heaps kh = &uh->kh;
    bprintf(b, "Kernel heaps:\n");
    dump_heap_stats(b, "general", heap_general(kh));
    dump_heap_stats(b, "physical", (heap)heap_physical(kh));
    dump_heap_stats(b, "virtual huge", (heap)heap_virtual_huge(kh));
    dump_heap_stats(b, "virtual page", (heap)heap_virtual_page(kh));
    bprintf(b, "Unix heaps:\n");
    dump_heap_stats(b, "file cache", (heap)uh->file_cache);
    dump_heap_stats(b, "pipe cache", (heap)uh->pipe_cache);
    dump_heap_stats(b, "socket cache", (heap)uh->socket_cache);
}
