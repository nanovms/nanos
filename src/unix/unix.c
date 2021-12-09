#include <unix_internal.h>
#include <ftrace.h>
#include <gdb.h>
#include <log.h>
#include <filesystem.h>

//#define PF_DEBUG
#ifdef PF_DEBUG
#define pf_debug(x, ...) do {log_printf("FAULT", "[%02d] tid %02d " x "\n", current_cpu()->id, \
                                        current->tid, ##__VA_ARGS__);} while(0)
#else
#define pf_debug(x, ...) thread_log(current, x, ##__VA_ARGS__);
#endif

static unix_heaps u_heap;

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
    assert(signo == SIGSEGV || signo == SIGBUS || signo == SIGFPE);
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
    }
    pf_debug("delivering %s to thread %d; vaddr 0x%lx si_code %d", signame,
        t->tid, vaddr, si_code);
    deliver_signal_to_thread(t, &s);
}

const char *string_from_mmap_type(int type)
{
    return type == VMAP_MMAP_TYPE_ANONYMOUS ? "anonymous" :
        (type == VMAP_MMAP_TYPE_FILEBACKED ? "filebacked" :
         (type == VMAP_MMAP_TYPE_IORING ? "io_uring" : "unknown"));
}

static boolean handle_protection_fault(context frame, u64 vaddr, vmap vm)
{
    /* vmap found, with protection violation set --> send prot violation */
    if (is_protection_fault(frame)) {
        u64 flags = VMAP_FLAG_MMAP | VMAP_FLAG_WRITABLE;
        if (is_write_fault(frame) && (vm->flags & flags) == flags &&
            (vm->flags & VMAP_MMAP_TYPE_MASK) == VMAP_MMAP_TYPE_FILEBACKED) {
            /* copy on write */
            u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
            u64 node_offset = vm->node_offset + (vaddr_aligned - vm->node.r.start);
            pf_debug("copy-on-write for private map: vaddr 0x%lx, node %p, node_offset 0x%lx\n",
                     vaddr, vm->cache_node, node_offset);
            if (!pagecache_node_do_page_cow(vm->cache_node, node_offset, vaddr_aligned,
                                            pageflags_from_vmflags(vm->flags))) {
                msg_err("cannot get physical page; OOM\n");
                return false;
            }
            return true;
        }
        pf_debug("page protection violation\naddr 0x%lx, rip 0x%lx, "
                 "error %s%s%s vm->flags (%s%s %s%s)",
                 vaddr, frame_return_address(frame),
                 is_write_fault(frame) ? "W" : "R",
                 is_usermode_fault(frame) ? "U" : "S",
                 is_instruction_fault(frame) ? "I" : "D",
                 (vm->flags & VMAP_FLAG_MMAP) ? "mmap " : "",
                 string_from_mmap_type(vm->flags & VMAP_MMAP_TYPE_MASK),
                 (vm->flags & VMAP_FLAG_WRITABLE) ? "writable " : "",
                 (vm->flags & VMAP_FLAG_EXEC) ? "executable " : "");

        deliver_fault_signal(SIGSEGV, current, vaddr, SEGV_ACCERR);
        return true;
    }
    return false;
}

define_closure_function(1, 1, context, default_fault_handler,
                        thread, t,
                        context, frame)
{
    process p = 0;
    u64 vaddr = fault_address(frame);
    if (vaddr >= USER_LIMIT) {
        rprintf("\nPage fault on non-user memory (vaddr 0x%lx)\n", vaddr);
        goto bug;
    }

    thread current_thread = current;
    if (!current_thread) {
        rprintf("\nPage fault outside of thread context (vaddr 0x%lx)\n", vaddr);
        goto bug;
    }

    boolean user = is_usermode_fault(frame);

    /* Really this should be the enclosed thread, but that won't fly
       for kernel page faults on user pages. If we were ever to
       support multiple processes, we may need to install current when
       resuming deferred processing. */
    p = current_thread->p;

    if (is_div_by_zero(frame)) {
        if (current_cpu()->state == cpu_user) {
            deliver_fault_signal(SIGFPE, current_thread, vaddr, FPE_INTDIV);
            schedule_frame(frame);
            return 0;
        } else {
            rprintf("\nDivide by zero occurs in kernel mode\n");
            goto bug;
        }
    } else if (is_page_fault(frame)) {
        pf_debug("page fault, vaddr 0x%lx\n", vaddr);
        vmap vm = vmap_from_vaddr(p, vaddr);
        if (vm == INVALID_ADDRESS) {
            if (user) {
                pf_debug("no vmap found for addr 0x%lx, rip 0x%lx", vaddr, frame[SYSCALL_FRAME_PC]);
                deliver_fault_signal(SIGSEGV, current_thread, vaddr, SEGV_MAPERR);

                /* schedule this thread to either run signal handler or terminate */
                schedule_frame(frame);
                return 0;
            } else {
                rprintf("\nUnhandled page fault in kernel mode: ");
                goto bug;
            }
        }

        if (is_pte_error(frame)) {
            /* no SEGV on reserved PTEs */
            msg_err("bug: pte entries reserved or corrupt\n");
            dump_page_tables(vaddr, 8);
            goto bug;
        }

        if (handle_protection_fault(frame, vaddr, vm)) {
            if (is_current_kernel_context(frame)) {
                current_cpu()->state = cpu_kernel;
                return frame;   /* direct return */
            }
            schedule_frame(frame);
            return 0;
        }

        if (do_demand_page(fault_address(frame), vm, frame)) {
            if (is_current_kernel_context(frame)) {
                current_cpu()->state = cpu_kernel;
                return frame;   /* direct return */
            }
            schedule_frame(frame);
            return 0;
        }
    }
    /* XXX arch dep */
#ifdef __x86_64__
    else if (frame[FRAME_VECTOR] == 13) {
        if (current_cpu()->state == cpu_user) {
            pf_debug("general protection fault in user mode, rip 0x%lx", frame[SYSCALL_FRAME_PC]);
            deliver_fault_signal(SIGSEGV, current_thread, 0, SI_KERNEL);
            schedule_frame(frame);
            return 0;
        }
    }
#endif

  bug:
    // panic handling in a more central location?
    rprintf("cpu: %d\n", current_cpu()->id);
    print_frame(frame);
    print_stack(frame);
    frame[FRAME_FULL] = 0;

    if (p && get(p->process_root, sym(fault))) {
        rputs("TODO: in-kernel gdb needs revisiting\n");
//        init_tcp_gdb(heap_locked(get_kernel_heaps()), p, 9090);
//        thread_sleep_uninterruptible();
    }
    /* XXX need a safe, polling storage driver to try to save crash dump here */
    vm_exit(VM_EXIT_FAULT);
}

void init_thread_fault_handler(thread t)
{
    init_closure(&t->fault_handler, default_fault_handler, t);
}

closure_function(0, 6, sysreturn, dummy_read,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    thread_log(t, "%s: dest %p, length %ld, offset_arg %ld",
	       __func__, dest, length, offset_arg);
    if (completion)
        apply(completion, t, 0);
    return 0;
}

closure_function(1, 2, sysreturn, std_close,
                 file, f,
                 thread, t, io_completion, completion)
{
    unix_cache_free(get_unix_heaps(), file, bound(f));
    return io_complete(completion, t, 0);
}

closure_function(0, 6, sysreturn, stdout,
                 void*, d, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    console_write(d, length);
    klog_write(d, length);
    if (completion)
        apply(completion, t, length);
    return length;
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

extern struct syscall *linux_syscalls;

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

process create_process(unix_heaps uh, tuple root, filesystem fs)
{
    kernel_heaps kh = (kernel_heaps)uh;
    heap locked = heap_locked(kh);
    process p = allocate(locked, sizeof(struct process));
    assert(p != INVALID_ADDRESS); 
    boolean aslr = get(root, sym(noaslr)) == 0;

    spin_lock_init(&p->lock);
    p->uh = uh;
    p->brk = 0;
    p->pid = allocate_u64((heap)uh->processes, 1);
    assert(p->pid != INVALID_PHYSICAL);

    /* don't need these for kernel process */
    if (p->pid > 1) {

#ifdef __x86_64__
        /* This heap is used to track the lowest 32 bits of process
           address space. Allocations are presently only made from the
           top half for MAP_32BIT mappings. */
        p->virtual32 = create_id_heap(locked, locked, 0, 0x100000000, PAGESIZE, true);
        assert(p->virtual32 != INVALID_ADDRESS);
        if (aslr)
            id_heap_set_randomize(p->virtual32, true);
#endif
        mmap_process_init(p, aslr);
        init_vdso(p);
    } else {
#ifdef __x86_64__
        p->virtual32 = 0;
#endif
        p->virtual = 0;
        p->vareas = p->vmaps = INVALID_ADDRESS;
    }
    filesystem_reserve(fs); /* because it hosts the current working directory */
    p->root_fs = p->cwd_fs = fs;
    p->cwd = inode_from_tuple(root);
    p->process_root = root;
    p->fdallocator = create_id_heap(locked, locked, 0, infinity, 1, false);
    p->files = allocate_vector(locked, 64);
    zero(p->files, sizeof(p->files));
    create_stdfiles(uh, p);
    init_threads(p);
    p->syscalls = linux_syscalls;
    init_sigstate(&p->signals);
    zero(p->sigactions, sizeof(p->sigactions));
    p->posix_timer_ids = create_id_heap(locked, locked, 0, U32_MAX, 1, false);
    p->posix_timers = allocate_vector(locked, 8);
    p->itimers = allocate_vector(locked, 3);
    p->aio_ids = create_id_heap(locked, locked, 0, S32_MAX, 1, false);
    p->aio = allocate_vector(locked, 8);
    p->trace = 0;
    p->trap = 0;
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

void thread_enter_user(thread in)
{
    thread_resume(in);
    in->sysctx = false;
}

void thread_enter_system(thread t)
{
    if (!t->sysctx) {
        timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
        timestamp diff = here - t->start_time;
        t->utime += diff;
        t->start_time = here;
        t->sysctx = true;
        set_current_thread(&t->thrd);
    }
}

void thread_pause(thread t)
{
    if (get_current_thread() != &t->thrd)
        return;
    timestamp diff = now(CLOCK_ID_MONOTONIC_RAW) - t->start_time;
    if (t->sysctx) {
        t->stime += diff;
    }
    else {
        t->utime += diff;
    }
    context f = thread_frame(t);
    thread_frame_save_fpsimd(f);
    thread_frame_save_tls(f);
    set_current_thread(0);
}

void thread_resume(thread t)
{
    nanos_thread old = get_current_thread();
    if (old && old != &t->thrd)
        apply(old->pause);
    count_syscall_resume(t);
    if (get_current_thread() == &t->thrd)
        return;
    t->start_time = now(CLOCK_ID_MONOTONIC_RAW);
    set_current_thread(&t->thrd);
}

static timestamp utime_updated(thread t)
{
    timestamp ts = t->utime;
    if (!t->sysctx)
        ts += now(CLOCK_ID_MONOTONIC_RAW) - t->start_time;
    return ts;
}

static timestamp stime_updated(thread t)
{
    timestamp ts = t->stime;
    if (t->sysctx)
        ts += now(CLOCK_ID_MONOTONIC_RAW) - t->start_time;
    return ts;
}

closure_function(2, 1, boolean, count_thread_time,
                 timestamp *, ts, boolean, is_utime,
                 rbnode, n)
{
    thread t = struct_from_field(n, thread, n);
    *bound(ts) += bound(is_utime) ? utime_updated(t) : stime_updated(t);
    return true;
}

timestamp proc_utime(process p)
{
    timestamp utime = 0;
    spin_lock(&p->threads_lock);
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(count_thread_time, &utime, true));
    spin_unlock(&p->threads_lock);
    return utime;
}

timestamp proc_stime(process p)
{
    timestamp stime = 0;
    spin_lock(&p->threads_lock);
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(count_thread_time, &stime, false));
    spin_unlock(&p->threads_lock);
    return stime;
}

timestamp thread_utime(thread t)
{
    return utime_updated(t);
}

timestamp thread_stime(thread t)
{
    return stime_updated(t);
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
    uh->processes = create_id_heap(h, h, 1, 65535, 1, false);
    uh->file_cache = locking_heap_wrapper(h,
        allocate_objcache(h, (heap)heap_linear_backed(kh), sizeof(struct file), PAGESIZE));
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
#ifdef NET
    if (!netsyscall_init(uh, root))
        goto alloc_fail;
#endif
    process kernel_process = create_process(uh, root, fs);
    dummy_thread = create_thread(kernel_process);
    runtime_memcpy(dummy_thread->name, "dummy_thread",
        sizeof(dummy_thread->name));

    cpuinfo ci;
    vector_foreach(cpuinfos, ci) {
        context f = frame_from_kernel_context(get_kernel_context(ci));
        f[FRAME_THREAD] = u64_from_pointer(dummy_thread);
    }

    /* XXX remove once we have http PUT support */
    ftrace_enable();

    /* Install a fault handler for use when anonymous pages are
       faulted in within the interrupt handler (e.g. syscall bottom
       halves, I/O directly to user buffers). This is permissible now
       because we only support one process address space. Should this
       ever change, this will need to be reworked; either we make
       faults from the interrupt handler illegal or store a reference
       to the relevant thread frame upon entering the bottom half
       routine.
    */
    install_fallback_fault_handler((fault_handler)&dummy_thread->fault_handler);

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

    return kernel_process;
  alloc_fail:
    msg_err("failed to allocate kernel objects\n");
    return INVALID_ADDRESS;
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
    dump_heap_stats(b, "file cache", uh->file_cache);
    dump_heap_stats(b, "pipe cache", uh->pipe_cache);
    dump_heap_stats(b, "socket cache", uh->socket_cache);
}
