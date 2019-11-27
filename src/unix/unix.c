#include <unix_internal.h>
#include <ftrace.h>
#include <buffer.h>
#include <gdb.h>

void init_fdesc(heap h, fdesc f, int type)
{
    f->read = 0;
    f->write = 0;
    f->close = 0;
    f->events = 0;
    f->ioctl = 0;
    f->refcnt = 1;
    f->type = type;
    f->flags = 0;
    f->ns = allocate_notify_set(h);
}

void release_fdesc(fdesc f)
{
    deallocate_notify_set(f->ns);
}

u64 allocate_fd(process p, void *f)
{
    u64 fd = allocate_u64(p->fdallocator, 1);
    if (fd == INVALID_PHYSICAL) {
	msg_err("fail; maxed out\n");
	return fd;
    }
    vector_set(p->files, fd, f);
    return fd;
}

u64 allocate_fd_gte(process p, u64 min, void *f)
{
    u64 fd = id_heap_alloc_gte(p->fdallocator, 1, min);
    if (fd == INVALID_PHYSICAL) {
        msg_err("failed\n");
    }
    else {
        vector_set(p->files, fd, f);
    }
    return fd;
}

void deallocate_fd(process p, int fd)
{
    vector_set(p->files, fd, 0);
    deallocate_u64(p->fdallocator, fd, 1);
}

closure_function(1, 1, context, default_fault_handler,
                 thread, t,
                 context, frame)
{
    /* frame can be:
       - t->frame if user or syscall
       - miscframe in interrupt level
    */
    if (frame[FRAME_VECTOR] == 14) {
        /* XXX move this to x86_64 */
        if (unix_fault_page(frame[FRAME_CR2], frame))
            return frame;
    }

    print_frame(frame);
    print_stack(frame);

    if (table_find(current->p->process_root, sym(fault))) {
        console("starting gdb\n");
        init_tcp_gdb(heap_general(get_kernel_heaps()), current->p, 9090);
        thread_sleep_uninterruptible();
    } else {
        halt("halt\n");
    }
    return frame;
}

fault_handler create_fault_handler(heap h, thread t)
{
    return closure(h, default_fault_handler, t);
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

closure_function(1, 0, sysreturn, std_close,
                 file, f)
{
    unix_cache_free(get_unix_heaps(), file, bound(f));
    return 0;
}

closure_function(0, 6, sysreturn, stdout,
                 void*, d, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    console_write(d, length);
    if (completion)
        apply(completion, t, length);
    return length;
}

closure_function(0, 0, u32, std_output_events)
{
    return EPOLLOUT;
}

closure_function(0, 0, u32, std_input_events)
{
    return 0;
}

extern struct syscall *linux_syscalls;

static boolean create_stdfiles(unix_heaps uh, process p)
{
    heap h = heap_general((kernel_heaps)uh);
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
    heap h = heap_general((kernel_heaps)uh);
    process p = allocate(h, sizeof(struct process));
    boolean aslr = table_find(root, sym(noaslr)) == 0;

    p->uh = uh;
    p->brk = 0;
    p->pid = allocate_u64(uh->processes, 1);

    /* don't need these for kernel process */
    if (p->pid > 1) {
        p->virtual = create_id_heap(h, PROCESS_VIRTUAL_HEAP_START,
                                    PROCESS_VIRTUAL_HEAP_LENGTH, HUGE_PAGESIZE);
        assert(p->virtual != INVALID_ADDRESS);
        assert(id_heap_set_area(heap_virtual_huge((kernel_heaps)uh),
                                PROCESS_VIRTUAL_HEAP_START, PROCESS_VIRTUAL_HEAP_LENGTH,
                                true, true));
        p->virtual_page = create_id_heap_backed(h, p->virtual, PAGESIZE);
        assert(p->virtual_page != INVALID_ADDRESS);
        if (aslr)
            id_heap_set_randomize(p->virtual_page, true);

        /* This heap is used to track the lowest 32 bits of process
           address space. Allocations are presently only made from the
           top half for MAP_32BIT mappings. */
        p->virtual32 = create_id_heap(h, 0, 0x100000000, PAGESIZE);
        assert(p->virtual32 != INVALID_ADDRESS);
        if (aslr)
            id_heap_set_randomize(p->virtual32, true);
        mmap_process_init(p);
    } else {
        p->virtual = p->virtual_page = p->virtual32 = 0;
        p->vareas = p->vmaps = INVALID_ADDRESS;
    }
    p->fs = fs;
    p->cwd = root;
    p->process_root = root;
    p->fdallocator = create_id_heap(h, 0, infinity, 1);
    p->files = allocate_vector(h, 64);
    zero(p->files, sizeof(p->files));
    create_stdfiles(uh, p);
    init_threads(p);
    p->syscalls = linux_syscalls;
    p->sysctx = false;
    p->utime = p->stime = 0;
    p->start_time = now(CLOCK_ID_MONOTONIC);
    init_sigstate(&p->signals);
    zero(p->sigactions, sizeof(p->sigactions));
    return p;
}

void proc_enter_user(process p)
{
    if (p->sysctx) {
        timestamp here = now(CLOCK_ID_MONOTONIC);
        p->stime += here - p->start_time;
        p->sysctx = false;
        p->start_time = here;
    }
}

void proc_enter_system(process p)
{
    if (!p->sysctx) {
        timestamp here = now(CLOCK_ID_MONOTONIC);
        p->utime += here - p->start_time;
        p->sysctx = true;
        p->start_time = here;
    }
}

void proc_pause(process p)
{
    timestamp here = now(CLOCK_ID_MONOTONIC);
    if (p->sysctx) {
        p->stime += here - p->start_time;
    }
    else {
        p->utime += here - p->start_time;
    }
}

void proc_resume(process p)
{
    p->start_time = now(CLOCK_ID_MONOTONIC);
}

timestamp proc_utime(process p)
{
    timestamp utime = p->utime;
    if (!p->sysctx) {
        utime += now(CLOCK_ID_MONOTONIC) - p->start_time;
    }
    return utime;
}

timestamp proc_stime(process p)
{
    timestamp stime = p->stime;
    if (p->sysctx) {
        stime += now(CLOCK_ID_MONOTONIC) - p->start_time;
    }
    return stime;
}

process init_unix(kernel_heaps kh, tuple root, filesystem fs)
{
    heap h = heap_general(kh);
    unix_heaps uh = allocate(h, sizeof(struct unix_heaps));

    /* a failure here means termination; just leak */
    if (uh == INVALID_ADDRESS)
	return INVALID_ADDRESS;

    uh->kh = *kh;
    uh->processes = create_id_heap(h, 1, 65535, 1);
    uh->file_cache = allocate_objcache(h, heap_backed(kh), sizeof(struct file), PAGESIZE);
    if (uh->file_cache == INVALID_ADDRESS)
	goto alloc_fail;
    if (!poll_init(uh))
	goto alloc_fail;
    if (!pipe_init(uh))
	goto alloc_fail;

    if (ftrace_init(uh, fs))
	goto alloc_fail;

    set_syscall_handler(syscall_enter);
    process kernel_process = create_process(uh, root, fs);
    current = dummy_thread = create_thread(kernel_process);
    running_frame = current->frame;

    runtime_memcpy(dummy_thread->name, "dummy_thread",
        sizeof(dummy_thread->name));

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
    fault_handler fallback_handler = create_fault_handler(h, current);
    install_fallback_fault_handler(fallback_handler);

    init_vdso(heap_physical(kh), heap_pages(kh));
    register_special_files(kernel_process);
    init_syscalls();
    register_file_syscalls(linux_syscalls);
#ifdef NET
    if (!netsyscall_init(uh))
	goto alloc_fail;
    register_net_syscalls(linux_syscalls);
#endif

    register_signal_syscalls(linux_syscalls);
    register_mmap_syscalls(linux_syscalls);
    register_thread_syscalls(linux_syscalls);
    register_poll_syscalls(linux_syscalls);
    register_clock_syscalls(linux_syscalls);
    register_other_syscalls(linux_syscalls);
    configure_syscalls(kernel_process);
    return kernel_process;
  alloc_fail:
    msg_err("failed to allocate kernel objects\n");
    return INVALID_ADDRESS;
}
