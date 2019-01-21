#include <unix_internal.h>
#include <buffer.h>
#include <gdb.h>

u64 allocate_fd(process p, file f)
{
    u64 fd = allocate_u64(p->fdallocator, 1);
    if (fd == INVALID_PHYSICAL) {
	msg_err("fail; maxed out\n");
	return fd;
    }
    f->offset = 0;
    f->check = 0;
    f->close = 0;
    f->read = f->write = 0;
    vector_set(p->files, fd, f);
    return fd;
}

void deallocate_fd(process p, int fd, file f)
{
    vector_set(p->files, fd, 0);
    deallocate_u64(p->fdallocator, fd, 1);
}

void default_fault_handler(thread t, context frame)
{
    print_frame(t->frame);
    print_stack(t->frame);

    if (table_find (t->p->process_root, sym(fault))) {
        console("starting gdb\n");
        init_tcp_gdb(heap_general(get_kernel_heaps()), t->p, 9090);
        thread_sleep(current);
    }
    halt("");
}

static CLOSURE_0_3(dummy_read, sysreturn, void *, u64, u64);
static sysreturn dummy_read(void *dest, u64 length, u64 offset_arg)
{
    thread_log(current, "%s: dest %p, length %d, offset_arg %d",
	       __func__, dest, length, offset_arg);
    return 0;
}

static CLOSURE_1_0(std_close, sysreturn, file);
static sysreturn std_close(file f)
{
    unix_cache_free(get_unix_heaps(), file, f);
    return 0;
}

static CLOSURE_0_3(stdout, sysreturn, void*, u64, u64);
static sysreturn stdout(void *d, u64 length, u64 offset)
{
    u8 *z = d;
    for (int i = 0; i< length; i++) {
        serial_out(z[i]);
    }
    return length;
}

extern void *linux_syscalls[];

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
    in->write = out->write = err->write = closure(h, stdout);
    in->read = out->read = err->read = closure(h, dummy_read);
    in->close = closure(h, std_close, in);
    out->close = closure(h, std_close, out);
    err->close = closure(h, std_close, err);
    return true;
}

process create_process(unix_heaps uh, tuple root, filesystem fs)
{
    heap h = heap_general((kernel_heaps)uh);
    process p = allocate(h, sizeof(struct process));
    p->uh = uh;
    p->brk = 0;
    p->pid = allocate_u64(uh->processes, 1);
    // xxx - take from virtual allocator
    p->virtual = create_id_heap(h, 0x7000000000ull, 0x10000000000ull, 0x100000000);
    p->virtual32 = create_id_heap(h, 0x10000000, 0xe0000000, PAGESIZE);
    p->fs = fs;
    p->cwd = root;
    p->process_root = root;
    p->fdallocator = create_id_heap(h, 0, infinity, 1);
    p->files = allocate_vector(h, 64);
    zero(p->files, sizeof(p->files));
    create_stdfiles(uh, p);
    init_threads(p);
    p->syscall_handlers = linux_syscalls;
    p->vmap = rtrie_create(h);
    return p;
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
    set_syscall_handler(syscall_enter);
    process kernel_process = create_process(uh, root, fs);
    current = create_thread(kernel_process);
    frame = current->frame;
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
    return kernel_process;
  alloc_fail:
    msg_err("failed to allocate kernel objects\n");
    return INVALID_ADDRESS;
}
