#include <unix_internal.h>
#include <gdb.h>

thread kernel_thread;

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
    f->blocking = true;
    vector_set(p->files, fd, f);
    return fd;
}

void deallocate_fd(process p, int fd, file f)
{
    vector_set(p->files, fd, 0);
    deallocate_u64(p->fdallocator, fd, 1);
}

static boolean node_contents(tuple t, buffer d)
{
    return false;
}    

void default_fault_handler(thread t, context frame)
{
    print_frame(t->frame);
    print_stack(t->frame);

    if (table_find (t->p->process_root, sym(fault))) {
        console("starting gdb\n");
        init_tcp_gdb(heap_general(get_kernel_heaps()), t->p, 1234);
        thread_sleep(current);
    }
    halt("");
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
    u64 infinity = -1ull;
    p->fdallocator = create_id_heap(h, 3, infinity, 1);
    
    p->files = allocate_vector(h, 64);
    zero(p->files, sizeof(p->files));
    file out = allocate(h, sizeof(struct file));
    out->write = closure(h, stdout);
    vector_set(p->files, 1, out);
    vector_set(p->files, 2, out);

    init_threads(p);
    p->syscall_handlers = linux_syscalls;
    return p;
}

process init_unix(kernel_heaps kh, tuple root, filesystem fs, void *stack_top)
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
    set_syscall_handler(syscall_enter);
    process kernel_process = create_process(uh, root, fs);
    current = kernel_thread = create_thread(kernel_process, stack_top);
    rprintf("kernel init %d\n", kernel_thread->tid);
    frame = current->frame;
    init_vdso(heap_physical(kh), heap_pages(kh));
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
