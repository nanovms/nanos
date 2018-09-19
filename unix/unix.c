#include <unix_internal.h>
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

static boolean node_contents(tuple t, buffer d)
{
    return false;
}    

void default_fault_handler(thread t, context frame)
{
    kernel k = t->p->k;

    print_frame(t->frame);
    print_stack(t->frame);

    if (table_find (k->root, sym(gdb_on_fault))) {
        console("starting gdb\n");
        init_tcp_gdb(k->general, t->p, 1234);
        thread_sleep(current);
    }
    halt("");
}


static CLOSURE_0_3(stdout, int, void*, u64, u64);
static int stdout(void *d, u64 length, u64 offset)
{
    u8 *z = d;
    for (int i = 0; i< length; i++) {
        serial_out(z[i]);
    }
    return length;
}

static u64 futex_key_function(void *x)
{
    return u64_from_pointer(x);
}

static boolean futex_key_equal(void *a, void *b)
{
    return a == b;
}

static void *linux_syscalls[SYS_MAX];

process create_process(kernel k)
{
    process p = allocate(k->general, sizeof(struct process));
    heap h = k->general;
    p->k = k;
    p->brk = 0;
    p->pid = allocate_u64(k->processes, 1);
    // xxx - take from virtual allocator
    p->virtual = create_id_heap(h, 0x7000000000ull, 0x10000000000ull, 0x100000000);
    p->virtual32 = create_id_heap(h, 0x10000000, 0xe0000000, PAGESIZE);
    p->cwd = k->root;
    p->process_root = k->root;
    u64 infinity = -1ull;
    p->fdallocator = create_id_heap(h, 3, infinity, 1);
    p->files = allocate_vector(h, 64);
    zero(p->files, sizeof(p->files));
    file out = allocate(h, sizeof(struct file));
    out->write = closure(h, stdout);
    vector_set(p->files, 1, out);
    vector_set(p->files, 2, out);
    p->futices = allocate_table(h, futex_key_function, futex_key_equal);
    p->threads = allocate_vector(h, 5);
    p->syscall_handlers = linux_syscalls;
    return p;
}

void *syscall;

#define offsetof(__t, __e) u64_from_pointer(&((__t)0)->__e)


// return value is fucked up and need ENOENT - enoent could be initialized
buffer install_syscall(heap h)
{
    buffer b = allocate_buffer(h, 100);
    int working = REGISTER_A;
    mov_64_imm(b, working, u64_from_pointer(current));
    indirect_displacement(b, REGISTER_A, REGISTER_A, offsetof(thread, p));
    indirect_displacement(b, REGISTER_A, REGISTER_A, offsetof(process, syscall_handlers));
    indirect_scale(b, REGISTER_A, 3, REGISTER_B, REGISTER_A);
    jump_indirect(b, REGISTER_A);
    return b;
}

extern char *syscall_name(int);
static u64 syscall_debug()
{
    u64 *f = current->frame;
    int call = f[FRAME_VECTOR];
    if (table_find(current->p->root, sym(debug_syscalls)))
        thread_log(current, syscall_name(call));

    u64 (*h)(u64, u64, u64, u64, u64, u64) = current->p->syscall_handlers[call];
    u64 res = -ENOENT;
    if (h) {
        res = h(f[FRAME_RDI], f[FRAME_RSI], f[FRAME_RDX], f[FRAME_R10], f[FRAME_R8], f[FRAME_R9]);
    } else {
        rprintf("nosyscall %s\n", syscall_name(call));
    }
    return res;
}

kernel init_unix(heap h,
		 heap pages,
		 heap physical,
		 heap virtual,
		 heap virtual_pagesized,
		 heap backed,
		 tuple root,
		 filesystem fs)
{
    kernel k = allocate(h, sizeof(struct kernel));
    if (k == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    k->general = h;
    k->pages = pages;
    k->physical = physical;
    k->virtual = virtual;
    k->virtual_pagesized = virtual_pagesized;
    k->backed = backed;

    /* a failure here means termination; just leak */
    k->processes = create_id_heap(h, 1, 65535, 1);
    k->file_cache = allocate_objcache(h, backed, sizeof(struct file));
    if (k->file_cache == INVALID_ADDRESS)
	goto alloc_fail;
    if (!poll_init(k))
	goto alloc_fail;
    k->root = root;
    k->fs = fs;
    set_syscall_handler(syscall_enter);
    process kernel_process = create_process(k);
    current = create_thread(kernel_process);
    frame = current->frame;
    init_vdso(physical, pages);
    register_file_syscalls(linux_syscalls);
#ifdef NET
    if (!netsyscall_init(k))
	goto alloc_fail;
    register_net_syscalls(linux_syscalls);
#endif
    register_signal_syscalls(linux_syscalls);
    register_mmap_syscalls(linux_syscalls);
    register_thread_syscalls(linux_syscalls);
    register_poll_syscalls(linux_syscalls);
    //buffer b = install_syscall(h);
    //syscall = b->contents;
    // debug the synthesized version later, at least we have the table dispatch
    syscall = syscall_debug;
    return k;
  alloc_fail:
    msg_err("failed to allocate kernel objects\n");
    return INVALID_ADDRESS;
}
