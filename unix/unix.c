#include <sruntime.h>
#include <unix.h>

// conditionalize
// fix config/build, remove this include to take off network
#include <net.h>
#include <gdb.h>

static heap processes;


static boolean node_contents(tuple t, buffer d)
{
    return false;
}    

CLOSURE_1_1(default_fault_handler, void, thread, context);

void default_fault_handler(thread t, context frame)
{
    print_frame(t->frame);
    print_stack(t->frame);    

    if (table_find (children(t->p->filesystem), sym(fault))) {
        console("starting gdb\n");
        init_tcp_gdb(t->p->h, t->p, 1234);
        runloop();
    }
    QEMU_HALT();
}


CLOSURE_1_0(run_thread, void, thread);
void run_thread(thread t)
{
    current = t;
    frame = t->frame;
    IRETURN(frame);    
}

thread create_thread(process p)
{
    // heap I guess
    static int tidcount = 1;
    thread t = allocate(p->h, sizeof(struct thread));
    t->p = p;
    t->tid = tidcount++;
    t->set_child_tid = t->clear_child_tid = 0;
    t->frame[FRAME_FAULT_HANDLER] = u64_from_pointer(closure(p->h, default_fault_handler, t));
    t->run = closure(p->h, run_thread, t);
    vector_push(p->threads, t);
    return t;
}

static CLOSURE_0_3(stdout, int, void*, u64, u64);
static int stdout(void *d, u64 length, u64 offset)
{
    character *z = d;
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

process create_process(heap h, heap pages, heap physical, node filesystem)
{
    process p = allocate(h, sizeof(struct process));
    p->filesystem = filesystem;
    p->h = h;
    // stash end of bss? collisions?
    p->brk = pointer_from_u64(0x8000000);
    p->pid = allocate_u64(processes, 1);
    // xxx - take from virtual allocator
    p->virtual = create_id_heap(h, 0x7000000000ull, 0x10000000000ull, 0x100000000);
    p->virtual32 = create_id_heap(h, 0x10000000, 0xe0000000, PAGESIZE);
    p->pages = pages;
    p->cwd = filesystem;
    p->fdallocator = create_id_heap(h, 3, FDMAX - 3, 1);
    p->physical = physical;
    p->files[1].write = closure(h, stdout);    
    p->files[2].write = closure(h, stdout);
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
    rprintf ("current location: %p\n", current);
    mov_64_imm(b, working, u64_from_pointer(current));
    indirect_displacement(b, REGISTER_A, REGISTER_A, offsetof(thread, p));
    indirect_displacement(b, REGISTER_A, REGISTER_A, offsetof(process, syscall_handlers));
    indirect_scale(b, REGISTER_A, 3, REGISTER_B, REGISTER_A);
    jump_indirect(b, REGISTER_A);
    rprintf("generatron %X\n", b);
    return b;
}

extern char *syscall_name(int);
static u64 syscall_debug()
{
    u64 *f = current->frame;
    int call = f[FRAME_VECTOR];
    u64 (*h)(u64, u64, u64, u64, u64, u64) = current->p->syscall_handlers[call];
    u64 res = -ENOENT;
    if (h) {
        res = h(f[FRAME_RDI], f[FRAME_RSI], f[FRAME_RDX], f[FRAME_R10], f[FRAME_R8], f[FRAME_R9]);
        rprintf ("sys %s returns %d\n", syscall_name(call), res);
    } else {
        rprintf("nosyscall %s\n", syscall_name(call));
    }
    return res;
}

void init_unix(heap h, heap pages, heap physical, tuple filesystem)
{
    set_syscall_handler(syscall_enter);
    // could wrap this in a 'system'
    processes = create_id_heap(h, 1, 65535, 1);
    process kernel = create_process(h, pages, physical, filesystem);
    current = create_thread(kernel);
    frame = current->frame;
    init_vdso(physical, pages);
    register_file_syscalls(linux_syscalls);
#ifdef NET    
    register_net_syscalls(linux_syscalls);
#endif
    register_signal_syscalls(linux_syscalls);
    register_mmap_syscalls(linux_syscalls);
    register_thread_syscalls(linux_syscalls);
    register_poll_syscalls(linux_syscalls);
    buffer b = install_syscall(h);
    //rprintf ("syscall handler: %p %p\n", b->contents , *(u64 *)b->contents);
    syscall = b->contents;
    // debug the synthesized version later, at least we have the table dispatch
    syscall = syscall_debug;
}


