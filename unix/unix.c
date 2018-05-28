#include <unix_internal.h>

// conditionalize
// fix config/build, remove this include to take off network
#include <net.h>
#include <gdb.h>

static heap processes;


file allocate_fd(process p, bytes size, int *fd)
{
    file f = allocate(p->h, size);
    // check err
    *fd = allocate_u64(p->fdallocator, 1);
    f->offset = 0;
    f->check = 0;
    f->read = f->write = 0;
    p->files[*fd] = f;    
    return f;
}

static boolean node_contents(tuple t, buffer d)
{
    return false;
}    

void default_fault_handler(thread t, context frame)
{
    print_frame(t->frame);
    print_stack(t->frame);    

    if (table_find (children(t->p->filesystem), sym(fault))) {
        console("starting gdb\n");
        init_tcp_gdb(t->p->h, t->p, 1234);
        thread_sleep(current);
    }
    QEMU_HALT();
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
    p->files[1] = allocate(p->h, sizeof(struct file));
    p->files[1]->write = closure(p->h, stdout);
    p->files[2] = p->files[1];
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
    return b;
}

extern char *syscall_name(int);
static u64 syscall_debug()
{
    u64 *f = current->frame;
    int call = f[FRAME_VECTOR];
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

static void build_exec_stack(buffer s, heap general, vector argv, node env, vector auxp)
{
    int length = vector_length(argv) + table_elements(env) +  2 * vector_length(auxp) + 6;
    s->start = s->end = s->length - length *8;
    buffer_write_le64(s, vector_length(argv));
    tuple i;
    vector_foreach(i, argv) 
        buffer_write_le64(s, u64_from_pointer(aprintf(general, "%b\0\n", contents(i))->contents));
    
    buffer_write_le64(s, 0);

    table_foreach(env, n, v) {
        buffer binding = aprintf(general, "%b=%b\0\n", symbol_string(n), contents(v));
        buffer_write_le64(s, u64_from_pointer(binding->contents));
    }
    buffer_write_le64(s, 0);

    aux a;
    vector_foreach(a, auxp) {
        buffer_write_le64(s, a->tag);
        buffer_write_le64(s, a->val);
    }
    buffer_write_le64(s, 0);
    buffer_write_le64(s, 0);
}

process exec_elf(buffer ex, heap general, heap physical, heap pages, heap virtual, tuple fs)
{
    process p = create_process(general, pages, physical, fs);
    thread t = create_thread(p);
    void *user_entry = load_elf(ex, 0, pages, physical);
    void *actual_entry = user_entry;
    void *va;

    // extra elf munging
    Elf64_Ehdr *elfh = (Elf64_Ehdr *)buffer_ref(ex, 0);


    // also pick up the maximum load address for the brk
    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = (void *)elfh + elfh->e_phoff + (i * elfh->e_phentsize);
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = pointer_from_u64(p->p_vaddr);
        if (p->p_type == PT_INTERP) {
            char *n = (void *)elfh + p->p_offset;
            // xxx - assuming leading slash
            buffer nb = alloca_wrap_buffer(n, runtime_strlen(n));
            // file not found
            tuple ldso = resolve_path(fs, split(general, nb, '/'));
            u64 where = allocate_u64(virtual, HUGE_PAGESIZE);
            buffer c = table_find(ldso, sym(contents));
            user_entry = load_elf(c, where, pages, physical);
        }
    }

    u8 userspace_random_seed[16];

    struct aux auxp[] = {
        {AT_PHDR, elfh->e_phoff + u64_from_pointer(va)},
        {AT_PHENT, elfh->e_phentsize},
        {AT_PHNUM, elfh->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_RANDOM, u64_from_pointer(userspace_random_seed)},        
        {AT_ENTRY, u64_from_pointer(actual_entry)}};
    
    t->frame[FRAME_RIP] = u64_from_pointer(user_entry);
    map(0, INVALID_PHYSICAL, PAGESIZE, pages);
    
    // use runtime random
    u8 seed = 0x3e;
    for (int i = 0; i< sizeof(userspace_random_seed); i++)
        userspace_random_seed[i] = (seed<<3) ^ 0x9e;
    
    vector aux = allocate_vector(general, 10);
    for (int i = 0; i< sizeof(auxp)/(2*sizeof(u64)); i++) 
        vector_push(aux, auxp+i);

    u64 stack_size = 2*1024*1024;
    void *user_stack = allocate(virtual, stack_size);
    buffer s = alloca_wrap_buffer(user_stack, stack_size);       
    map(u64_from_pointer(user_stack), allocate_u64(physical, stack_size), stack_size, pages);

    build_exec_stack(s,
                     general,
                     tuple_vector(general, children(resolve_cstring(fs, "arguments"))),
                     children(resolve_cstring(fs, "environment")),
                     aux);

    t->frame[FRAME_RSP] = u64_from_pointer(buffer_ref(s, 0));
    // move outside?
#if NET && GDB
    if (resolve_cstring(fs, "gdb")) {
        console ("gdb!\n");
        init_tcp_gdb(general, p, 1234);
    } else
#endif
    {
        enqueue(runqueue, t->run);
    }
    return p;    
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
    //buffer b = install_syscall(h);
    //syscall = b->contents;
    // debug the synthesized version later, at least we have the table dispatch
    syscall = syscall_debug;
}


