#include <sruntime.h>
#include <unix.h>
// fix config/build, remove this include to take off network
#include <net.h>

static heap processes;


static boolean node_contents(tuple t, buffer d)
{
    return false;
}    

CLOSURE_0_1(default_fault_handler, context, context);

context default_fault_handler(context frame)
{

    u64 v = frame[FRAME_VECTOR];
    console(interrupt_name(v));
    console("\n");
    
    // page fault
    if (v == 14)  {
        u64 fault_address;
        mov_from_cr("cr2", fault_address);
        console("address: ");
        print_u64(fault_address);
        console("\n");
    }

    for (int j = 0; j< 18; j++) {
        console(register_name(j));
        console(": ");
        print_u64(frame[j]);
        console("\n");        
    }

#if 0        
    u64 *stack = pointer_from_u64(frame[FRAME_RSP]);
    for (int j = 0; (frame[FRAME_RSP] + 8*j)  & MASK(15); j++) {
        print_u64(u64_from_pointer(stack + j));
        console (" ");
        print_u64(stack[j]);
        console("\n");        
    }
#endif            
    QEMU_HALT();
    return 0;
}


CLOSURE_1_0(run_thread, void, thread);
void run_thread(thread t)
{
    rprintf("run thread\n");
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
    t->frame[FRAME_FAULT_HANDLER] = u64_from_pointer(p->handler);
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
}

static u64 futex_key_function(void *x)
{
    return u64_from_pointer(x);
}

static boolean futex_key_equal(void *a, void *b)
{
    return a == b;
}

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
    p->fdallocator = create_id_heap(h, 3, FDMAX - 3, 1);
    p->physical = physical;
    p->files[1].write = closure(h, stdout);    
    p->files[2].write = closure(h, stdout);
    p->futices = allocate_table(h, futex_key_function, futex_key_equal);
    p->handler = closure(h, default_fault_handler);
    p->threads = allocate_vector(h, 5);
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
}

