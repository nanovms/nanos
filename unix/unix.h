// really unix internal?
#include <syscalls.h>
#include <system_structs.h>

// fix
#define FDS 64

typedef struct process *process;
typedef struct thread *thread;

process create_process(heap h, heap pages, heap contig, node filesystem);
thread create_thread(process);
void run(thread);


typedef struct thread {
    // if we use an array typedef its fragile
    // there are likley assumptions that frame sits at the base of thread
    u64 frame[FRAME_MAX];
    process p;

    void *set_child_tid;
    void *clear_child_tid;
    u64 tid;
    thunk run;
} *thread;


typedef closure_type(io, int, void *, u64 length, u64 offset);

typedef struct file {
    u64 offset; 
    io read, write;
    queue notify;
    node n;
} *file;

typedef struct process {
    heap h, pages, physical;
    int pid;
    node filesystem;
    // could resize w/ a vector
    void *brk;
    heap virtual;
    heap virtual32;    
    heap fdallocator;
    node cwd; 
    table futices;
    fault_handler handler;
    vector threads;
    u64 sigmask;
    void **syscall_handlers;
    file files[FDS];
} *process;

file allocate_fd(process p, bytes size, int *);

void init_unix(heap, heap, heap, tuple);
void run_unix();
thread current;

void init_vdso(heap, heap);

static inline void register_syscall(void **m, int i, void *f)
{
    m[i]= f;
}

void register_file_syscalls(void **);
void register_net_syscalls(void **);
void register_signal_syscalls(void **);
void register_mmap_syscalls(void **);
void register_thread_syscalls(void **);
void register_poll_syscalls(void **);

extern u64 syscall_ignore();
