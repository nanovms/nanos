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
    node n;
} *file;

typedef struct process {
    heap h, pages, physical;
    int pid;
    node filesystem;
    // could resize w/ a vector
    struct file files[FDS];
    void *brk;
    heap virtual;
    heap virtual32;    
    heap fdallocator;
    node cwd; 
    table futices;
    fault_handler handler;
    vector threads;
} *process;

int allocate_fd(process p, io reader, io writer);


void init_unix(heap, heap, heap, tuple);
void run_unix();
thread current;

