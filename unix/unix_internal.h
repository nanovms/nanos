#include <runtime.h>
#include <syscalls.h>
#include <system_structs.h>
#include <tfs.h>
#include <unix.h>

// fix
#define FDS 64

typedef struct process *process;
typedef struct thread *thread;

process create_process(heap h, heap pages, heap contig, tuple root, filesystem fs);
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
    queue log[64];
} *thread;


typedef closure_type(io, int, void *, u64 length, u64 offset);

typedef struct file {
    u64 offset; 
    io read, write;
    // check if data on the read path
    closure_type(check, void, thunk);
    tuple n;
} *file;

typedef struct process {
    heap h, pages, physical;
    int pid;
    tuple root;
    // xxx - filesystem should be folded underneath tuple operators
    filesystem fs;
    // i guess this should also be a heap, brk is so nasty
    void *brk;
    heap virtual;
    heap virtual32;    
    heap fdallocator;
    tuple cwd; 
    table futices;
    fault_handler handler;
    vector threads;
    u64 sigmask;
    void **syscall_handlers;
    // vector - there is no reason this should be fixed
    file files[FDS];
} *process;

file allocate_fd(process p, bytes size, int *);

thread current;

void init_vdso(heap, heap);

static inline time time_from_timeval(struct timeval *t)
{
    return (((u64)t->tv_sec)<<32) + ((((u64)t->tv_usec) * 1000000) / (1ull << 32));
}

static inline void timeval_from_time(struct timeval *d, time t)
{
    u64 micro  = 1000000;
    d->tv_sec = t>>32;
    d->tv_usec = ((t-(d->tv_sec<<32)) * micro) >> 32;
}

static inline time time_from_timespec(struct timespec *t)
{
    return (((u64)t->ts_sec)<<32) + time_from_nsec(t->ts_nsec);
}

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
CLOSURE_1_1(default_fault_handler, void, thread, context);
void default_fault_handler(thread t, context frame);
void thread_log_internal(thread t, char *desc, ...);
#define thread_log(__t, __desc, ...) thread_log_internal(__t, __desc, ##__VA_ARGS__)
// this should always be current
void thread_sleep(thread);
void thread_wakeup(thread);
static inline void set_syscall_return(thread t, u64 val)
{
    t->frame[FRAME_RAX] = val;
}
