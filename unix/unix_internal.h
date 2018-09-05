#pragma once
#include <runtime.h>
#include <syscalls.h>
#include <system_structs.h>
#include <tfs.h>
#include <unix.h>

// conditionalize
// fix config/build, remove this include to take off network
#include <net.h>

typedef struct process *process;
typedef struct thread *thread;

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
    closure_type(check, void, thunk in, thunk hup);
    closure_type(close, int);
    tuple n;
} *file;

/* kernel "instance", really just a collection of allocators, fs root, etc. */
typedef struct kernel {
    /* memory heaps */
    heap general;
    heap pages;
    heap physical;
    heap virtual;		/* these are for kernel-only mappings; */
    heap virtual_pagesized;	/* not user space */
    heap backed;

    /* object caches */
    heap file_cache;
    heap epoll_cache;
    heap epollfd_cache;
    heap epoll_blocked_cache;
#ifdef NET
    heap socket_cache;
#endif

    /* id heaps */
    heap processes;

    /* filesystem */
    tuple root;
    // xxx - filesystem should be folded underneath tuple operators
    filesystem fs;
} *kernel;

typedef struct process {
    kernel k;
    int pid;
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
    vector files;
} *process;

extern thread current;

u64 allocate_fd(process p, file f);

void deallocate_fd(process p, int fd, file f);

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

boolean poll_init(kernel k);

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

#define resolve_fd(__p, __fd) ({void *f ; if (!(f = vector_get(__p->files, __fd))) return(-EBADF); f;})

