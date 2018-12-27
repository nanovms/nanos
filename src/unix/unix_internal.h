#pragma once
#include <runtime.h>
#include <syscalls.h>
#include <system_structs.h>
#include <tfs.h>
#include <unix.h>

typedef s64 sysreturn;

// conditionalize
// fix config/build, remove this include to take off network
#include <net.h>

typedef struct process *process;
typedef struct thread *thread;

thread create_thread(process);

void run(thread);

// Taken from the manual pages
// License: http://man7.org/linux/man-pages/man2/getdents.2.license.html
struct linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                        /* length is actually (d_reclen - 2 -
                            offsetof(struct linux_dirent, d_name)) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux
    // 2.6.4); offset is (d_reclen - 1)
    */
};

/* unix-specific memory objects and ids */
typedef struct unix_heaps {
    struct kernel_heaps kh;	/* must be first */

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
} *unix_heaps;

typedef struct epoll *epoll;
typedef struct thread {
    // if we use an array typedef its fragile
    // there are likley assumptions that frame sits at the base of thread
    u64 frame[FRAME_MAX];
    process p;

    /* Heaps in the unix world are typically found through
       current. Copying them here means any heap is accessed through
       one level of indirection. It also allows heaps to be
       substituted on a per-thread basis (e.g. with a debug wrapper, a
       CPU-bound object cache).
    */
    struct unix_heaps uh;

    epoll select_epoll;
    void *set_child_tid;
    void *clear_child_tid;
    u64 tid;
    thunk run;
    queue log[64];
} *thread;

typedef closure_type(io, sysreturn, void *, u64 length, u64 offset);
typedef closure_type(event_handler, boolean, u32 events);

typedef struct file {
    u64 offset;
    u64 length;
    io read, write;
    closure_type(check, boolean, u32 eventmask, u32 * last, event_handler eh);
    closure_type(close, sysreturn);
    tuple n;
} *file;

typedef struct process {
    unix_heaps uh;		/* non-thread-specific */
    int pid;
    // i guess this should also be a heap, brk is so nasty
    void *brk;
    heap virtual;
    heap virtual32;    
    heap fdallocator;
    filesystem fs;	/* XXX should be underneath tuple operators */
    tuple process_root;
    tuple cwd; 
    table futices;
    fault_handler handler;
    vector threads;
    u64 sigmask;
    void **syscall_handlers;
    vector files;
} *process;

extern thread current;

static inline unix_heaps get_unix_heaps()
{
    return &current->uh;
}

static inline kernel_heaps get_kernel_heaps()
{
    return (kernel_heaps)&current->uh;
}

#define unix_cache_alloc(uh, c) ({ heap __c = uh->c ## _cache; allocate(__c, __c->pagesize); })
#define unix_cache_free(uh, c, p) ({ heap __c = uh->c ## _cache; deallocate(__c, p, __c->pagesize); })

u64 allocate_fd(process p, file f);

void deallocate_fd(process p, int fd, file f);

void init_vdso(heap, heap);

static inline timestamp time_from_timeval(struct timeval *t)
{
    return (((u64)t->tv_sec)<<32) + ((((u64)t->tv_usec) * 1000000) / (1ull << 32));
}

static inline void timeval_from_time(struct timeval *d, timestamp t)
{
    u64 micro  = 1000000;
    d->tv_sec = t>>32;
    d->tv_usec = ((t-(d->tv_sec<<32)) * micro) >> 32;
}

static inline timestamp time_from_timespec(struct timespec *t)
{
    return (((u64)t->ts_sec)<<32) + time_from_nsec(t->ts_nsec);
}

static inline void timespec_from_time(struct timespec *ts, timestamp t)
{
    ts->ts_sec = t>>32;
    ts->ts_nsec = nsec_from_time(t - (ts->ts_sec<<32));
}

static inline time_t time_t_from_time(timestamp t)
{
    return t >> 32;
}

static inline void register_syscall(void **m, int i, sysreturn (*f)())
{
    m[i]= f;
}

void register_file_syscalls(void **);
void register_net_syscalls(void **);
void register_signal_syscalls(void **);
void register_mmap_syscalls(void **);
void register_thread_syscalls(void **);
void register_poll_syscalls(void **);
void register_clock_syscalls(void **);

boolean poll_init(unix_heaps uh);
#define sysreturn_from_pointer(__x) ((s64)u64_from_pointer(__x));

extern sysreturn syscall_ignore();
CLOSURE_1_1(default_fault_handler, void, thread, context);
void default_fault_handler(thread t, context frame);
void thread_log_internal(thread t, char *desc, ...);
#define thread_log(__t, __desc, ...) thread_log_internal(__t, __desc, ##__VA_ARGS__)
// this should always be current
void thread_sleep(thread);
void thread_wakeup(thread);

static inline sysreturn set_syscall_return(thread t, sysreturn val)
{
    t->frame[FRAME_RAX] = val;
    return val;
}

static inline sysreturn set_syscall_error(thread t, s32 val)
{
    t->frame[FRAME_RAX] = (sysreturn)-val;
    return (sysreturn)-val;
}

static sysreturn sysreturn_value(thread t)
{
    return (sysreturn)t->frame[FRAME_RAX];
}

#define resolve_fd_noret(__p, __fd) vector_get(__p->files, __fd)
#define resolve_fd(__p, __fd) ({void *f ; if (!(f = resolve_fd_noret(__p, __fd))) return set_syscall_error(current, EBADF); f;})

void init_threads(process p);
void init_syscalls();
