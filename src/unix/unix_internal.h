#pragma once
#include <runtime.h>
#include <syscalls.h>
#include <system_structs.h>
#include <tfs.h>
#include <unix.h>

/* XXX kinda arbitrary, not sure where these came from or what correct
   values should be */
#define PROCESS_VIRTUAL_HEAP_START      0x7000000000ull
#define PROCESS_VIRTUAL_HEAP_LENGTH     0x10000000000ull
#define PROCESS_VIRTUAL_HEAP_END        (PROCESS_VIRTUAL_HEAP_START + PROCESS_VIRTUAL_HEAP_LENGTH - 1)
#define PROCESS_VIRTUAL_32_HEAP_START   0x10000000
#define PROCESS_VIRTUAL_32_HEAP_LENGTH  0x6f000000
#define PROCESS_VIRTUAL_32_HEAP_END     (PROCESS_VIRTUAL_32_HEAP_START + PROCESS_VIRTUAL_32_HEAP_LENGTH - 1)

typedef s64 sysreturn;

// conditionalize
// fix config/build, remove this include to take off network
#include <net.h>

typedef struct process *process;
typedef struct thread *thread;

thread create_thread(process);
void exit_thread(thread);

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

#define NAME_MAX 255

struct linux_dirent64 {
    u64            d_ino;    /* 64-bit inode number */
    u64            d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

#define CPU_SET_SIZE    1024
#define CPU_SET_WORDS   (CPU_SET_SIZE >> 6)
typedef struct {
    u64 mask[CPU_SET_WORDS];
} cpu_set_t;

/* unix-specific memory objects and ids */
typedef struct unix_heaps {
    struct kernel_heaps kh;	/* must be first */

    /* object caches */
    heap file_cache;
    heap epoll_cache;
    heap epollfd_cache;
    heap epoll_blocked_cache;
    heap pipe_cache;
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
    int *clear_tid;
    int tid;
    thunk run;
    queue log[64];
} *thread;

typedef closure_type(io, sysreturn, void *, u64 length, u64 offset);

#include <notify.h>

#define FDESC_TYPE_REGULAR      1
#define FDESC_TYPE_DIRECTORY    2
#define FDESC_TYPE_SPECIAL      3
#define FDESC_TYPE_SOCKET       4
#define FDESC_TYPE_PIPE         5
#define FDESC_TYPE_STDIO        6
#define FDESC_TYPE_EPOLL        7

typedef struct fdesc {
    io read, write;
    closure_type(check, boolean, u32 eventmask, u32 * last, event_handler eh);
    closure_type(close, sysreturn);
    u64 refcnt;
    int type;
    int flags;                  /* F_GETFD/F_SETFD flags */
} *fdesc;

struct file {
    struct fdesc f;             /* must be first */
    tuple n;
    u64 offset;
    u64 length;
};

typedef struct file *file;

typedef struct process {
    unix_heaps uh;		/* non-thread-specific */
    int pid;
    // i guess this should also be a heap, brk is so nasty
    void *brk;
    heap virtual;
    heap virtual_page;
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
    rangemap vmap;                /* virtual areas */
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

void fdesc_init(fdesc f, int type);

u64 allocate_fd(process p, void *f);

void deallocate_fd(process p, int fd);

void init_vdso(heap, heap);

static inline timestamp time_from_timeval(const struct timeval *t)
{
    return seconds(t->tv_sec) + microseconds(t->tv_usec);
}

static inline void timeval_from_time(struct timeval *d, timestamp t)
{
    d->tv_sec = t / TIMESTAMP_SECOND;
    d->tv_usec = usec_from_timestamp(t);
}

static inline timestamp time_from_timespec(const struct timespec *t)
{
    return seconds(t->ts_sec) + nanoseconds(t->ts_nsec);
}

static inline void timespec_from_time(struct timespec *ts, timestamp t)
{
    ts->ts_sec = t / TIMESTAMP_SECOND;
    ts->ts_nsec = nsec_from_timestamp(t);
}

static inline time_t time_t_from_time(timestamp t)
{
    return t / TIMESTAMP_SECOND;
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
boolean pipe_init(unix_heaps uh);
#define sysreturn_from_pointer(__x) ((s64)u64_from_pointer(__x));

extern sysreturn syscall_ignore();
//CLOSURE_1_1(default_fault_handler, void, thread, context);
void default_fault_handler(thread t, context frame);
void thread_log_internal(thread t, char *desc, ...);
#define thread_log(__t, __desc, ...) thread_log_internal(__t, __desc, ##__VA_ARGS__)
// this should always be current
void thread_sleep(thread) __attribute__((noreturn));
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

static inline sysreturn sysreturn_value(thread t)
{
    return (sysreturn)t->frame[FRAME_RAX];
}

#define resolve_fd_noret(__p, __fd) vector_get(__p->files, __fd)
#define resolve_fd(__p, __fd) ({void *f ; if (!(f = resolve_fd_noret(__p, __fd))) return set_syscall_error(current, EBADF); f;})

void init_threads(process p);
void init_syscalls();

int do_pipe2(int fds[2], int flags);

void register_special_files(process p);
sysreturn spec_read(file f, void *dest, u64 length, u64 offset_arg);
sysreturn spec_write(file f, void *dest, u64 length, u64 offset_arg);
u32 spec_events(file f);

#define BLOCKQ_NAME_MAX 20

typedef struct blockq {
    heap h;
    /* spinlock lock; */
    queue waiters;              /* queue of blockq_actions */
    char name[BLOCKQ_NAME_MAX]; /* for debug */
    timer timeout;              /* timeout to protect against stuck queue scenarios */
    timestamp timeout_interval;
} *blockq;

typedef closure_type(blockq_action, sysreturn, boolean);

blockq allocate_blockq(heap h, char * name, u64 size, timestamp timeout_interval);
void deallocate_blockq(blockq bq);
sysreturn blockq_check(blockq bq, thread t, blockq_action a);
void blockq_wake_one(blockq bq);
void blockq_flush(blockq bq);
