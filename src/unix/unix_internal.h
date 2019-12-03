#pragma once
#include <runtime.h>
#include <syscalls.h>
#include <system_structs.h>
#include <tfs.h>
#include <unix.h>
#include <x86_64.h>

/* area for mmaps abut the kernel tagged region */
#define PROCESS_VIRTUAL_HEAP_START  0x7000000000ull
#define PROCESS_VIRTUAL_HEAP_END    0x10000000000ull
#define PROCESS_VIRTUAL_HEAP_LENGTH (PROCESS_VIRTUAL_HEAP_END - PROCESS_VIRTUAL_HEAP_START)

#define PROCESS_STACK_SIZE          (2 * MB)

/* restrict the area in which ELF segments can be placed */
#define PROCESS_ELF_LOAD_END        (GB) /* 1gb hard upper limit */

/* range of variation for various ASLR mappings; kind of arbitrary at this point */
#define PROCESS_PIE_LOAD_ASLR_RANGE (4 * MB)
#define PROCESS_HEAP_ASLR_RANGE     (4 * MB)
#define PROCESS_STACK_ASLR_RANGE    (4 * MB)

#define VSYSCALL_BASE                   0xffffffffff600000ull

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

struct linux_dirent64 {
    u64            d_ino;    /* 64-bit inode number */
    u64            d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

struct sysinfo {
    u64 uptime;         /* Seconds since boot */
    u64 loads[3];       /* 1, 5, and 15 minute load averages */
    u64 totalram;       /* Total usable main memory size */
    u64 freeram;        /* Available memory size */
    u64 sharedram;      /* Amount of shared memory */
    u64 bufferram;      /* Memory used by buffers */

    u64 totalswap;      /* Total swap space size */
    u64 freeswap;       /* Swap space still available */
    u16 procs;          /* Number of current processes */
    u16 pad;
    u64 totalhigh;      /* Total high memory size */
    u64 freehigh;       /* Available high memory size */
    u32 mem_unit;       /* Memory unit size in bytes */
    char _f[20-2*sizeof(u64)-sizeof(u32)];
                        /* Padding to 64 bytes */
};

#define CPU_SET_SIZE    1024
#define CPU_SET_WORDS   (CPU_SET_SIZE >> 6)
typedef struct {
    u64 mask[CPU_SET_WORDS];
} cpu_set_t;

typedef struct user_cap_header {
    u32 version;
    int pid;
} *cap_user_header_t;

typedef struct user_cap_data {
    u32 effective;
    u32 permitted;
    u32 inheritable;
} *cap_user_data_t;

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

#define BLOCKQ_ACTION_BLOCKED  1
#define BLOCKQ_ACTION_NULLIFY  2
#define BLOCKQ_ACTION_TIMEDOUT 4

/* This value must not alias any legitimate syscall return value (i.e. -errno). */
#define SYSRETURN_INVALID           (0xffffffff00000000ull) /* outside the range of int errno */
#define SYSRETURN_CONTINUE_BLOCKING SYSRETURN_INVALID
#define BLOCKQ_BLOCK_REQUIRED       SYSRETURN_INVALID

typedef closure_type(io_completion, void, thread t, sysreturn rv);
typedef closure_type(blockq_action, sysreturn, u64 flags);

struct blockq;
typedef struct blockq * blockq;

io_completion syscall_io_complete;

blockq allocate_blockq(heap h, char * name);
void deallocate_blockq(blockq bq);
const char * blockq_name(blockq bq);
thread blockq_wake_one(blockq bq);
void blockq_flush(blockq bq);
boolean blockq_flush_thread(blockq bq, thread t);
void blockq_set_completion(blockq bq, io_completion completion, thread t,
                           sysreturn rv);
sysreturn blockq_check_timeout(blockq bq, thread t, blockq_action a, boolean in_bh, 
                               timestamp timeout, clock_id id);
int blockq_transfer_waiters(blockq dest, blockq src, int n);

static inline sysreturn blockq_check(blockq bq, thread t, blockq_action a, boolean in_bh)
{
    return blockq_check_timeout(bq, t, a, in_bh, 0, 0 /* n/a */);
}

static inline void blockq_handle_completion(blockq bq, u64 bq_flags, io_completion completion, thread t, sysreturn rv)
{
    if (!completion)
        return;
    if (bq_flags & BLOCKQ_ACTION_BLOCKED) {
        blockq_set_completion(bq, completion, t, rv);
    } else {
        apply(completion, t, rv);
    }
}

/* pending and masked signals for a given thread or process */
typedef struct sigstate {
    /* these should be bitmaps, but time is of the essence, and presently NSIG=64 */
    u64         pending;        /* pending and not yet dispatched */
    u64         mask;           /* masked or "blocked" signals are set */
    u64         saved;          /* original mask saved on rt_sigsuspend or handler dispatch */
    u64         ignored;        /* mask of signals set to SIG_IGN */
    struct list heads[NSIG];
} *sigstate;

declare_closure_struct(1, 0, void, free_thread,
                         thread, t);
typedef struct epoll *epoll;
struct ftrace_graph_entry;

typedef struct thread {
    // if we use an array typedef its fragile
    // there are likley assumptions that frame sits at the base of thread
    u64 frame[FRAME_MAX];
    char name[16]; /* thread name */
    int syscall;
    process p;

    /* Heaps in the unix world are typically found through
       current. Copying them here means any heap is accessed through
       one level of indirection. It also allows heaps to be
       substituted on a per-thread basis (e.g. with a debug wrapper, a
       CPU-bound object cache).
    */
    struct unix_heaps uh;

    struct refcount refcount;
    closure_struct(free_thread, free);

    epoll select_epoll;
    int *clear_tid;
    int tid;

    thunk run;

    /* blockq thread is waiting on, INVALID_ADDRESS for uninterruptible */
    blockq blocked_on;

    /* set by file op completion; used to detect if blocking is necessary */
    boolean file_op_is_complete;

    /* for waiting on thread-specific conditions rather than a resource */
    blockq thread_bq;

    struct sigstate signals;
    sigstate dispatch_sigstate; /* while signal handler in flight, save sigstate... */
    u64 saved_rax;              /* ... and t->frame[FRAME_RAX] */
    u64 sigframe[FRAME_MAX];

    /* sigs that can wake thread regardless of mask or ignored
       nonzero when in rt_sigtimedwait) */
    u64 siginterest;

    u16 active_signo;

#ifdef CONFIG_FTRACE
    int graph_idx;
    struct ftrace_graph_entry * graph_stack;
#endif
} *thread;

typedef closure_type(io, sysreturn, void *buf, u64 length, u64 offset, thread t,
        boolean bh, io_completion completion);

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
    closure_type(events, u32);
    closure_type(ioctl, sysreturn, unsigned long request, vlist ap);

    /* close() is assumed to not block the calling thread. If any implementation
     * violates this assumption, the code in dup2() will need to be revisited.
     */
    closure_type(close, sysreturn);

    u64 refcnt;
    int type;
    int flags;                  /* F_GETFD/F_SETFD flags */
    notify_set ns;
} *fdesc;

#define IOV_MAX 1024

struct file {
    struct fdesc f;             /* must be first */
    tuple n;
    u64 offset;
    u64 length;
};

void epoll_finish(epoll e);

#define VMAP_FLAG_MMAP          1
#define VMAP_FLAG_ANONYMOUS     2
#define VMAP_FLAG_WRITABLE      4
#define VMAP_FLAG_EXEC          8

typedef struct vmap {
    struct rmnode node;
    u64 flags;
} *vmap;

vmap allocate_vmap(rangemap rm, range r, u64 flags);
boolean adjust_vmap_range(rangemap rm, vmap v, range new);

typedef struct file *file;

struct syscall;

typedef struct process {
    unix_heaps        uh;       /* non-thread-specific */
    int               pid;
    void             *brk;
    u64               heap_base;
    u64               lowmem_end; /* end of elf / heap / stack area (low 2gb below reserved) */
    heap              virtual;  /* huge virtual, parent of virtual_page */
    heap              virtual_page; /* pagesized, default for mmaps */
    heap              virtual32; /* for tracking low 32-bit space and MAP_32BIT maps */
    heap              fdallocator;
    filesystem        fs;       /* XXX should be underneath tuple operators */
    tuple             process_root;
    tuple             cwd;
    table             futices;
    fault_handler     handler;
    vector            threads;
    struct syscall   *syscalls;
    vector            files;
    rangemap          vareas;   /* available address space */
    rangemap          vmaps;    /* process mappings */
    vmap              stack_map;
    vmap              heap_map;
    boolean           sysctx;
    timestamp         utime, stime;
    timestamp         start_time;
    struct sigstate   signals;
    struct sigaction  sigactions[NSIG];
} *process;

typedef struct sigaction *sigaction;

#define SIGACT_SIGINFO  0x00000001
#define SIGACT_SIGNALFD 0x00000002 /* TODO */

extern thread dummy_thread;
extern thread current;

static inline unix_heaps get_unix_heaps()
{
    assert(current);
    return &current->uh;
}

static inline kernel_heaps get_kernel_heaps()
{
    return (kernel_heaps)get_unix_heaps();
}

#define unix_cache_alloc(uh, c) ({ heap __c = uh->c ## _cache; allocate(__c, __c->pagesize); })
#define unix_cache_free(uh, c, p) ({ heap __c = uh->c ## _cache; deallocate(__c, p, __c->pagesize); })

fault_handler create_fault_handler(heap h, thread t);

void init_fdesc(heap h, fdesc f, int type);

void release_fdesc(fdesc f);

u64 allocate_fd(process p, void *f);

/* Allocate a file descriptor greater than or equal to min. */
u64 allocate_fd_gte(process p, u64 min, void *f);

void deallocate_fd(process p, int fd);

void init_vdso(heap, heap);

void mmap_process_init(process p);

static inline u64 get_aslr_offset(u64 range)
{
    assert((range & (range - 1)) == 0);
    return random_u64() & ((range - 1) & ~MASK(PAGELOG));
}

static inline timestamp time_from_timeval(const struct timeval *t)
{
    return seconds(t->tv_sec) + microseconds(t->tv_usec);
}

static inline void timeval_from_time(struct timeval *d, timestamp t)
{
    d->tv_sec = t / TIMESTAMP_SECOND;
    d->tv_usec = usec_from_timestamp(truncate_seconds(t));
}

static inline timestamp time_from_timespec(const struct timespec *t)
{
    return seconds(t->ts_sec) + nanoseconds(t->ts_nsec);
}

static inline void timespec_from_time(struct timespec *ts, timestamp t)
{
    ts->ts_sec = t / TIMESTAMP_SECOND;
    ts->ts_nsec = nsec_from_timestamp(truncate_seconds(t));
}

static inline time_t time_t_from_time(timestamp t)
{
    return t / TIMESTAMP_SECOND;
}

void init_sigstate(sigstate ss);
void sigstate_flush_queue(sigstate ss);
void sigstate_reset_thread(thread t);
void thread_clone_sigmask(thread dest, thread src);

static inline void sigstate_thread_restore(thread t)
{
    sigstate ss = t->dispatch_sigstate;
    if (ss) {
        t->dispatch_sigstate = 0;
        ss->mask = ss->saved;
        ss->saved = 0;
    }
}

void dispatch_signals(thread t);
void deliver_signal_to_thread(thread t, struct siginfo *);
void deliver_signal_to_process(process p, struct siginfo *);

void _register_syscall(struct syscall *m, int n, sysreturn (*f)(), const char *name);

#define register_syscall(m, n, f) _register_syscall(m, SYS_##n, f, #n)

void configure_syscalls(process p);
boolean syscall_notrace(int syscall);

void register_file_syscalls(struct syscall *);
void register_net_syscalls(struct syscall *);
void register_signal_syscalls(struct syscall *);
void register_mmap_syscalls(struct syscall *);
void register_thread_syscalls(struct syscall *);
void register_poll_syscalls(struct syscall *);
void register_clock_syscalls(struct syscall *);
void register_other_syscalls(struct syscall *);

boolean poll_init(unix_heaps uh);
boolean pipe_init(unix_heaps uh);
#define sysreturn_from_pointer(__x) ((s64)u64_from_pointer(__x));

extern sysreturn syscall_ignore();
boolean unix_fault_page(u64 vaddr, context frame);

void thread_log_internal(thread t, const char *desc, ...);
#define thread_log(__t, __desc, ...) thread_log_internal(__t, __desc, ##__VA_ARGS__)

void thread_sleep_interruptible(void) __attribute__((noreturn));
void thread_sleep_uninterruptible(void) __attribute__((noreturn));
void thread_yield(void) __attribute__((noreturn));
void thread_wakeup(thread);
boolean thread_attempt_interrupt(thread t);

static inline boolean thread_in_interruptible_sleep(thread t)
{
    return t->blocked_on && t->blocked_on != INVALID_ADDRESS;
}

static inline boolean thread_in_uninterruptible_sleep(thread t)
{
    return t->blocked_on == INVALID_ADDRESS;
}

static inline boolean thread_is_runnable(thread t)
{
    return t->blocked_on == 0;
}

static inline sysreturn set_syscall_return(thread t, sysreturn val)
{
    t->frame[FRAME_RAX] = val;
    return val;
}

static inline sysreturn get_syscall_return(thread t)
{
    return t->frame[FRAME_RAX];
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

static inline void file_op_begin(thread t)
{
    t->file_op_is_complete = false;
}

static inline sysreturn file_op_maybe_sleep(thread t)
{
    u64 flags = irq_disable_save(); /* XXX mutex / spinlock */
    if (!t->file_op_is_complete) {
        /* leave ints disabled... */
        thread_sleep_uninterruptible();
    }
    irq_restore(flags);
    return get_syscall_return(t);
}

static inline void file_op_maybe_wake(thread t)
{
    u64 flags = irq_disable_save(); /* XXX mutex / spinlock */
    t->file_op_is_complete = true;
    if (t->blocked_on)
        thread_wakeup(t);
    irq_restore(flags);
}

#define resolve_fd_noret(__p, __fd) vector_get(__p->files, __fd)
#define resolve_fd(__p, __fd) ({void *f ; if (!(f = resolve_fd_noret(__p, __fd))) return set_syscall_error(current, EBADF); f;})

void init_syscalls();
void init_threads(process p);
void init_futices(process p);

sysreturn futex(int *uaddr, int futex_op, int val, u64 val2, int *uaddr2, int val3);
boolean futex_wake_many_by_uaddr(process p, int *uaddr, int val);

static inline boolean futex_wake_one_by_uaddr(process p, int *uaddr)
{
    return futex_wake_many_by_uaddr(p, uaddr, 1);
}

int do_pipe2(int fds[2], int flags);

sysreturn socketpair(int domain, int type, int protocol, int sv[2]);

int do_eventfd2(unsigned int count, int flags);

void register_special_files(process p);
sysreturn spec_open(file f);
sysreturn spec_close(file f);
sysreturn spec_read(file f, void *dest, u64 length, u64 offset_arg, thread t,
        boolean bh, io_completion completion);
sysreturn spec_write(file f, void *dest, u64 length, u64 offset_arg, thread t,
        boolean bh, io_completion completion);
u32 spec_events(file f);

/* Values to pass as first argument to prctl() */
#define PR_SET_NAME    15               /* Set process name */
#define PR_GET_NAME    16               /* Get process name */

/* getrandom(2) flags */
#define GRND_NONBLOCK               1
#define GRND_RANDOM                 2
