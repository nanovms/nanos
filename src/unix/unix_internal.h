/* main header for unix-specific kernel objects */

#include <kernel.h>
#include <unix_syscalls.h>
#include <pagecache.h>
#include <tfs.h>
#include <unix.h>

#define VMAP_FLAG_PROT_MASK 0x000f
#define VMAP_FLAG_EXEC     0x0001
#define VMAP_FLAG_WRITABLE 0x0002
#define VMAP_FLAG_READABLE 0x0004

#define VMAP_FLAG_MMAP     0x0010
#define VMAP_FLAG_SHARED   0x0020 /* vs private; same semantics as unix */
#define VMAP_FLAG_PREALLOC 0x0040

#define VMAP_MMAP_TYPE_MASK       0x0f00
#define VMAP_MMAP_TYPE_ANONYMOUS  0x0100
#define VMAP_MMAP_TYPE_FILEBACKED 0x0200
#define VMAP_MMAP_TYPE_IORING     0x0400

#define ACCESS_PERM_READ    VMAP_FLAG_READABLE
#define ACCESS_PERM_WRITE   VMAP_FLAG_WRITABLE
#define ACCESS_PERM_EXEC    VMAP_FLAG_EXEC
#define ACCESS_PERM_ALL     \
    (ACCESS_PERM_READ | ACCESS_PERM_WRITE | ACCESS_PERM_EXEC)

#include <system_structs.h>

/* arch dependent bits */
#include <unix_machine.h>

#define PROCESS_VIRTUAL_HEAP_START  0x000100000000ull
#define PROCESS_VIRTUAL_HEAP_LIMIT  USER_LIMIT
#define PROCESS_VIRTUAL_HEAP_LENGTH (PROCESS_VIRTUAL_HEAP_LIMIT - PROCESS_VIRTUAL_HEAP_START)

#define PROCESS_STACK_SIZE          (2 * MB)

/* restrict the area in which ELF segments can be placed */
#define PROCESS_ELF_LOAD_END        (GB) /* 1gb hard upper limit */

/* range of variation for various ASLR mappings; kind of arbitrary at this point */
#define PROCESS_PIE_LOAD_ASLR_RANGE (4 * MB)
#define PROCESS_HEAP_ASLR_RANGE     (4 * MB)
#define PROCESS_STACK_ASLR_RANGE    (4 * MB)

/* This will change if we add support for more clocktypes */
#define VVAR_NR_PAGES               2

extern unsigned long vdso_raw_length;

typedef s64 sysreturn;

// conditionalize
// fix config/build, remove this include to take off network
#include <net.h>
boolean netsyscall_init(unix_heaps uh, tuple cfg);

typedef struct process *process;
typedef struct thread *thread;

thread create_thread(process);
void exit_thread(thread);

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
    heap pipe_cache;
#ifdef NET
    heap socket_cache;
#endif

    /* id heaps */
    id_heap processes;
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
typedef closure_type(blockq_action_handler, void, blockq_action action);

struct blockq;
typedef struct blockq * blockq;

extern io_completion syscall_io_complete;
extern io_completion io_completion_ignore;

static inline sysreturn io_complete(io_completion completion, thread t,
                                    sysreturn rv) {
    apply(completion, t, rv);
    return rv;
}

declare_closure_struct(1, 0, void, free_blockq,
                       blockq, bq)

/* queue of threads waiting for a resource */
#define BLOCKQ_NAME_MAX 20
struct blockq {
    heap h;
    char name[BLOCKQ_NAME_MAX]; /* for debug */
    struct spinlock lock;
    struct list waiters_head;   /* of threads and associated timers+actions */
    struct refcount refcount;
    closure_struct(free_blockq, free);
};

blockq allocate_blockq(heap h, char * name);
void deallocate_blockq(blockq bq);
void blockq_thread_init(thread t);

static inline void blockq_reserve(blockq bq)
{
    refcount_reserve(&bq->refcount);
}

static inline void blockq_release(blockq bq)
{
    refcount_release(&bq->refcount);
}

static inline const char * blockq_name(blockq bq)
{
    return bq->name;
}

thread blockq_wake_one(blockq bq);
boolean blockq_wake_one_for_thread(blockq bq, thread t, boolean nullify);
void blockq_flush(blockq bq);
void blockq_set_completion(blockq bq, io_completion completion, thread t,
                           sysreturn rv);
sysreturn blockq_check_timeout(blockq bq, thread t, blockq_action a, boolean in_bh, 
                               clock_id id, timestamp timeout, boolean absolute);
int blockq_transfer_waiters(blockq dest, blockq src, int n, blockq_action_handler handler);

static inline sysreturn blockq_check(blockq bq, thread t, blockq_action a, boolean in_bh)
{
    return blockq_check_timeout(bq, t, a, in_bh, 0, 0, false);
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
    u64         ignored;        /* mask of signals set to SIG_IGN */
    u64         interest;       /* signals of interest, regardless of mask or ignored */
    struct spinlock   ss_lock;
    struct list heads[NSIG];
} *sigstate;

typedef struct epoll *epoll;
struct ftrace_graph_entry;

#include <notify.h>

struct pending_fault;
declare_closure_struct(1, 1, void, pending_fault_complete,
                       struct pending_fault *, pf,
                       status, s);

typedef struct pending_fault {
    struct rbnode n;            /* must be first */
    u64 addr;
    process p;
    union {
        struct list dependents;
        struct list l_free;
    };
    closure_struct(pending_fault_complete, complete);
    boolean kern;
} *pending_fault;

declare_closure_struct(1, 0, void, free_thread,
                       thread, t);
declare_closure_struct(1, 0, void, resume_syscall,
                       thread, t);
declare_closure_struct(1, 0, void, run_thread,
                       thread, t);
declare_closure_struct(1, 0, void, pause_thread,
                        thread, t);
declare_closure_struct(1, 1, context, default_fault_handler,
                       thread, t,
                       context, frame);
declare_closure_struct(5, 0, void, thread_demand_file_page,
                       pending_fault, pf, struct vmap *, vm, u64, node_offset, u64, page_addr, pageflags, flags);
declare_closure_struct(2, 1, void, thread_demand_page_complete,
                       thread, t, u64, vaddr,
                       status, s);

/* XXX probably should bite bullet and allocate these... */
#define FRAME_MAX_PADDED ((FRAME_MAX + 15) & ~15)

#define thread_frame(t) ((t)->frame)

declare_closure_struct(2, 2, void, blockq_thread_timeout,
                       blockq, bq, struct thread *, t,
                       u64, expiry, u64, overruns);

typedef struct thread {
    struct nanos_thread thrd;
    context frame;

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
    closure_struct(run_thread, run_thread);
    closure_struct(pause_thread, pause_thread);
    closure_struct(default_fault_handler, fault_handler);
    closure_struct(thread_demand_file_page, demand_file_page);
    closure_struct(thread_demand_page_complete, demand_page_complete);

    epoll select_epoll;
    int *clear_tid;
    int tid;
    struct rbnode n;

    /* set by set_robust_list syscall */
    void *robust_list;

    /* blockq data */
    boolean bq_timer_pending;
    struct timer bq_timer;         /* timer for this item */
    closure_struct(blockq_thread_timeout, bq_timeout_func);
    blockq_action bq_action;  /* action to check for wake, timeout or abort */
    struct list bq_l;         /* embedding on blockq->waiters_head */
    io_completion bq_completion;
    sysreturn bq_completion_rv;

    /* blockq thread is waiting on, INVALID_ADDRESS for uninterruptible */
    blockq blocked_on;

    /* set by syscall_return(); used to detect if blocking is necessary */
    boolean syscall_complete;

    /* for waiting on thread-specific conditions rather than a resource */
    blockq thread_bq;

    boolean sysctx;
    timestamp utime, stime;
    timestamp start_time;
    int last_syscall;
    timestamp syscall_enter_ts;
    u64 syscall_time;

    /* signals pending and saved state */
    struct sigstate signals;
    u64 signal_mask;
    u64 saved_signal_mask;      /* for rt_sigsuspend */
    notify_set signalfds;
    boolean interrupting_syscall;
    void *signal_stack;
    u64 signal_stack_length;

    closure_struct(resume_syscall, deferred_syscall);
    bitmap affinity;
    struct list l_faultwait;
    struct spinlock lock;   /* generic lock for struct members without a specific lock */
} *thread;

#define thread_lock(t)      spin_lock(&(t)->lock)
#define thread_unlock(t)    spin_unlock(&(t)->lock)

typedef closure_type(file_io, sysreturn, void *buf, u64 length, u64 offset, thread t,
        boolean bh, io_completion completion);
typedef closure_type(sg_file_io, sysreturn, sg_list sg, u64 length, u64 offset, thread t,
        boolean bh, io_completion completion);

#define FDESC_TYPE_REGULAR      1
#define FDESC_TYPE_DIRECTORY    2
#define FDESC_TYPE_SPECIAL      3
#define FDESC_TYPE_SOCKET       4
#define FDESC_TYPE_PIPE         5
#define FDESC_TYPE_STDIO        6
#define FDESC_TYPE_EPOLL        7
#define FDESC_TYPE_EVENTFD      8
#define FDESC_TYPE_SIGNALFD     9
#define FDESC_TYPE_TIMERFD     10
#define FDESC_TYPE_SYMLINK     11
#define FDESC_TYPE_IORING      12
#define FDESC_TYPE_INOTIFY     13

declare_closure_struct(1, 2, void, fdesc_io_complete,
                       struct fdesc *, f,
                       thread, t, sysreturn, rv);

typedef struct fdesc {
    file_io read, write;
    sg_file_io sg_read, sg_write;
    closure_type(events, u32, thread);
    closure_type(ioctl, sysreturn, unsigned long request, vlist ap);
    closure_type(close, sysreturn, thread t, io_completion completion);
    closure_type(edge_trigger_handler, u64, u64 events, u64 lastevents);
    closure_struct(fdesc_io_complete, io_complete);

    u64 refcnt;
    int type;
    int flags;                  /* F_GETFD/F_SETFD flags */
    notify_set ns;
    struct spinlock lock;
} *fdesc;

#define IOV_MAX 1024

#define FILE_READAHEAD_DEFAULT  (128 * KB)

struct file {
    struct fdesc f;             /* must be first */
    filesystem fs;
    struct {
        fsfile fsf;         /* fsfile for regular files */
        sg_io fs_read;
        sg_io fs_write;
        int fadv;           /* posix_fadvise advice */
    };
    inode n;                /* filesystem inode number */
    u64 offset;
    u64 length;
};

sysreturn ioctl_generic(fdesc f, unsigned long request, vlist ap);

void epoll_finish(epoll e);

typedef struct vmap {
    struct rmnode node;
    u32 flags;
    u32 allowed_flags;
    pagecache_node cache_node;
    u64 node_offset;
    fsfile fsf;
} *vmap;

typedef struct varea {
    struct rmnode node;
    id_heap h;
    boolean allow_fixed;
} *varea;

#define ivmap(__f, __af, __o, __fsf) (struct vmap) {        \
    .flags = __f,                                   \
    .allowed_flags = __f | __af,                    \
    .node_offset = __o,                             \
    .cache_node = __fsf ? fsfile_get_cachenode(__fsf) : 0,  \
    .fsf = __fsf,                                   \
}
typedef closure_type(vmap_handler, void, vmap);

static inline sysreturn set_syscall_return(thread t, sysreturn val)
{
    thread_frame(t)[SYSCALL_FRAME_RETVAL1] = val;
    return val;
}

static inline sysreturn get_syscall_return(thread t)
{
    return thread_frame(t)[SYSCALL_FRAME_RETVAL1];
}

static inline sysreturn set_syscall_error(thread t, s32 val)
{
    thread_frame(t)[SYSCALL_FRAME_RETVAL1] = (sysreturn)-val;
    return (sysreturn)-val;
}

vmap allocate_vmap(rangemap rm, range r, struct vmap q);
boolean adjust_process_heap(process p, range new);

u64 process_get_virt_range(process p, u64 size);
void *process_map_physical(process p, u64 phys_addr, u64 size, u64 vmflags);

typedef struct file *file;

struct syscall;

typedef struct process {
    unix_heaps        uh;       /* non-thread-specific */
    int               pid;
    void             *brk;
    u64               heap_base;
    u64               vdso_base;
    heap              virtual; /* pagesized, default for mmaps */
#ifdef __x86_64__
    id_heap           virtual32; /* for tracking low 32-bit space and MAP_32BIT maps */
#endif
    id_heap           fdallocator;
    filesystem        root_fs;
    filesystem        cwd_fs;
    tuple             process_root;
    inode             cwd;
    table             futices;
    fault_handler     handler;
    rbtree            threads;
    struct spinlock   threads_lock;
    struct syscall   *syscalls;
    vector            files;
    rangemap          vareas;   /* available address space */
    struct spinlock   vmap_lock;
    rangemap          vmaps;    /* process mappings */
    vmap              stack_map;
    vmap              heap_map;
    struct rbtree     pending_faults; /* pending_faults in progress */
    struct spinlock   faulting_lock;
    struct sigstate   signals;
    struct sigaction  sigactions[NSIG];
    id_heap           posix_timer_ids;
    vector            posix_timers; /* unix_timer by timerid */
    vector            itimers;      /* unix_timer by ITIMER_ type */
    id_heap           aio_ids;
    vector            aio;
    boolean           trace;
    boolean           trap;         /* do not run threads when set */
    struct spinlock   lock; /* generic lock for struct members without a specific lock */
} *process;

#define process_lock(p)     spin_lock(&(p)->lock)
#define process_unlock(p)   spin_unlock(&(p)->lock)

typedef struct sigaction *sigaction;

#define SIGACT_SIGINFO  0x00000001
#define SIGACT_SIGNALFD 0x00000002 /* TODO */

extern thread dummy_thread;
#ifdef CURRENT_DEBUG
#define current _current(__func__)
static inline thread _current(const char *caller) {
    if (get_current_thread() == 0 &&
      runtime_strcmp("run_thread_frame", caller) != 0 &&
      runtime_strcmp("thread_wakeup", caller) != 0) {
        log_printf("CURRENT", "invalid address returned to caller '%s'\n", caller);
        print_frame_trace_from_here();
    }
    return (thread)get_current_thread();
}
#else
#define current ((thread)get_current_thread())
#endif


void init_thread_fault_handler(thread t);

static inline boolean proc_is_exec_protected(process p)
{
    return !!get(p->process_root, sym(exec_protection));
}

static inline fsfile file_get_fsfile(file f)
{
    return f->fsf;
}

static inline boolean fdesc_is_readable(fdesc f)
{
    return ((f->flags & O_ACCMODE) != O_WRONLY);
}

static inline boolean fdesc_is_writable(fdesc f)
{
    return ((f->flags & O_ACCMODE) != O_RDONLY);
}

static inline u32 anon_perms(process p)
{
    if (proc_is_exec_protected(p))
        return (ACCESS_PERM_READ | ACCESS_PERM_WRITE);
    return ACCESS_PERM_ALL;
}

static inline u32 file_meta_perms(process p, tuple m)
{
    if (proc_is_exec_protected(p)) {
        if (m && get(m, sym(exec)))
            return (ACCESS_PERM_READ | ACCESS_PERM_EXEC);
        else
            return (ACCESS_PERM_READ | ACCESS_PERM_WRITE);
    }
    return ACCESS_PERM_ALL;
}

static inline u32 file_perms(process p, file f)
{
    tuple n = filesystem_get_meta(f->fs, f->n);
    u32 perms = file_meta_perms(p, n);
    if (n)
        filesystem_put_meta(f->fs, n);
    if (!fdesc_is_readable(&f->f))
        perms &= ~ACCESS_PERM_READ;
    if (!fdesc_is_writable(&f->f))
        perms &= ~ACCESS_PERM_WRITE;
    return perms;
}

static inline void thread_reserve(thread t)
{
    refcount_reserve(&t->refcount);
}

static inline void thread_release(thread t)
{
    refcount_release(&t->refcount);
}

static inline thread thread_from_tid(process p, int tid)
{
    struct thread tk;
    tk.tid = tid;
    thread t;
    spin_lock(&p->threads_lock);
    rbnode n = rbtree_lookup(p->threads, &tk.n);
    if (n != INVALID_ADDRESS) {
        t = struct_from_field(n, thread, n);
        thread_reserve(t);
    }
    spin_unlock(&p->threads_lock);
    if (n == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    return t;
}

unix_heaps get_unix_heaps();

#define unix_cache_alloc(uh, c) ({ heap __c = uh->c ## _cache; allocate(__c, __c->pagesize); })
#define unix_cache_free(uh, c, p) ({ heap __c = uh->c ## _cache; deallocate(__c, p, __c->pagesize); })

#define fdesc_lock(f)   spin_lock(&(f)->lock)
#define fdesc_unlock(f) spin_unlock(&(f)->lock)

static inline void fdesc_put(fdesc f)
{
    if (fetch_and_add(&f->refcnt, -1) == 1)
        apply(f->close, 0, io_completion_ignore);
}

define_closure_function(1, 2, void, fdesc_io_complete,
                        struct fdesc *, f,
                        thread, t, sysreturn, rv)
{
    fdesc_put(bound(f));
    apply(syscall_io_complete, t, rv);
}

static inline void init_fdesc(heap h, fdesc f, int type)
{
    f->read = 0;
    f->write = 0;
    f->sg_read = 0;
    f->sg_write = 0;
    f->close = 0;
    f->events = 0;
    f->edge_trigger_handler = 0;
    init_closure(&f->io_complete, fdesc_io_complete, f);
    f->ioctl = 0;
    f->refcnt = 1;
    f->type = type;
    f->flags = 0;
    f->ns = allocate_notify_set(h);
    spin_lock_init(&f->lock);
}

static inline void release_fdesc(fdesc f)
{
    deallocate_notify_set(f->ns);
}

static inline int fdesc_type(fdesc f)
{
    return f->type;
}

static inline fdesc fdesc_get(process p, int fd)
{
    process_lock(p);
    fdesc f = vector_get(p->files, fd);
    if (f)
        fetch_and_add(&f->refcnt, 1);
    process_unlock(p);
    return f;
}

static inline void fdesc_notify_events(fdesc f)
{
    u32 events = apply(f->events, 0);
    notify_dispatch(f->ns, events);
}

u64 allocate_fd(process p, void *f);

/* Allocate a file descriptor greater than or equal to min. */
u64 allocate_fd_gte(process p, u64 min, void *f);

void deallocate_fd(process p, int fd);

void init_vdso(process p);

void mmap_process_init(process p, boolean aslr);

/* This "validation" is just a simple limit check right now, but this
   could optionally expand to do more rigorous validation (e.g. vmap
   lookup or page table walk). We may also want to place attributes on
   user pointer arguments for use with a static analysis tool like
   Sparse. */

static inline boolean validate_user_memory(const void *p, bytes length, boolean write)
{
    u64 v = u64_from_pointer(p);

    /* no zero page access */
    if (v < PAGESIZE)
        return false;

    if (length >= USER_LIMIT)
        return false;

    return v < USER_LIMIT - length;
}

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
    return seconds(t->tv_sec) + nanoseconds(t->tv_nsec);
}

static inline void timespec_from_time(struct timespec *ts, timestamp t)
{
    ts->tv_sec = sec_from_timestamp(t);
    ts->tv_nsec = nsec_from_timestamp(truncate_seconds(t));
}

static inline time_t time_t_from_time(timestamp t)
{
    return t / TIMESTAMP_SECOND;
}

void init_sigstate(sigstate ss);
void sigstate_flush_queue(sigstate ss);
void sigstate_reset_thread(thread t);
void thread_clone_sigmask(thread dest, thread src);

static inline u64 mask_from_sig(int sig)
{
    assert(sig > 0);
    return U64_FROM_BIT(sig - 1);
}

static inline u64 normalize_signal_mask(u64 mask)
{
    return mask & ~(mask_from_sig(SIGKILL) | mask_from_sig(SIGSTOP));
}

static inline u64 sigstate_get_pending(sigstate ss)
{
    return ss->pending;
}

static inline boolean sigstate_is_pending(sigstate ss, int sig)
{
    return (ss->pending & mask_from_sig(sig)) != 0;
}

static inline sigaction sigaction_from_sig(thread t, int signum)
{
    return &t->p->sigactions[signum - 1];
}

boolean dispatch_signals(thread t);
void deliver_signal_to_thread(thread t, struct siginfo *);
void deliver_signal_to_process(process p, struct siginfo *);
void deliver_fault_signal(u32 signo, thread t, u64 vaddr, s32 si_code);

void threads_to_vector(process p, vector v);

/* machine-specific signal dispatch */
struct rt_sigframe *get_rt_sigframe(thread t);
void setup_sigframe(thread t, int signum, struct siginfo *si);
void restore_ucontext(struct ucontext * uctx, thread t);

void _register_syscall(struct syscall *m, int n, sysreturn (*f)(), const char *name);

#define register_syscall(m, n, f) _register_syscall(m, SYS_##n, f, #n)

void configure_syscalls(process p);
boolean syscall_notrace(process p, int syscall);

void count_syscall(thread t, sysreturn rv);

extern boolean do_syscall_stats;
static inline void count_syscall_save(thread t)
{
    if (do_syscall_stats && !t->syscall_complete) {
        t->syscall_time += usec_from_timestamp(now(CLOCK_ID_MONOTONIC_RAW) - t->syscall_enter_ts);
        t->syscall_enter_ts = 0;
    }
}

static inline void count_syscall_resume(thread t)
{
    if (do_syscall_stats && !t->syscall_complete && t->syscall_enter_ts == 0)
        t->syscall_enter_ts = now(CLOCK_ID_MONOTONIC_RAW);
}

static inline void count_syscall_noreturn(thread t)
{
    if (!do_syscall_stats)
        return;
    t->syscall_time = 0;
    t->last_syscall = -1;
}

void register_file_syscalls(struct syscall *);
void register_net_syscalls(struct syscall *);
void register_signal_syscalls(struct syscall *);
void register_mmap_syscalls(struct syscall *);
void register_thread_syscalls(struct syscall *);
void register_poll_syscalls(struct syscall *);
void register_clock_syscalls(struct syscall *);
void register_timer_syscalls(struct syscall *);
void register_other_syscalls(struct syscall *);

/* Call this routine if RTC offset should ever shift... */
void notify_unix_timers_of_rtc_change(void);

boolean poll_init(unix_heaps uh);
boolean pipe_init(unix_heaps uh);
boolean unix_timers_init(unix_heaps uh);

#define sysreturn_from_pointer(__x) ((s64)u64_from_pointer(__x));

extern sysreturn syscall_ignore();
u64 new_zeroed_pages(u64 v, u64 length, pageflags flags, status_handler complete);
boolean do_demand_page(u64 vaddr, vmap vm, context frame);
vmap vmap_from_vaddr(process p, u64 vaddr);
void vmap_iterator(process p, vmap_handler vmh);
boolean vmap_validate_range(process p, range q);
void truncate_file_maps(process p, fsfile f, u64 new_length);
const char *string_from_mmap_type(int type);

void thread_log_internal(thread t, const char *desc, ...);
#define thread_log(__t, __desc, ...) do {if (!__t || !__t->p->trace) break; thread_log_internal(__t, __desc, ##__VA_ARGS__);} while (0)

void thread_sleep_interruptible(void) __attribute__((noreturn));
void thread_sleep_uninterruptible(thread t) __attribute__((noreturn));
void thread_yield(void) __attribute__((noreturn));
void thread_wakeup(thread);
boolean thread_attempt_interrupt(thread t);

/* XXX This should eventually be rolled into validate_user_memory */
static inline boolean validate_process_memory(process p, const void *a, bytes length, boolean write)
{
    u64 v = u64_from_pointer(a);

    return vmap_validate_range(p, irange(v, v + length));
}

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

static inline sysreturn thread_maybe_sleep_uninterruptible(thread t)
{
    thread_lock(t);
    if (!t->syscall_complete) {
        thread_sleep_uninterruptible(t);
    }
    thread_unlock(t);
    return get_syscall_return(t);
}

static inline sysreturn syscall_return(thread t, sysreturn val)
{
    thread_lock(t);
    set_syscall_return(t, val);
    t->syscall_complete = true;
    if (do_syscall_stats)
        count_syscall(t, val);
    if (t->blocked_on)
        thread_wakeup(t);
    thread_unlock(t);
    return val;
}

void iov_op(fdesc f, boolean write, struct iovec *iov, int iovcnt, u64 offset,
            boolean blocking, io_completion completion);

static inline u64 iov_total_len(struct iovec *iov, int iovcnt)
{
    u64 len = 0;
    for (int i = 0; i < iovcnt; i++)
        len += iov[i].iov_len;
    return len;
}

#define resolve_fd(__p, __fd) ({void *f ; if (!(f = fdesc_get(__p, __fd))) return set_syscall_error(current, EBADF); f;})

void init_syscalls(tuple root);
void init_threads(process p);
void init_futices(process p);

sysreturn futex(int *uaddr, int futex_op, int val, u64 val2, int *uaddr2, int val3);
sysreturn get_robust_list(int pid, void *head, u64 *len);
sysreturn set_robust_list(void *head, u64 len);
void wake_robust_list(process p, void *head);
boolean futex_wake_many_by_uaddr(process p, int *uaddr, int val);

static inline boolean futex_wake_one_by_uaddr(process p, int *uaddr)
{
    return futex_wake_many_by_uaddr(p, uaddr, 1);
}

sysreturn io_setup(unsigned int nr_events, aio_context_t *ctx_idp);
sysreturn io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
sysreturn io_getevents(aio_context_t ctx_id, long min_nr, long nr,
        struct io_event *events, struct timespec *timeout);
sysreturn io_destroy(aio_context_t ctx_id);

sysreturn io_uring_setup(unsigned int entries, struct io_uring_params *params);
sysreturn io_uring_mmap(fdesc desc, u64 len, pageflags mapflags, u64 offset);
sysreturn io_uring_enter(int fd, unsigned int to_submit,
                         unsigned int min_complete, unsigned int flags,
                         sigset_t *sig);
sysreturn io_uring_register(int fd, unsigned int opcode, void *arg,
                            unsigned int nr_args);

int do_pipe2(int fds[2], int flags);
int pipe_set_capacity(fdesc f, int capacity);
int pipe_get_capacity(fdesc f);

sysreturn socketpair(int domain, int type, int protocol, int sv[2]);

typedef struct inotify_evdata {
    string name;
    u32 cookie;
} *inotify_evdata;

sysreturn inotify_init(void);
sysreturn inotify_init1(int flags);
sysreturn inotify_add_watch(int fd, const char *pathname, u32 mask);
sysreturn inotify_rm_watch(int fd, int wd);

int do_eventfd2(unsigned int count, int flags);

typedef closure_type(spec_file_open, sysreturn, file f);

void register_special_files(process p);
boolean create_special_file(const char *path, spec_file_open open, u64 size);
sysreturn spec_open(file f, tuple t);
file spec_allocate(tuple t);
void spec_deallocate(file f);

/* Values to pass as first argument to prctl() */
#define PR_SET_NAME    15               /* Set process name */
#define PR_GET_NAME    16               /* Get process name */

/* getrandom(2) flags */
#define GRND_NONBLOCK               1
#define GRND_RANDOM                 2

#define SIGNAL_STACK_SIZE 8192

void syscall_debug(context f);

boolean validate_iovec(struct iovec *iov, u64 len, boolean write);
boolean validate_user_string(const char *name);

static inline boolean iov_to_sg(sg_list sg, struct iovec *iov, int iovlen)
{
    for (int i = 0; i < iovlen; i++) {
        u64 len = iov[i].iov_len;
        if (len == 0)
            continue;
        sg_buf sgb = sg_list_tail_add(sg, len);
        if (!sgb)
            return false;
        sgb->buf = iov[i].iov_base;
        sgb->size = len;
        sgb->offset = 0;
        sgb->refcount = 0;
    }
    return true;
}

static inline void sg_to_iov(sg_list sg, struct iovec *iov, int iovlen)
{
    for (int i = 0; i < iovlen; i++)
        if (sg_copy_to_buf(iov[i].iov_base, sg, iov[i].iov_len) == 0)
            break;
}
