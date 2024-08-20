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
#define VMAP_FLAG_STACK    0x0040
#define VMAP_FLAG_HEAP     0x0080
#define VMAP_FLAG_PROG     0x1000
#define VMAP_FLAG_BSS      0x2000
#define VMAP_FLAG_TAIL_BSS 0x4000
#define VMAP_FLAG_THP      0x8000   /* Transparent Huge Pages */

#define VMAP_MMAP_TYPE_MASK       0x0f00
#define VMAP_MMAP_TYPE_ANONYMOUS  0x0100
#define VMAP_MMAP_TYPE_FILEBACKED 0x0200
#define VMAP_MMAP_TYPE_CUSTOM     0x0400

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
#define PROCESS_VIRTUAL_MMAP_RANGE  (irange(PROCESS_VIRTUAL_HEAP_START, PROCESS_VIRTUAL_HEAP_LIMIT))
#define PROCESS_VIRTUAL_32BIT_RANGE (irange(2ull * GB, 4ull * GB))

#define PROCESS_STACK_SIZE          (2 * MB)
#define PROCESS_STACK_PREALLOC_SIZE PAGESIZE

/* restrict the area in which ELF segments can be placed */
#define PROCESS_ELF_LOAD_END        (3ull * GB) /* 3gb hard upper limit */

/* range of variation for various ASLR mappings; kind of arbitrary at this point */
#define PROCESS_PIE_LOAD_ASLR_RANGE (4 * MB)
#define PROCESS_HEAP_ASLR_RANGE     (4 * MB)
#define PROCESS_STACK_ASLR_RANGE    (4 * MB)

#define NAUX                        32

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

thread create_thread(process, u64 tid);
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
    caching_heap file_cache;
    caching_heap pipe_cache;
#ifdef NET
    caching_heap socket_cache;
#endif
    closure_struct(mem_cleaner, mem_cleaner);

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

closure_type(io_completion, void, sysreturn rv);
closure_type(blockq_action, sysreturn, u64 flags);
closure_type(blockq_action_handler, void, blockq_action action);

struct blockq;
typedef struct blockq * blockq;

declare_closure_struct(1, 2, void, blockq_thread_timeout,
                       blockq, bq,
                       u64 expiry, u64 overruns);
typedef struct unix_context {
    struct kernel_context kc;
    blockq blocked_on;  /* blockq context is waiting on, INVALID_ADDRESS for uninterruptible */
    boolean bq_timer_pending;
    struct timer bq_timer;
    clock_id bq_clkid;
    timestamp bq_remain_at_wake;    /* remaining time at timer removal */
    closure_struct(blockq_thread_timeout, bq_timeout_func);
    blockq_action bq_action;    /* action to check for wake, timeout or abort */
    struct list bq_l;           /* embedding on blockq->waiters_head */
    struct spinlock lock;
} *unix_context;

void init_unix_context(unix_context uc, int type, int size, queue free_ctx_q);

typedef struct process_context {
    struct unix_context uc;
    process p;
    timestamp start_time;
} *process_context;

process_context get_process_context(void);

typedef struct syscall_context {
    struct unix_context uc;
    thread t;                   /* corresponding thread */
    timestamp start_time;
    int call;                   /* syscall number */
} *syscall_context;

syscall_context allocate_syscall_context(cpuinfo ci);

extern struct syscall * const linux_syscalls;
extern io_completion syscall_io_complete;
extern io_completion io_completion_ignore;

static inline sysreturn io_complete(io_completion completion,
                                    sysreturn rv) {
    apply(completion, rv);
    return rv;
}

/* queue of threads waiting for a resource */
struct blockq {
    heap h;
    sstring name;   /* for debug */
    boolean wake;
    struct spinlock lock;
    struct list waiters_head;   /* of threads and associated timers+actions */
    struct refcount refcount;
    closure_struct(thunk, free);
};

void blockq_init(blockq bq, sstring name);
blockq allocate_blockq(heap h, sstring name);
void deallocate_blockq(blockq bq);
void blockq_thread_init(unix_context t);

static inline void blockq_reserve(blockq bq)
{
    refcount_reserve(&bq->refcount);
}

static inline void blockq_release(blockq bq)
{
    refcount_release(&bq->refcount);
}

static inline sstring blockq_name(blockq bq)
{
    return bq->name;
}

unix_context blockq_wake_one(blockq bq);
boolean blockq_wake_one_for_thread(blockq bq, unix_context t, boolean nullify);
void blockq_flush(blockq bq);
sysreturn blockq_check_timeout(blockq bq, blockq_action a, boolean in_bh,
                               clock_id id, timestamp timeout, boolean absolute);
int blockq_transfer_waiters(blockq dest, blockq src, int n, blockq_action_handler handler);

static inline sysreturn blockq_check(blockq bq, blockq_action a, boolean in_bh)
{
    return blockq_check_timeout(bq, a, in_bh, 0, 0, false);
}

/* pending and masked signals for a given thread or process */
typedef struct sigstate {
    /* these should be bitmaps, but time is of the essence, and presently NSIG=64 */
    u64         pending;        /* pending and not yet dispatched */
    u64         interest;       /* signals of interest, regardless of mask or ignored */
    struct spinlock   ss_lock;
    struct list heads[NSIG];
} *sigstate;

typedef struct epoll *epoll;
struct ftrace_graph_entry;

#include <notify.h>

typedef struct pending_fault {
    u64 addr;
    process p;
    context ctx;
    enum {
        PENDING_FAULT_ANONYMOUS,
        PENDING_FAULT_FILEBACKED,
    } type;
    union {
        struct {
        } anonymous;
        struct {
            pagecache_node pn;
            u64 node_offset;
            closure_struct(pagecache_page_handler, demand_file_page);
            void *page_kvirt;
        } filebacked;
    };
    struct list l_free;
    closure_struct(thunk, async_handler);
    closure_struct(thunk, complete);
} *pending_fault;

/* XXX probably should bite bullet and allocate these... */
#define FRAME_MAX_PADDED ((FRAME_MAX + 15) & ~15)

#define thread_frame(t) ((t)->context.frame)

typedef struct thread {
    struct context context;

    char name[16]; /* thread name */
    syscall_context syscall;
    struct sched_task task;
    sched_queue scheduling_queue;
    process p;

    /* Heaps in the unix world are typically found through
       current. Copying them here means any heap is accessed through
       one level of indirection. It also allows heaps to be
       substituted on a per-thread basis (e.g. with a debug wrapper, a
       CPU-bound object cache).
    */
    struct unix_heaps uh;

    closure_struct(thunk, free);
    closure_struct(thunk, thread_return);

    epoll select_epoll;
    int *clear_tid;
    int tid;
    struct rbnode n;

    /* set by set_robust_list syscall */
    void *robust_list;

    /* set by syscall_return(); used to detect if blocking is necessary */
    boolean syscall_complete;

    /* for waiting on thread-specific conditions rather than a resource */
    blockq thread_bq;

    timestamp utime, stime;
    timestamp start_time;
    closure_struct(clock_now, now);
    timerqueue cpu_timers;

    /* signals pending and saved state */
    struct sigstate signals;
    u64 signal_mask;
    u64 saved_signal_mask;      /* for rt_sigsuspend */
    boolean interrupting_syscall;
    void *signal_stack;
    u64 signal_stack_length;

    struct spinlock lock;   /* generic lock for struct members without a specific lock */

#ifdef CONFIG_TRACELOG
    tuple tracelog_attrs;
#endif
} *thread;

static inline timestamp thread_cputime(thread t)
{
    return t->utime + t->stime;
}

#define thread_lock(t)      spin_lock(&(t)->lock)
#define thread_unlock(t)    spin_unlock(&(t)->lock)

struct vmap;

closure_type(file_io, sysreturn, void *buf, u64 length, u64 offset, context ctx, boolean bh,
             io_completion completion);
closure_type(file_iov, sysreturn, struct iovec *iov, int count, u64 offset, context ctx, boolean bh,
             io_completion completion);
closure_type(fdesc_events, u32, thread t);
closure_type(fdesc_ioctl, sysreturn, unsigned long request, vlist ap);
closure_type(fdesc_mmap, sysreturn, struct vmap *vm, u64 offset);
closure_type(fdesc_close, sysreturn, context ctx, io_completion completion);
closure_type(fdesc_et_handler, u64, u64 events, u64 lastevents);

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

typedef struct fdesc {
    file_io read, write;
    file_iov readv, writev;
    fdesc_events events;
    fdesc_ioctl ioctl;
    fdesc_mmap mmap;
    fdesc_close close;
    fdesc_et_handler edge_trigger_handler;
    closure_struct(io_completion, io_complete);

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
    closure_struct(file_io, read);
    closure_struct(file_io, write);
    closure_struct(file_iov, readv);
    closure_struct(file_iov, writev);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_close, close);
};

/* Allocates a file descriptor and returns its value (or an error code) */
int unix_file_new(filesystem fs, tuple md, int type, int flags, fsfile fsf);

sysreturn ioctl_generic(fdesc f, unsigned long request, vlist ap);

void epoll_finish(epoll e);

typedef struct vmap {
    struct rmnode node;
    u32 flags;
    u32 allowed_flags;
    pagecache_node cache_node;
    u64 node_offset;
    union {
        fdesc fd;
        u64 bss_offset;
    };
} *vmap;

#define ivmap(__f, __af, __o, __c, __fd) (struct vmap) {    \
    .flags = __f,                                   \
    .allowed_flags = __f | __af,                    \
    .node_offset = __o,                             \
    .cache_node = __c,                              \
    .fd = __fd,                                     \
}
closure_type(vmap_handler, boolean, vmap vm);

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

void blockq_resume_blocking(blockq bq, unix_context t);

static inline sysreturn blockq_block_required(unix_context t, u64 bq_flags)
{
    if (bq_flags & BLOCKQ_ACTION_BLOCKED)
        blockq_resume_blocking(t->blocked_on, t);
    return BLOCKQ_BLOCK_REQUIRED;
}

vmap allocate_vmap(process p, range r, struct vmap q);
boolean adjust_process_heap(process p, range new);

u64 process_get_virt_range(process p, u64 size, range region);
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
    id_heap           fdallocator;
    filesystem        root_fs;
    filesystem        cwd_fs;
    tuple             process_root;
    inode             cwd;
    table             futices;
    closure_struct(fault_handler, fault_handler);
    rbtree            threads;
    struct spinlock   threads_lock;
    struct syscall   *syscalls;
    vector            files;
    u64               mmap_min_addr;
    struct spinlock   vmap_lock;
    rangemap          vmaps;    /* process mappings */
    vmap              stack_map;
    vmap              heap_map;
    struct aux        saved_aux[NAUX];
    char             *saved_args_begin;
    char             *saved_args_end;
    struct sigstate   signals;
    struct sigaction  sigactions[NSIG];
    notify_set        signalfds;
    id_heap           posix_timer_ids;
    vector            posix_timers; /* unix_timer by timerid */
    vector            itimers;      /* unix_timer by ITIMER_ type */
    timestamp         utime, stime;
    closure_struct(clock_now, now);
    timerqueue        cpu_timers;
    id_heap           aio_ids;
    vector            aio;
    u8                trace;
    boolean           trap;         /* do not run threads when set */
    struct spinlock   lock; /* generic lock for struct members without a specific lock */
} *process;

static inline timestamp proc_cputime(process p)
{
    return p->utime + p->stime;
}

#define process_lock(p)     spin_lock(&(p)->lock)
#define process_unlock(p)   spin_unlock(&(p)->lock)

typedef struct sigaction *sigaction;

#define SIGACT_SIGINFO  0x00000001
#define SIGACT_SIGNALFD 0x00000002 /* TODO */

extern thread dummy_thread;

// TODO could isolate thread type uses to eliminate conditional
#define get_current_thread() \
    ({context _ctx = get_current_context(current_cpu());                \
        _ctx->type == CONTEXT_TYPE_SYSCALL ? ((syscall_context)_ctx)->t : \
            (_ctx->type == CONTEXT_TYPE_THREAD ? (thread)_ctx : 0);})

#ifdef CURRENT_DEBUG
#define current _current(func_ss)
static inline thread _current(sstring caller) {
    thread t = get_current_thread();
    if (t == 0 && runtime_strcmp(ss("run_thread_frame"), caller) != 0 &&
        runtime_strcmp(ss("thread_wakeup"), caller) != 0) {
        log_printf(ss("CURRENT"), ss("invalid address returned to caller '%s'\n"), caller);
        print_frame_trace_from_here();
    }
    return t;
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
    u32 perms;
    if (proc_is_exec_protected(p)) {
        if (m && get(m, sym(exec)))
            perms = ACCESS_PERM_READ | ACCESS_PERM_EXEC;
        else
            perms = ACCESS_PERM_READ | ACCESS_PERM_WRITE;
    } else {
        perms = ACCESS_PERM_ALL;
    }
    if ((perms & ACCESS_PERM_WRITE) && m && get(m, sym(readonly)))
        perms &= ~ACCESS_PERM_WRITE;
    return perms;
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
    refcount_reserve(&t->context.refcount);
}

static inline void thread_release(thread t)
{
    refcount_release(&t->context.refcount);
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

#define unix_cache_alloc(uh, c) ({ heap __c = (heap)uh->c ## _cache; allocate(__c, __c->pagesize); })
#define unix_cache_free(uh, c, p) ({ heap __c = (heap)uh->c ## _cache; deallocate(__c, p, __c->pagesize); })

#define fdesc_lock(f)   spin_lock(&(f)->lock)
#define fdesc_unlock(f) spin_unlock(&(f)->lock)

static inline void fdesc_put(fdesc f)
{
    if (fetch_and_add(&f->refcnt, -1) == 1)
        apply(f->close, 0, io_completion_ignore);
}

void init_fdesc(heap h, fdesc f, int type);
void release_fdesc(fdesc f);

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

boolean copy_from_user(const void *uaddr, void *kaddr, u64 len);
boolean copy_to_user(void *uaddr, const void *kaddr, u64 len);

#define get_user_value(addr, val_p) copy_from_user(addr, val_p, sizeof(*(val_p)))
#define set_user_value(addr, val)   copy_to_user(addr, &(val), sizeof(val))

boolean validate_user_memory_permissions(process p, const void *buf, bytes length,
                                         u64 required_flags, u64 disallowed_flags);

boolean fault_in_memory(const void *buf, bytes length);
boolean fault_in_user_memory(const void *buf, bytes length, boolean writable);

void mmap_process_init(process p, tuple root);

/* This "validation" is just a simple limit check right now, but this
   could optionally expand to do more rigorous validation (e.g. vmap
   lookup or page table walk). We may also want to place attributes on
   user pointer arguments for use with a static analysis tool like
   Sparse. */

static inline boolean validate_user_memory(const void *p, bytes length, boolean write)
{
    u64 v = u64_from_pointer(p);

    if (v < MIN(PAGESIZE, current->p->mmap_min_addr))
        return false;

    if (length >= USER_LIMIT)
        return false;

    return v < USER_LIMIT - length;
}

static inline u64 grow_and_validate_stack(thread t, u64 sp, u64 size)
{
    if (!validate_user_memory_permissions(t->p, pointer_from_u64(sp - size), size, VMAP_FLAG_WRITABLE, 0))
        return INVALID_PHYSICAL;
    return sp - size;
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
boolean setup_sigframe(thread t, int signum, struct siginfo *si);
void restore_ucontext(struct ucontext * uctx, thread t);

void _register_syscall(struct syscall *m, int n, sysreturn (*f)());
void *swap_syscall_handler(struct syscall *m, int n, sysreturn (*f)());

#define register_syscall(m, n, f) _register_syscall(m, SYS_##n, f)

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

#define vmap_lock(p) u64 _savedflags = spin_lock_irq(&(p)->vmap_lock)
#define vmap_unlock(p) spin_unlock_irq(&(p)->vmap_lock, _savedflags)

extern sysreturn syscall_ignore();
status do_demand_page(process p, context ctx, u64 vaddr, vmap vm, boolean *done);
void demand_page_done(context ctx, u64 vaddr, status s);
vmap vmap_from_vaddr(process p, u64 vaddr);
void vmap_iterator(process p, vmap_handler vmh);
boolean vmap_validate_range(process p, range q, u32 flags);
void truncate_file_maps(process p, fsfile f, u64 new_length);
sstring string_from_mmap_type(int type);

void thread_log_internal(thread t, sstring desc, ...);
#define thread_trace(__t, __f, __desc, ...)                 \
    do {                                                    \
        if ((__t) && ((__t)->p->trace & (__f)))             \
        thread_log_internal(__t, ss(__desc), ##__VA_ARGS__);    \
    } while (0)
#define thread_log(__t, __desc, ...)    thread_trace(__t, TRACE_OTHER, __desc, ##__VA_ARGS__)

void thread_sleep_interruptible(void) __attribute__((noreturn));
void thread_sleep_uninterruptible(thread t) __attribute__((noreturn));
void thread_yield(void) __attribute__((noreturn));
void thread_wakeup(thread);
boolean thread_attempt_interrupt(thread t);

timerqueue thread_get_cpu_timer_queue(thread t);

void cputime_update(thread t, timestamp delta, boolean is_utime);

static inline boolean validate_process_memory(process p, const void *a, bytes length, boolean write)
{
    return vmap_validate_range(p, irangel(u64_from_pointer(a), length), write ? VMAP_FLAG_WRITABLE : 0);
}

static inline boolean thread_in_interruptible_sleep(thread t)
{
    if (!t->syscall)
        return false;
    unix_context ctx = &t->syscall->uc;
    return ctx->blocked_on && ctx->blocked_on != INVALID_ADDRESS;
}

static inline boolean thread_in_uninterruptible_sleep(thread t)
{
    if (!t->syscall)
        return false;
    unix_context ctx = &t->syscall->uc;
    return ctx->blocked_on == INVALID_ADDRESS;
}

static inline boolean thread_is_runnable(thread t)
{
    if (!t->syscall)
        return true;
    unix_context ctx = &t->syscall->uc;
    return ctx->blocked_on == 0;
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

static inline void schedule_thread(thread t)
{
    context_schedule_return(&t->context);
}

static inline sysreturn syscall_return(thread t, sysreturn val)
{
    thread_lock(t);
    set_syscall_return(t, val);
    t->syscall_complete = true;
    if (t->syscall && t->syscall->uc.blocked_on)
        thread_wakeup(t);
    thread_unlock(t);
    return val;
}

static inline void syscall_accumulate_stime(syscall_context sc)
{
    assert(sc->start_time != 0);
    thread t = sc->t;
    if (t) {
        timestamp dt = now(CLOCK_ID_MONOTONIC_RAW) - sc->start_time;
        fetch_and_add(&t->stime, dt);
        cputime_update(sc->t, dt, false);
    }
    sc->start_time = 0;
}

/* syscall finish without return (e.g. rt_sigreturn, exit, thread_yield) */
static inline void __attribute__((noreturn)) syscall_finish(boolean exit)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    assert(is_syscall_context(&sc->uc.kc.context));
    thread t = sc->t;
    t->syscall = 0;
    context_release_refcount(&sc->uc.kc.context);
    if (exit) {
        thread_release(t);      /* void frame return reference */
        sc->t = 0;
    } else {
        schedule_thread(t);
    }
    kern_yield();
}

boolean clockid_get(process p, clockid_t id, boolean timer, clock_id *res, thread *cputime_thread);

void iov_op(fdesc f, boolean write, struct iovec *iov, int iovcnt, u64 offset,
            context ctx, boolean blocking, io_completion completion);

static inline u64 iov_total_len(struct iovec *iov, int iovcnt)
{
    u64 len = 0;
    for (int i = 0; i < iovcnt; i++)
        len += iov[i].iov_len;
    return len;
}

#define resolve_fd(__p, __fd) ({void *f ; if (!(f = fdesc_get(__p, __fd))) return set_syscall_error(current, EBADF); f;})

void init_syscalls(process p);
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

typedef struct special_file_wrapper {
    struct file f;
    u64 alloc_size;
} *special_file_wrapper;

closure_type(spec_file_open, sysreturn, file f);

void register_special_files(process p);
boolean create_special_file(sstring path, spec_file_open open, u64 size, u64 rdev);
sysreturn spec_open(file f, tuple t);
file spec_allocate(tuple t);
void spec_deallocate(file f);

void coredump(thread t, struct siginfo *si, status_handler complete);
void reg_copy_out(struct core_regs *r, thread t);
u64 fpreg_size(void);
void fpreg_copy_out(void *b, thread t);

/* Values to pass as first argument to prctl() */
#define PR_SET_NAME    15               /* Set process name */
#define PR_GET_NAME    16               /* Get process name */

/* getrandom(2) flags */
#define GRND_NONBLOCK               1
#define GRND_RANDOM                 2

#define SIGNAL_STACK_SIZE 8192

void syscall_debug(context f);

boolean validate_iovec(struct iovec *iov, u64 len, boolean write);

static inline boolean validate_user_string(const char *name)
{
    u64 a = u64_from_pointer(name);
    while (validate_user_memory(pointer_from_u64(a & ~PAGEMASK),
                                PAGESIZE, false)) {
        u64 lim = (a & ~PAGEMASK) + PAGESIZE;
        while (a < lim) {
            if (*(u8*)pointer_from_u64(a++) == '\0')
                return true;
        }
    }
    return false;
}

static inline boolean fault_in_user_string(const char *name, sstring *res)
{
    u64 a = u64_from_pointer(name);
    while (fault_in_user_memory(pointer_from_u64(a & ~PAGEMASK),
                                PAGESIZE, false)) {
        u64 lim = (a & ~PAGEMASK) + PAGESIZE;
        while (a < lim) {
            if (*(u8*)pointer_from_u64(a) == '\0') {
                res->ptr = (char *)name;
                res->len = a - u64_from_pointer(name);
                return true;
            }
            a++;
        }
    }
    return false;
}

static inline boolean iov_to_sg(sg_list sg, struct iovec *iov, int iovlen)
{
    for (int i = 0; i < iovlen; i++) {
        u64 len = iov[i].iov_len;
        u64 offset = 0;
        while (len > 0) {
            u64 buf_len = MIN(len, U32_MAX & ~PAGEMASK);
            sg_buf sgb = sg_list_tail_add(sg, buf_len);
            if (sgb == INVALID_ADDRESS)
                return false;
            sgb->buf = iov[i].iov_base + offset;
            sgb->size = buf_len;
            sgb->offset = 0;
            sgb->refcount = 0;
            len -= buf_len;
            offset += buf_len;
        }
    }
    return true;
}

static inline void iov_to_buf(void *buf, struct iovec *iov, int iovlen)
{
    for (int i = 0; i < iovlen; i++) {
        u64 len = iov[i].iov_len;
        if (len == 0)
            continue;
        runtime_memcpy(buf, iov[i].iov_base, len);
        buf += len;
    }
}

static inline void check_syscall_context_replace(cpuinfo ci, context ctx)
{
    if (ci->m.syscall_context == ctx) {
        assert(ctx->refcount.c > 1); /* not final release */
        context_release_refcount(ctx);
        ctx = dequeue_single(ci->free_syscall_contexts);
        if (ctx != INVALID_ADDRESS) {
            refcount_set_count(&ctx->refcount, 1);
        } else {
            ctx = (context)allocate_syscall_context(ci);
            assert(ctx != INVALID_ADDRESS);
        }
        ci->m.syscall_context = ctx;
    }
}

static inline void __attribute__((noreturn)) syscall_yield(void)
{
    cpuinfo ci = current_cpu();
    disable_interrupts();
    check_syscall_context_replace(ci, get_current_context(ci));
    kern_yield();
}

