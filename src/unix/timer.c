#include <unix_internal.h>

//#define UNIX_TIMER_DEBUG
#ifdef UNIX_TIMER_DEBUG
#define timer_debug(x, ...) do {log_printf("UTMR", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define timer_debug(x, ...)
#endif

enum unix_timer_type {
    UNIX_TIMER_TYPE_TIMERFD = 1,
    UNIX_TIMER_TYPE_TIMER,      /* timer_create */
    UNIX_TIMER_TYPE_ITIMER
};

typedef struct unix_timer {
    struct fdesc f;             /* used for timerfd only; must be first */
    int type;
    clock_id cid;
    timer t;                    /* zero if disarmed */
    u64 expirations;

    union {
        struct {
            void *timerid;
        } timer;

        struct {
            int itimer_which;
        } itimer;

        struct {
            int fd;
            blockq bq;
            boolean cancel_on_set;
            boolean canceled;   /* by time set */
        } timerfd;
    } info;
} *unix_timer;

static heap unix_timer_heap;

static unix_timer allocate_unix_timer(int type, clock_id cid)
{
    unix_timer ut = allocate(unix_timer_heap, sizeof(struct unix_timer));
    if (ut == INVALID_ADDRESS)
        return ut;
    ut->type = type;
    ut->cid = cid;
    ut->t = 0;
    ut->expirations = 0;
    return ut;
}

static void deallocate_unix_timer(unix_timer t)
{
    deallocate(unix_timer_heap, t, sizeof(struct unix_timer));
}

static void itimerspec_from_timer(unix_timer ut, struct itimerspec *i)
{
    timestamp remain = 0, interval = 0;
    if (ut->t) {
        timer t = ut->t;
        timestamp tnow = now(t->id);
        remain = t->expiry > tnow ? t->expiry - tnow : 0;
        interval = t->interval;
    }
    timespec_from_time(&i->it_value, remain);
    timespec_from_time(&i->it_interval, interval);
}

/* note that all of this assumes that the various timer operations are
   performed in the syscall top half, i.e. with interrupts disabled... */

static inline void timerfd_remove_timer(unix_timer ut)
{
    if (!ut->t)
        return;
    thunk t = ut->t->t;
    remove_timer(ut->t, 0);
    ut->t = 0;
    deallocate_closure(t);
}

closure_function(1, 0, void, timerfd_timer_expire,
                 unix_timer, ut)
{
    unix_timer ut = bound(ut);
    assert(ut->t);
    assert(!ut->t->disabled);

    fetch_and_add(&ut->expirations, 1); /* atomic really necessary? */
    timer_debug("fd %d -> %d\n", ut->info.timerfd.fd, ut->expirations);

    blockq_wake_one(ut->info.timerfd.bq);
    notify_dispatch(ut->f.ns, EPOLLIN);

    if (ut->t->interval == 0)
        timerfd_remove_timer(ut);     /* deallocs closure for us */
}

void notify_unix_timers_of_rtc_change(void)
{
    /* XXX TODO:

       This should be implemented if and when we support explicit
       setting of wall time via settimeofday(2), clock_settime(2),
       update detected from hypervisor, etc. Any such setting of the
       clock should call this function, which in turn should walk
       through the active unix_timers and cancel them as necessary (if
       cancel_on_set).
    */
}

sysreturn timerfd_settime(int fd, int flags,
                          const struct itimerspec *new_value,
                          struct itimerspec *old_value)
{
    if (flags & ~(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET))
        return -EINVAL;

    if (!new_value)
        return -EFAULT;

    unix_timer ut = resolve_fd(current->p, fd); /* macro, may return EBADF */
    if (ut->f.type != FDESC_TYPE_TIMERFD)
        return -EINVAL;

    if (old_value)
        itimerspec_from_timer(ut, old_value);

    ut->info.timerfd.cancel_on_set =
        (ut->cid == CLOCK_REALTIME || ut->cid == CLOCK_REALTIME_ALARM) &&
        (flags ^ (TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)) == 0;

    /* runtime timers are partly immutable; so cancel and re-create on set */
    timerfd_remove_timer(ut);

    timestamp tinit = time_from_timespec(&new_value->it_value);
    timestamp interval = time_from_timespec(&new_value->it_interval);

    timer t = register_timer(ut->cid, tinit, (flags & TFD_TIMER_ABSTIME) != 0, interval,
                             closure(unix_timer_heap, timerfd_timer_expire, ut));
    if (t == INVALID_ADDRESS)
        return -ENOMEM;

    ut->t = t;
    return 0;
}

sysreturn timerfd_gettime(int fd, struct itimerspec *curr_value)
{
    unix_timer ut = resolve_fd(current->p, fd); /* macro, may return EBADF */
    if (ut->f.type != FDESC_TYPE_TIMERFD)
        return -EINVAL;

    if (!curr_value)
        return -EFAULT;

    itimerspec_from_timer(ut, curr_value);
    return 0;
}

closure_function(5, 1, sysreturn, timerfd_read_bh,
                 unix_timer, ut, void *, dest, u64, length, thread, t, io_completion, completion,
                 u64, flags)
{
    unix_timer ut = bound(ut);
    thread t = bound(t);
    boolean blocked = (flags & BLOCKQ_ACTION_BLOCKED) != 0;
    sysreturn rv = sizeof(u64);

    timer_debug("fd %d, dest %p, length %ld, tid %d, flags 0x%lx\n",
                ut->info.timerfd.fd, bound(dest), bound(length), t->tid, flags);

    if (bound(length) < sizeof(u64)) {
        assert(!blocked);
        rv = -EINVAL;
        goto out;
    }

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        assert(blocked);
        rv = -EINTR;
        goto out;
    }

    if (ut->info.timerfd.canceled) {
        rv = -ECANCELED;
        goto out;
    }

    u64 expirations = ut->expirations;
    if (expirations == 0) {
        if (!blocked && (ut->f.flags & TFD_NONBLOCK)) {
            rv = -EAGAIN;
            goto out;
        }
        timer_debug("   -> block\n");
        return BLOCKQ_BLOCK_REQUIRED;
    }

    /* would do atomic swap were it not for ints disabled... */
    *(u64*)bound(dest) = expirations;
    ut->expirations = 0;
  out:
    timer_debug("   -> returning %ld\n", rv);
    blockq_handle_completion(ut->info.timerfd.bq, flags, bound(completion), t, rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, timerfd_read,
                 unix_timer, ut,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    if (length == 0)
        return 0;
    unix_timer ut = bound(ut);
    timer_debug("fd %d, dest %p, length %ld, tid %d, bh %d, completion %p\n", ut->info.timerfd.fd,
                dest, length, t->tid, bh, completion);
    blockq_action ba = closure(unix_timer_heap, timerfd_read_bh, ut, dest, length, t, completion);
    return blockq_check(ut->info.timerfd.bq, t, ba, bh);
}

closure_function(1, 0, u32, timerfd_events,
                 unix_timer, ut)
{
    return bound(ut)->expirations > 0 ? EPOLLIN : 0;
}

closure_function(1, 0, sysreturn, timerfd_close,
                 unix_timer, ut)
{
    unix_timer ut = bound(ut);
    timerfd_remove_timer(ut);
    deallocate_blockq(ut->info.timerfd.bq);
    deallocate_closure(ut->f.read);
    deallocate_closure(ut->f.events);
    deallocate_closure(ut->f.close);
    release_fdesc(&ut->f);
    deallocate_unix_timer(ut);
    return 0;
}

sysreturn timerfd_create(int clockid, int flags)
{
    if (clockid != CLOCK_REALTIME &&
        clockid != CLOCK_MONOTONIC &&
        clockid != CLOCK_BOOTTIME &&
        clockid != CLOCK_REALTIME_ALARM &&
        clockid != CLOCK_BOOTTIME_ALARM)
        return -EINVAL;

    if (flags & ~(TFD_NONBLOCK | TFD_CLOEXEC))
        return -EINVAL;

    unix_timer ut = allocate_unix_timer(UNIX_TIMER_TYPE_TIMERFD, clockid);
    if (ut == INVALID_ADDRESS)
        return -ENOMEM;

    u64 fd = allocate_fd(current->p, ut);
    if (fd == INVALID_PHYSICAL) {
        deallocate_unix_timer(ut);
        return -EMFILE;
    }

    timer_debug("unix_timer %p, fd %d\n", ut, fd);
    init_fdesc(unix_timer_heap, &ut->f, FDESC_TYPE_TIMERFD);
    ut->info.timerfd.fd = fd;
    ut->info.timerfd.bq = allocate_blockq(unix_timer_heap, "timerfd");
    if (ut->info.timerfd.bq == INVALID_ADDRESS)
        goto err_mem_bq;
    ut->info.timerfd.cancel_on_set = false;
    ut->f.flags = flags;
    ut->f.read = closure(unix_timer_heap, timerfd_read, ut);
    ut->f.events = closure(unix_timer_heap, timerfd_events, ut);
    ut->f.close = closure(unix_timer_heap, timerfd_close, ut);
    return fd;
  err_mem_bq:
    deallocate_fd(current->p, fd);
    deallocate_unix_timer(ut);
    return -ENOMEM;
}

#if 0
sysreturn timer_create(clockid_t clockid, struct sigevent *sevp, void **timerid)
{

}
#endif

void register_timer_syscalls(struct syscall *map)
{
    register_syscall(map, timerfd_create, timerfd_create);
    register_syscall(map, timerfd_gettime, timerfd_gettime);
    register_syscall(map, timerfd_settime, timerfd_settime);
}

boolean unix_timers_init(unix_heaps uh)
{
    unix_timer_heap = heap_general((kernel_heaps)uh);
    return true;
}
