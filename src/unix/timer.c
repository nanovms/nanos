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
        } timerfd;
    } info;
} *unix_timer;

static heap unix_timer_heap;

static unix_timer allocate_unix_timer(int type)
{
    unix_timer ut = allocate(unix_timer_heap, sizeof(struct unix_timer));
    if (ut == INVALID_ADDRESS)
        return ut;
    ut->type = type;
    return ut;
}

static void deallocate_unix_timer(unix_timer t)
{
    deallocate(unix_timer_heap, t, sizeof(struct unix_timer));
}

static void timerfd_fill_itimerspec(timer t, struct itimerspec *i)
{
    if (t->t) {
        timestamp tnow = now(t->id);
        timestamp tremain = t->expiry > tnow ? t->expiry - tnow : 0;
        i->it_value.ts_sec = sec_from_timestamp(tremain);
        i->it_value.ts_nsec = nsec_from_timestamp(tremain);
        i->it_interval.ts_sec = sec_from_timestamp(t->interval);
        i->it_interval.ts_nsec = nsec_from_timestamp(t->interval);
    } else {
        i->it_value.ts_sec = 0;
        i->it_value.ts_nsec = 0;
        i->it_interval.ts_sec = 0;
        i->it_interval.ts_nsec = 0;
    }
}

sysreturn timerfd_settime(int fd, int flags,
                          const struct itimerspec *new_value,
                          struct itimerspec *old_value)
{
    unix_timer ut = resolve_fd(current->p, fd); /* macro, may return EBADF */
    if (ut->f.type != FDESC_TYPE_TIMERFD)
        return -EINVAL;

    if (!new_value)
        return -EFAULT;

    if (old_value)
        timerfd_fill_itimerspec(ut->t, old_value);

    
    
    return 0;
}

sysreturn timerfd_gettime(int fd, struct itimerspec *curr_value)
{
    unix_timer ut = resolve_fd(current->p, fd); /* macro, may return EBADF */
    if (ut->f.type != FDESC_TYPE_TIMERFD)
        return -EINVAL;

    if (!curr_value)
        return -EFAULT;

    /* XXX really need a way to take a reference to timer object */
    timerfd_fill_itimerspec(ut->t, curr_value);
    return 0;
}

closure_function(1, 6, sysreturn, timerfd_read,
                 unix_timer, ut,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
//    unix_timer ut = bound(ut);
    if (length == 0)
        return 0;

    return 0; // XXX
}

closure_function(1, 0, u32, timerfd_events,
                 unix_timer, ut)
{
//    unix_timer ut = bound(ut);

    return 0; // XXX
}

closure_function(1, 0, sysreturn, timerfd_close,
                 unix_timer, ut)
{
    // XXX
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

    if (flags & ~(EFD_NONBLOCK | TFD_CLOEXEC))
        return -EINVAL;

    unix_timer ut = allocate_unix_timer(UNIX_TIMER_TYPE_TIMERFD);
    if (ut == INVALID_ADDRESS)
        return -ENOMEM;

    u64 fd = allocate_fd(current->p, ut);
    if (fd == INVALID_PHYSICAL) {
        deallocate_unix_timer(ut);
        return -EMFILE;
    }

    timer_debug("unix_timer %p, fd %d\n", ut, fd);
    init_fdesc(unix_timer_heap, &ut->f, FDESC_TYPE_TIMERFD);
    ut->cid = clockid;
    ut->t = 0;
    ut->info.timerfd.fd = fd;
    ut->info.timerfd.bq = allocate_blockq(unix_timer_heap, "timerfd");
    if (ut->info.timerfd.bq == INVALID_ADDRESS)
        goto err_mem_bq;
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
    
}

void init_unix_timers(kernel_heaps kh)
{
    unix_timer_heap = heap_general(kh);
}
