#include <unix_internal.h>

/* TODO

   - validation of timeval and timespecs parameters across board
   - support for thread and process time(r)s
*/

//#define UNIX_TIMER_DEBUG
#ifdef UNIX_TIMER_DEBUG
#define timer_debug(x, ...) do {log_printf("UTMR", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define timer_debug(x, ...)
#endif

enum unix_timer_type {
    UNIX_TIMER_TYPE_TIMERFD = 1,
    UNIX_TIMER_TYPE_POSIX,      /* POSIX.1b (timer_create) */
    UNIX_TIMER_TYPE_ITIMER
};

typedef struct unix_timer {
    struct fdesc f;             /* used for timerfd only; must be first */
    process p;
    int type;
    clock_id cid;
    timer t;                    /* zero if disarmed */
    u64 overruns;

    union {
        struct {
            struct siginfo si;
            int id;
            thread recipient;   /* INVALID_ADDRESS means deliver to process */
            struct sigevent sevp;
        } posix;

        struct {
            struct siginfo si;
            int which;
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
    ut->p = current->p;
    ut->type = type;
    ut->cid = cid;
    ut->t = 0;
    ut->overruns = 0;
    return ut;
}

static void deallocate_unix_timer(unix_timer t)
{
    deallocate(unix_timer_heap, t, sizeof(struct unix_timer));
}

static void itimerspec_from_timer(unix_timer ut, struct itimerspec *i)
{
    timestamp remain = 0, interval = 0;
    if (ut->t)
        timer_get_remaining(ut->t, &remain, &interval);
    timespec_from_time(&i->it_value, remain);
    timespec_from_time(&i->it_interval, interval);
}

static void itimerval_from_timer(unix_timer ut, struct itimerval *i)
{
    timestamp remain = 0, interval = 0;
    if (ut->t)
        timer_get_remaining(ut->t, &remain, &interval);
    timeval_from_time(&i->it_value, remain);
    timeval_from_time(&i->it_interval, interval);
}

/* note that all of this assumes that the various timer operations are
   performed in the syscall top half, i.e. with interrupts disabled... */

static inline void remove_unix_timer(unix_timer ut)
{
    if (!ut->t)
        return;
    timer_handler t = ut->t->t;
    remove_timer(ut->t, 0);
    ut->t = 0;
    deallocate_closure(t);
}

closure_function(1, 1, void, timerfd_timer_expire,
                 unix_timer, ut,
                 u64, overruns)
{
    unix_timer ut = bound(ut);
    assert(ut->t);
    assert(!ut->t->disabled);

    ut->overruns += overruns;
    timer_debug("interval %ld, fd %d, %d overruns -> %ld\n", ut->t->interval,
                ut->info.timerfd.fd, overruns, ut->overruns);

    blockq_wake_one(ut->info.timerfd.bq);
    notify_dispatch(ut->f.ns, EPOLLIN);

    if (ut->t->interval == 0)
        remove_unix_timer(ut);     /* deallocs closure for us */
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

    if (!validate_user_memory(new_value, sizeof(struct itimerspec), false))
        return -EFAULT;

    unix_timer ut = resolve_fd(current->p, fd); /* macro, may return EBADF */
    if (ut->f.type != FDESC_TYPE_TIMERFD)
        return -EINVAL;

    if (old_value) {
        if (!validate_user_memory(old_value, sizeof(struct itimerspec), true))
            return -EFAULT;
        itimerspec_from_timer(ut, old_value);
    }

    ut->info.timerfd.cancel_on_set =
        (ut->cid == CLOCK_REALTIME || ut->cid == CLOCK_REALTIME_ALARM) &&
        (flags ^ (TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)) == 0;

    /* runtime timers are partly immutable; so cancel and re-create on set */
    remove_unix_timer(ut);
    ut->overruns = 0;

    if (new_value->it_value.tv_sec == 0 && new_value->it_value.tv_nsec == 0)
        return 0;

    timestamp tinit = time_from_timespec(&new_value->it_value);
    timestamp interval = time_from_timespec(&new_value->it_interval);
    boolean absolute = (flags & TFD_TIMER_ABSTIME) != 0;
    timer_debug("register timer: cid %d, init value %T, absolute %d, interval %T\n",
                ut->cid, tinit, absolute, interval);
    timer t = register_timer(runloop_timers, ut->cid, tinit, absolute, interval,
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

    if (!validate_user_memory(curr_value, sizeof(struct itimerspec), true))
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

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        assert(blocked);
        rv = -EINTR;
        goto out;
    }

    if (ut->info.timerfd.canceled) {
        rv = -ECANCELED;
        goto out;
    }

    u64 overruns = ut->overruns;
    if (overruns == 0) {
        if (!blocked && (ut->f.flags & TFD_NONBLOCK)) {
            rv = -EAGAIN;
            goto out;
        }
        timer_debug("   -> block\n");
        return BLOCKQ_BLOCK_REQUIRED;
    }
    *(u64*)bound(dest) = overruns;
    ut->overruns = 0;
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
    if (length < sizeof(u64))
        return io_complete(completion, t, -EINVAL);
    unix_timer ut = bound(ut);
    timer_debug("fd %d, dest %p, length %ld, tid %d, bh %d, completion %p\n", ut->info.timerfd.fd,
                dest, length, t->tid, bh, completion);
    blockq_action ba = closure(unix_timer_heap, timerfd_read_bh, ut, dest, length, t, completion);
    return blockq_check(ut->info.timerfd.bq, t, ba, bh);
}

closure_function(1, 1, u32, timerfd_events,
                 unix_timer, ut,
                 thread, t /* ignored */)
{
    return bound(ut)->overruns > 0 ? EPOLLIN : 0;
}

closure_function(1, 2, sysreturn, timerfd_close,
                 unix_timer, ut,
                 thread, t, io_completion, completion)
{
    unix_timer ut = bound(ut);
    remove_unix_timer(ut);
    deallocate_blockq(ut->info.timerfd.bq);
    deallocate_closure(ut->f.read);
    deallocate_closure(ut->f.events);
    deallocate_closure(ut->f.close);
    release_fdesc(&ut->f);
    deallocate_unix_timer(ut);
    return io_complete(completion, t, 0);
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
    ut->info.timerfd.canceled = false;
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

static unix_timer posix_timer_from_timerid(u32 timerid)
{
    unix_timer ut = vector_get(current->p->posix_timers, timerid);
    if (!ut)
        return INVALID_ADDRESS;
    return ut ? ut : INVALID_ADDRESS;
}

static s32 timer_overruns_s32(unix_timer ut)
{
    return (s32)MIN((u64)S32_MAX, ut->overruns);
}

static void sigev_update_siginfo(unix_timer ut)
{
    struct siginfo *si = &ut->info.posix.si;
    si->sifields.timer.overrun = timer_overruns_s32(ut);
    ut->overruns = 0;
}

static void sigev_deliver(unix_timer ut)
{
    struct sigevent *sevp = &ut->info.posix.sevp;
    switch (sevp->sigev_notify) {
    case SIGEV_NONE:
        break;
    case SIGEV_SIGNAL | SIGEV_THREAD_ID: /* flag or value? */
        assert(ut->info.posix.recipient != INVALID_ADDRESS);
        sigev_update_siginfo(ut);
        deliver_signal_to_thread(ut->info.posix.recipient, &ut->info.posix.si);
        break;
    case SIGEV_SIGNAL:
        sigev_update_siginfo(ut);
        deliver_signal_to_process(ut->p, &ut->info.posix.si);
        break;
    default:
        /* SIGEV_THREAD is a glibc thing; we should never see it. */
        halt("%s: invalid sigev_notify %d\n", __func__, sevp->sigev_notify);
    }
}

closure_function(1, 1, void, posix_timer_expire,
                 unix_timer, ut,
                 u64, overruns)
{
    unix_timer ut = bound(ut);
    assert(ut->t);
    assert(!ut->t->disabled);
    assert(overruns > 0);

    ut->overruns += overruns - 1;
    timer_debug("id %d, interval %ld, +%d -> %d\n",
                ut->info.posix.id, ut->t->interval, overruns, ut->overruns);

    sigev_deliver(ut);

    if (ut->t->interval == 0)
        remove_unix_timer(ut);     /* deallocs closure for us */
}

sysreturn timer_settime(u32 timerid, int flags,
                        const struct itimerspec *new_value,
                        struct itimerspec *old_value) {
    /* Linux doesn't validate flags? */
    if (!validate_user_memory(new_value, sizeof(struct itimerspec), false))
        return -EINVAL;         /* usually EFAULT, but linux gives EINVAL */

    unix_timer ut = posix_timer_from_timerid(timerid);
    if (ut == INVALID_ADDRESS)
        return -EINVAL;

    if (old_value) {
        if (!validate_user_memory(old_value, sizeof(struct itimerspec), true))
            return -EFAULT;
        itimerspec_from_timer(ut, old_value);
    }

    remove_unix_timer(ut);
    ut->overruns = 0;

    if (new_value->it_value.tv_sec == 0 && new_value->it_value.tv_nsec == 0)
        return 0;

    timestamp tinit = time_from_timespec(&new_value->it_value);
    timestamp interval = time_from_timespec(&new_value->it_interval);

    boolean absolute = (flags & TFD_TIMER_ABSTIME) != 0;
    timer_debug("register timer: cid %d, init value %T, absolute %d, interval %T\n",
                ut->cid, tinit, absolute, interval);
    timer t = register_timer(runloop_timers, ut->cid, tinit, absolute, interval,
                             closure(unix_timer_heap, posix_timer_expire, ut));
    if (t == INVALID_ADDRESS)
        return -ENOMEM;

    ut->t = t;
    return 0;
}

sysreturn timer_gettime(u32 timerid, struct itimerspec *curr_value) {
    if (!validate_user_memory(curr_value, sizeof(struct itimerspec), true))
        return -EFAULT;

    unix_timer ut = posix_timer_from_timerid(timerid);
    if (ut == INVALID_ADDRESS)
        return -EINVAL;

    itimerspec_from_timer(ut, curr_value);
    return 0;
}

sysreturn timer_getoverrun(u32 timerid) {
    unix_timer ut = posix_timer_from_timerid(timerid);
    if (ut == INVALID_ADDRESS)
        return -EINVAL;
    sysreturn rv = timer_overruns_s32(ut);
    ut->overruns = 0;
    return rv;
}

sysreturn timer_delete(u32 timerid) {
    unix_timer ut = posix_timer_from_timerid(timerid);
    if (ut == INVALID_ADDRESS)
        return -EINVAL;
    if (ut->info.posix.recipient != INVALID_ADDRESS)
        thread_release(ut->info.posix.recipient);
    process p = current->p;
    remove_unix_timer(ut);
    deallocate_u64((heap)p->posix_timer_ids, ut->info.posix.id, 1);
    vector_set(p->posix_timers, ut->info.posix.id, 0);
    deallocate_unix_timer(ut);
    return 0;
}

sysreturn timer_create(int clockid, struct sigevent *sevp, u32 *timerid)
{
    if (clockid == CLOCK_PROCESS_CPUTIME_ID ||
        clockid == CLOCK_THREAD_CPUTIME_ID) {
        msg_err("%s: clockid %d not implemented\n", __func__);
        return -EOPNOTSUPP;
    }

    if (clockid != CLOCK_REALTIME &&
        clockid != CLOCK_MONOTONIC &&
        clockid != CLOCK_BOOTTIME &&
        clockid != CLOCK_REALTIME_ALARM &&
        clockid != CLOCK_BOOTTIME_ALARM)
        return -EINVAL;

    if (!validate_user_memory(timerid, sizeof(u32), true))
        return -EFAULT;

    process p = current->p;
    thread recipient = INVALID_ADDRESS; /* default to process */
    if (sevp) {
        if (!validate_user_memory(sevp, sizeof(struct sigevent), false))
            return -EFAULT;
        switch (sevp->sigev_notify) {
        case SIGEV_NONE:
            break;
        case SIGEV_SIGNAL | SIGEV_THREAD_ID:
            recipient = thread_from_tid(p, sevp->sigev_un.tid);
            if (recipient == INVALID_ADDRESS)
                return -EINVAL;
            /* fall through */
        case SIGEV_SIGNAL:
            if (sevp->sigev_signo < 1 || sevp->sigev_signo > NSIG)
                return -EINVAL;
            break;
        case SIGEV_THREAD:
            /* should never see this, but bark if we do */
            msg_err("%s: SIGEV_THREAD should be handled by libc / nptl\n", __func__);
            return -EINVAL;
        default:
            return -EINVAL;
        }
    }

    u64 id = allocate_u64((heap)p->posix_timer_ids, 1);
    if (id == INVALID_PHYSICAL)
        return -ENOMEM;

    struct sigevent default_sevp;
    if (!sevp) {
        default_sevp.sigev_notify = SIGEV_SIGNAL;
        default_sevp.sigev_signo = SIGALRM;
        zero(&default_sevp.sigev_value, sizeof(sigval_t));
        default_sevp.sigev_value.sival_int = id;
        sevp = &default_sevp;
    }

    unix_timer ut = allocate_unix_timer(UNIX_TIMER_TYPE_POSIX, clockid);
    if (ut == INVALID_ADDRESS) {
        deallocate_u64((heap)p->posix_timer_ids, id, 1);
        return -ENOMEM;
    }

    ut->info.posix.id = id;
    *timerid = id;
    vector_set(p->posix_timers, id, ut);
    ut->info.posix.sevp = *sevp;
    ut->info.posix.recipient = recipient;
    if (recipient != INVALID_ADDRESS)
        thread_reserve(recipient);

    struct siginfo *si = &ut->info.posix.si;
    zero(si, sizeof(struct siginfo));
    si->si_signo = sevp->sigev_signo;
    si->si_code = SI_TIMER;
    si->sifields.timer.tid = ut->info.posix.id;
    si->sifields.timer.sigval = ut->info.posix.sevp.sigev_value;
    return 0;
}

sysreturn getitimer(int which, struct itimerval *curr_value)
{
    if (which == ITIMER_VIRTUAL || which == ITIMER_PROF) {
        msg_err("timer type %d not yet supported\n");
        return -EOPNOTSUPP;
    } else if (which != ITIMER_REAL) {
        return -EINVAL;
    }

    if (!validate_user_memory(curr_value, sizeof(struct itimerval), true))
        return -EFAULT;

    unix_timer ut = vector_get(current->p->itimers, which);
    if (ut) {
        itimerval_from_timer(ut, curr_value);
    } else {
        curr_value->it_value.tv_sec = curr_value->it_interval.tv_sec = 0;
        curr_value->it_value.tv_usec = curr_value->it_interval.tv_usec = 0;
    }
    return 0;
}

closure_function(1, 1, void, itimer_expire,
                 unix_timer, ut,
                 u64, overruns)
{
    unix_timer ut = bound(ut);
    assert(ut->t);
    assert(!ut->t->disabled);

    /* Ignore overruns. Only one itimer signal may be queued. */
    timer_debug("which %d, interval %ld, overruns (ignored) %d\n",
                ut->info.itimer.which, ut->t->interval, overruns);

    deliver_signal_to_process(ut->p, &ut->info.itimer.si);

    if (ut->t->interval == 0)
        remove_unix_timer(ut);     /* deallocs closure for us */
}

#define USEC_LIMIT 999999

static sysreturn setitimer_internal(unix_timer ut, int clockid,
                                    const struct itimerval *new_value,
                                    struct itimerval *old_value)
{
    if (old_value)
        itimerval_from_timer(ut, old_value);

    remove_unix_timer(ut);

    if (!new_value || (new_value->it_value.tv_sec == 0 && new_value->it_value.tv_usec == 0))
        return 0;

    timestamp tinit = time_from_timeval(&new_value->it_value);
    timestamp interval = time_from_timeval(&new_value->it_interval);

    timer_debug("register timer: clockid %d, init value %T, interval %T\n",
                clockid, tinit, interval);
    timer t = register_timer(runloop_timers, clockid, tinit, false, interval,
                             closure(unix_timer_heap, itimer_expire, ut));
    if (t == INVALID_ADDRESS)
        return -ENOMEM;

    ut->t = t;
    return 0;
}

static unix_timer unix_timer_from_itimer_index(process p, int which, clock_id clockid)
{
    unix_timer ut = vector_get(p->itimers, which);
    if (!ut) {
        ut = allocate_unix_timer(UNIX_TIMER_TYPE_ITIMER, clockid);
        if (ut == INVALID_ADDRESS)
            return ut;
        ut->info.itimer.which = which;
        struct siginfo *si = &ut->info.itimer.si;
        zero(si, sizeof(struct siginfo));
        switch (which) {
        case ITIMER_REAL:
            si->si_signo = SIGALRM;
            break;
        case ITIMER_VIRTUAL:
            si->si_signo = SIGVTALRM;
            break;
        case ITIMER_PROF:
            si->si_signo = SIGPROF;
            break;
        }
        si->si_code = SI_KERNEL;
        vector_set(p->itimers, which, ut);
    }
    return ut;
}

sysreturn setitimer(int which, const struct itimerval *new_value,
                    struct itimerval *old_value)
{
    /* Since we are a unikernel, and ITIMER_REAL accounts for both
       user and system time, we'll just treat it like an ITIMER_REAL.

       This isn't entirely accurate because it accounts for system
       time that isn't on behalf of running threads. A more accurate
       method might be to create a timer heap per clock domain (in
       this case timer heaps attached to the process itself). We are
       presently limited by all timers mapping to monotonic system
       time. */
    clock_id clockid;
    if (which == ITIMER_VIRTUAL) {
        msg_err("timer type %d not yet supported\n", which);
        if (new_value) {
            msg_err("   (it_value %T, it_interval %T)\n",
                    time_from_timeval(&new_value->it_value),
                    time_from_timeval(&new_value->it_interval));
        }
        return -EOPNOTSUPP;
    } else if (which == ITIMER_REAL) {
        clockid = CLOCK_ID_REALTIME;
    } else if (which == ITIMER_PROF) {
        clockid = CLOCK_ID_MONOTONIC;
    } else {
        return -EINVAL;
    }

    if (new_value && (new_value->it_value.tv_usec > USEC_LIMIT ||
                      new_value->it_interval.tv_usec > USEC_LIMIT))
        return -EINVAL;

    if (old_value && !validate_user_memory(old_value, sizeof(struct itimerval), true))
        return -EFAULT;

    unix_timer ut = unix_timer_from_itimer_index(current->p, which, clockid);
    if (ut == INVALID_ADDRESS)
        return -ENOMEM;

    return setitimer_internal(ut, clockid, new_value, old_value);
}

sysreturn alarm(unsigned int seconds)
{
    struct itimerval new, old;
    new.it_value.tv_sec = seconds;
    new.it_value.tv_usec = 0;
    new.it_interval.tv_sec = 0;
    new.it_interval.tv_usec = 0;

    unix_timer ut = unix_timer_from_itimer_index(current->p, ITIMER_REAL, CLOCK_ID_MONOTONIC);
    if (ut == INVALID_ADDRESS)
        return 0;               /* TODO: no error return from alarm... */
    if (setitimer_internal(ut, CLOCK_ID_REALTIME, &new, &old) < 0)
        return 0;               /* no errno here (uint retval), so default to 0? */
    if (old.it_value.tv_sec == 0 && old.it_value.tv_usec != 0)
        return 1;               /* 0 for disarmed timer only, so round up */
    return old.it_value.tv_sec;
}

void register_timer_syscalls(struct syscall *map)
{
    register_syscall(map, timerfd_create, timerfd_create);
    register_syscall(map, timerfd_gettime, timerfd_gettime);
    register_syscall(map, timerfd_settime, timerfd_settime);
    register_syscall(map, timer_create, timer_create);
    register_syscall(map, timer_settime, timer_settime);
    register_syscall(map, timer_gettime, timer_gettime);
    register_syscall(map, timer_getoverrun, timer_getoverrun);
    register_syscall(map, timer_delete, timer_delete);
    register_syscall(map, getitimer, getitimer);
    register_syscall(map, setitimer, setitimer);
    register_syscall(map, alarm, alarm);
}

boolean unix_timers_init(unix_heaps uh)
{
    unix_timer_heap = heap_general((kernel_heaps)uh);
    return true;
}
