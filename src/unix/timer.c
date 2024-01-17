#include <unix_internal.h>

/* TODO

   - validation of timeval and timespecs parameters across board
   - support for thread and process time(r)s
*/

//#define UNIX_TIMER_DEBUG
#ifdef UNIX_TIMER_DEBUG
#define timer_debug(x, ...) do {tprintf(sym(unix_timer), 0, ss("%s: " x), func_ss, ##__VA_ARGS__);} while(0)
#else
#define timer_debug(x, ...)
#endif

enum unix_timer_type {
    UNIX_TIMER_TYPE_TIMERFD = 1,
    UNIX_TIMER_TYPE_POSIX,      /* POSIX.1b (timer_create) */
    UNIX_TIMER_TYPE_ITIMER
};

declare_closure_struct(1, 2, void, posix_timer_expire,
                       struct unix_timer *, ut,
                       u64, expiry, u64, overruns);

declare_closure_struct(1, 2, void, itimer_expire,
                       struct unix_timer *, ut,
                       u64, expiry, u64, overruns);

declare_closure_struct(1, 2, void, timerfd_timer_expire,
                       struct unix_timer *, ut,
                       u64, expiry, u64, overruns);

declare_closure_struct(1, 0, void, unix_timer_free,
                       struct unix_timer *, ut);

typedef struct unix_timer {
    struct fdesc f;             /* used for timerfd only; must be first */
    process p;
    int type;
    boolean interval;
    clock_id cid;
    timerqueue tq;
    struct timer t;
    u64 overruns;
    struct spinlock lock;

    union {
        struct {
            struct siginfo si;
            int id;
            thread cputime_thread;
            thread recipient;   /* INVALID_ADDRESS means deliver to process */
            struct sigevent sevp;
            closure_struct(posix_timer_expire, timer_expire);
        } posix;

        struct {
            struct siginfo si;
            int which;
            closure_struct(itimer_expire, timer_expire);
        } itimer;

        struct timerfd {
            struct list l;  /* cancelable timer list */
            blockq bq;
            boolean cancel_on_set;
            boolean canceled;   /* by time set */
            closure_struct(timerfd_timer_expire, timer_expire);
        } timerfd;
    } info;
    struct refcount refcount;
    closure_struct(unix_timer_free, free);
} *unix_timer;

BSS_RO_AFTER_INIT static heap unix_timer_heap;
static struct spinlock timer_cancel_lock;
static struct list timer_cancel_list;

define_closure_function(1, 0, void, unix_timer_free,
                        unix_timer, ut)
{
    timer_debug("ut %p\n", bound(ut));
    deallocate(unix_timer_heap, bound(ut), sizeof(struct unix_timer));
}

static unix_timer allocate_unix_timer(int type, timerqueue tq, clock_id cid)
{
    unix_timer ut = allocate(unix_timer_heap, sizeof(struct unix_timer));
    if (ut == INVALID_ADDRESS)
        return ut;
    ut->p = current->p;
    ut->type = type;
    ut->interval = false;
    ut->tq = tq;
    ut->cid = cid;
    init_timer(&ut->t);
    ut->overruns = 0;
    spin_lock_init(&ut->lock);
    init_refcount(&ut->refcount, 1, init_closure(&ut->free, unix_timer_free, ut));
    timer_debug("type %d, cid %d, ut %p\n", type, cid, ut);
    return ut;
}

static inline void reserve_unix_timer(unix_timer ut)
{
    timer_debug("ut %p\n", ut);
    refcount_reserve(&ut->refcount);
}

static inline void release_unix_timer(unix_timer ut)
{
    timer_debug("ut %p\n", ut);
    refcount_release(&ut->refcount);
}

static boolean itimerspec_from_timer(unix_timer ut, struct itimerspec *i)
{
    timestamp remain = 0, interval = 0;
    if (timer_is_active(&ut->t))
        timer_get_remaining(ut->tq, &ut->t, &remain, &interval);
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(i, sizeof(struct itimerspec), true) || context_set_err(ctx))
        return false;
    timespec_from_time(&i->it_value, remain);
    timespec_from_time(&i->it_interval, interval);
    context_clear_err(ctx);
    return true;
}

static void itimerval_from_timer(unix_timer ut, struct itimerval *i)
{
    timestamp remain = 0, interval = 0;
    if (timer_is_active(&ut->t))
        timer_get_remaining(ut->tq, &ut->t, &remain, &interval);
    timeval_from_time(&i->it_value, remain);
    timeval_from_time(&i->it_interval, interval);
}

static inline void remove_unix_timer(unix_timer ut)
{
    remove_timer(ut->tq, &ut->t, 0);
}

define_closure_function(1, 2, void, timerfd_timer_expire,
                        unix_timer, ut,
                        u64, expiry, u64, overruns)
{
    unix_timer ut = bound(ut);
    if (overruns != timer_disabled) {
        spin_lock(&ut->lock);
        ut->overruns += overruns;
        timer_debug("ut %p, interval %ld, %d overruns -> %ld\n",
                    ut, ut->t.interval, overruns, ut->overruns);

        blockq_wake_one(ut->info.timerfd.bq);
        notify_dispatch(ut->f.ns, EPOLLIN);

        boolean interval = ut->interval;
        spin_unlock(&ut->lock);
        if (interval)
            return;
    }
    release_unix_timer(ut);
}

void notify_unix_timers_of_rtc_change(void)
{
    spin_lock(&timer_cancel_lock);
    list_foreach(&timer_cancel_list, e) {
        struct timerfd *tfd = struct_from_list(e, struct timerfd *, l);
        if (tfd->canceled)
            continue;
        unix_timer ut = struct_from_field(tfd, unix_timer, info);
        spin_lock(&ut->lock);
        tfd->canceled = true;
        blockq_wake_one(tfd->bq);
        notify_dispatch(ut->f.ns, EPOLLIN);
        spin_unlock(&ut->lock);
    }
    spin_unlock(&timer_cancel_lock);
}

sysreturn timerfd_settime(int fd, int flags,
                          const struct itimerspec *new_value,
                          struct itimerspec *old_value)
{
    if (flags & ~(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET))
        return -EINVAL;

    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(new_value, sizeof(struct itimerspec), false) || context_set_err(ctx))
        return -EFAULT;
    timestamp tinit = time_from_timespec(&new_value->it_value);
    timestamp interval = time_from_timespec(&new_value->it_interval);
    context_clear_err(ctx);

    unix_timer ut = resolve_fd(current->p, fd); /* macro, may return EBADF */
    spin_lock(&timer_cancel_lock);  /* to avoid lock inversion with unix timer lock */
    spin_lock(&ut->lock);
    sysreturn rv = 0;
    if (ut->f.type != FDESC_TYPE_TIMERFD) {
        rv = -EINVAL;
        goto out;
    }

    if (old_value && !itimerspec_from_timer(ut, old_value)) {
        rv = -EFAULT;
        goto out;
    }

    ut->info.timerfd.canceled = false;
    boolean cancel_on_set =
        (ut->cid == CLOCK_REALTIME || ut->cid == CLOCK_REALTIME_ALARM) &&
        (flags ^ (TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)) == 0;
    if (cancel_on_set != ut->info.timerfd.cancel_on_set) {
        if (cancel_on_set)
            list_push_back(&timer_cancel_list, &ut->info.timerfd.l);
        else
            list_delete(&ut->info.timerfd.l);
        ut->info.timerfd.cancel_on_set = cancel_on_set;
    }

    remove_unix_timer(ut);
    ut->overruns = 0;

    if (tinit == 0)
        goto out;
    boolean absolute = (flags & TFD_TIMER_ABSTIME) != 0;
    timer_debug("register timer: cid %d, init value %T, absolute %d, interval %T\n",
                ut->cid, tinit, absolute, interval);
    if (interval != 0)
        ut->interval = true;
    reserve_unix_timer(ut);
    register_timer(kernel_timers, &ut->t, ut->cid, tinit, absolute, interval,
                   init_closure(&ut->info.timerfd.timer_expire, timerfd_timer_expire, ut));
  out:
    spin_unlock(&ut->lock);
    spin_unlock(&timer_cancel_lock);
    fdesc_put(&ut->f);
    return rv;
}

sysreturn timerfd_gettime(int fd, struct itimerspec *curr_value)
{
    sysreturn rv = 0;
    unix_timer ut = resolve_fd(current->p, fd); /* macro, may return EBADF */
    spin_lock(&ut->lock);
    if (ut->f.type != FDESC_TYPE_TIMERFD)
        rv = -EINVAL;
    else
        rv = itimerspec_from_timer(ut, curr_value) ? 0 : -EFAULT;
    spin_unlock(&ut->lock);
    fdesc_put(&ut->f);
    return rv;
}

closure_function(4, 1, sysreturn, timerfd_read_bh,
                 unix_timer, ut, void *, dest, u64, length, io_completion, completion,
                 u64, flags)
{
    unix_timer ut = bound(ut);
    boolean blocked = (flags & BLOCKQ_ACTION_BLOCKED) != 0;
    sysreturn rv = sizeof(u64);

    timer_debug("ut %p, dest %p, length %ld, flags 0x%lx\n",
                ut, bound(dest), bound(length), flags);

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        assert(blocked);
        rv = -ERESTARTSYS;
        goto out;
    }

    spin_lock(&ut->lock);

    if (ut->info.timerfd.canceled) {
        ut->info.timerfd.canceled = false;
        rv = -ECANCELED;
        goto out;
    }

    context ctx = get_current_context(current_cpu());
    u64 overruns = ut->overruns;
    if (overruns == 0) {
        if (!blocked && (ut->f.flags & TFD_NONBLOCK)) {
            rv = -EAGAIN;
            goto out;
        }
        timer_debug("   -> block\n");
        spin_unlock(&ut->lock);
        return blockq_block_required((unix_context)ctx, flags);
    }
    if (!context_set_err(ctx)) {
        *(u64*)bound(dest) = overruns;
        context_clear_err(ctx);
        ut->overruns = 0;
    } else {
        rv = -EFAULT;
    }
  out:
    spin_unlock(&ut->lock);
    timer_debug("   -> returning %ld\n", rv);
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, timerfd_read,
                 unix_timer, ut,
                 void *, dest, u64, length, u64, offset_arg, context, ctx, boolean, bh, io_completion, completion)
{
    if (length < sizeof(u64))
        return io_complete(completion, -EINVAL);
    unix_timer ut = bound(ut);
    timer_debug("ut %p, dest %p, length %ld, ctx %p, bh %d, completion %p\n",
                ut, dest, length, ctx, bh, completion);
    blockq_action ba = closure_from_context(ctx, timerfd_read_bh, ut, dest, length, completion);
    return blockq_check(ut->info.timerfd.bq, ba, bh);
}

closure_function(1, 1, u32, timerfd_events,
                 unix_timer, ut,
                 thread, t /* ignored */)
{
    return bound(ut)->overruns > 0 ? EPOLLIN : 0;
}

closure_function(1, 2, sysreturn, timerfd_close,
                 unix_timer, ut,
                 context, ctx, io_completion, completion)
{
    unix_timer ut = bound(ut);
    spin_lock(&ut->lock);
    remove_unix_timer(ut);
    deallocate_blockq(ut->info.timerfd.bq);
    deallocate_closure(ut->f.read);
    deallocate_closure(ut->f.events);
    deallocate_closure(ut->f.close);
    release_fdesc(&ut->f);
    spin_unlock(&ut->lock);
    release_unix_timer(ut);
    return io_complete(completion, 0);
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

    unix_timer ut = allocate_unix_timer(UNIX_TIMER_TYPE_TIMERFD, kernel_timers, clockid);
    if (ut == INVALID_ADDRESS)
        return -ENOMEM;

    init_fdesc(unix_timer_heap, &ut->f, FDESC_TYPE_TIMERFD);
    ut->info.timerfd.bq = allocate_blockq(unix_timer_heap, ss("timerfd"));
    if (ut->info.timerfd.bq == INVALID_ADDRESS)
        goto err_mem_bq;
    ut->info.timerfd.cancel_on_set = false;
    ut->info.timerfd.canceled = false;
    ut->f.flags = flags;
    ut->f.read = closure(unix_timer_heap, timerfd_read, ut);
    ut->f.events = closure(unix_timer_heap, timerfd_events, ut);
    ut->f.close = closure(unix_timer_heap, timerfd_close, ut);

    u64 fd = allocate_fd(current->p, ut);
    if (fd == INVALID_PHYSICAL) {
        apply(ut->f.close, 0, io_completion_ignore);
        return -EMFILE;
    }
    timer_debug("unix_timer %p, fd %d\n", ut, fd);
    return fd;
  err_mem_bq:
    release_unix_timer(ut);
    return -ENOMEM;
}

static unix_timer posix_timer_from_timerid(u32 timerid)
{
    process p = current->p;
    process_lock(p);
    unix_timer ut = vector_get(p->posix_timers, timerid);
    process_unlock(p);
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
        halt("%s: invalid sigev_notify %d\n", func_ss, sevp->sigev_notify);
    }
}

define_closure_function(1, 2, void, posix_timer_expire,
                        unix_timer, ut,
                        u64, expiry, u64, overruns)
{
    unix_timer ut = bound(ut);
    if (overruns != timer_disabled) {
        assert(overruns > 0);

        spin_lock(&ut->lock);
        ut->overruns += overruns - 1;
        timer_debug("id %d, interval %ld, +%d -> %d\n",
                    ut->info.posix.id, ut->t.interval, overruns, ut->overruns);

        sigev_deliver(ut);
        boolean interval = ut->interval;
        spin_unlock(&ut->lock);
        if (interval)
            return;
    }
    release_unix_timer(ut);
}

sysreturn timer_settime(u32 timerid, int flags,
                        const struct itimerspec *new_value,
                        struct itimerspec *old_value) {
    /* Linux doesn't validate flags? */
    if (!validate_user_memory(new_value, sizeof(struct itimerspec), false))
        return -EINVAL;         /* usually EFAULT, but linux gives EINVAL */

    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return -EFAULT;
    timestamp tinit = time_from_timespec(&new_value->it_value);
    timestamp interval = time_from_timespec(&new_value->it_interval);
    context_clear_err(ctx);

    unix_timer ut = posix_timer_from_timerid(timerid);
    if (ut == INVALID_ADDRESS)
        return -EINVAL;
    spin_lock(&ut->lock);
    sysreturn rv;

    if (old_value && !itimerspec_from_timer(ut, old_value)) {
        rv = -EFAULT;
        goto out;
    }

    remove_unix_timer(ut);
    ut->overruns = 0;

    if (tinit == 0) {
        rv = 0;
        goto out;
    }

    boolean absolute = (flags & TFD_TIMER_ABSTIME) != 0;
    timer_debug("register timer: cid %d, init value %T, absolute %d, interval %T\n",
                ut->cid, tinit, absolute, interval);
    if (interval != 0)
        ut->interval = true;
    reserve_unix_timer(ut);
    register_timer(ut->tq, &ut->t, ut->cid, tinit, absolute, interval,
                   init_closure(&ut->info.posix.timer_expire, posix_timer_expire, ut));
    rv = 0;
  out:
    spin_unlock(&ut->lock);
    return rv;
}

sysreturn timer_gettime(u32 timerid, struct itimerspec *curr_value) {
    unix_timer ut = posix_timer_from_timerid(timerid);
    if (ut == INVALID_ADDRESS)
        return -EINVAL;

    spin_lock(&ut->lock);
    boolean ok = itimerspec_from_timer(ut, curr_value);
    spin_unlock(&ut->lock);
    return ok ? 0 : -EFAULT;
}

sysreturn timer_getoverrun(u32 timerid) {
    unix_timer ut = posix_timer_from_timerid(timerid);
    if (ut == INVALID_ADDRESS)
        return -EINVAL;
    spin_lock(&ut->lock);
    sysreturn rv = timer_overruns_s32(ut);
    ut->overruns = 0;
    spin_unlock(&ut->lock);
    return rv;
}

sysreturn timer_delete(u32 timerid) {
    unix_timer ut = posix_timer_from_timerid(timerid);
    if (ut == INVALID_ADDRESS)
        return -EINVAL;
    spin_lock(&ut->lock);
    if (ut->info.posix.cputime_thread != INVALID_ADDRESS)
        thread_release(ut->info.posix.cputime_thread);
    if (ut->info.posix.recipient != INVALID_ADDRESS)
        thread_release(ut->info.posix.recipient);
    process p = current->p;
    remove_unix_timer(ut);
    int id = ut->info.posix.id;
    spin_unlock(&ut->lock);
    process_lock(p);
    deallocate_u64((heap)p->posix_timer_ids, id, 1);
    assert(vector_set(p->posix_timers, id, 0));
    process_unlock(p);
    release_unix_timer(ut);
    return 0;
}

sysreturn timer_create(int clockid, struct sigevent *sevp, u32 *timerid)
{
    process p = current->p;
    clock_id cid;
    thread cputime_thread;
    if (!clockid_get(p, clockid, true, &cid, &cputime_thread))
        return -EINVAL;

    sysreturn rv;
    if (!fault_in_user_memory(timerid, sizeof(u32), true)) {
        rv = -EFAULT;
        goto release_cputime_t;
    }

    thread recipient = INVALID_ADDRESS; /* default to process */
    if (sevp) {
        if (!fault_in_user_memory(sevp, sizeof(struct sigevent), false)) {
            rv = -EFAULT;
            goto release_cputime_t;
        }
        switch (sevp->sigev_notify) {
        case SIGEV_NONE:
            break;
        case SIGEV_SIGNAL | SIGEV_THREAD_ID:
            recipient = thread_from_tid(p, sevp->sigev_un.tid);
            if (recipient == INVALID_ADDRESS) {
                rv = -EINVAL;
                goto release_cputime_t;
            }
            /* fall through */
        case SIGEV_SIGNAL:
            if (sevp->sigev_signo < 1 || sevp->sigev_signo > NSIG) {
                rv = -EINVAL;
                goto release_cputime_t;
            }
            break;
        case SIGEV_THREAD:
            /* should never see this, but bark if we do */
            msg_err("SIGEV_THREAD should be handled by libc / nptl\n");
            /* no break */
        default:
            rv = -EINVAL;
            goto release_cputime_t;
        }
    }

    timerqueue tq;
    switch (cid) {
    case CLOCK_PROCESS_CPUTIME_ID:
        tq = p->cpu_timers;
        break;
    case CLOCK_THREAD_CPUTIME_ID:
        tq = thread_get_cpu_timer_queue(cputime_thread);
        if (!tq)
            goto err_nomem;
        break;
    default:
        tq = kernel_timers;
        break;
    }
    unix_timer ut = allocate_unix_timer(UNIX_TIMER_TYPE_POSIX, tq, clockid);
    if (ut == INVALID_ADDRESS)
        goto err_nomem;
    spin_lock(&ut->lock);

    process_lock(p);
    u64 id = allocate_u64((heap)p->posix_timer_ids, 1);
    if ((id != INVALID_PHYSICAL) && (!vector_set(p->posix_timers, id, ut))) {
        deallocate_u64((heap)p->posix_timer_ids, id, 1);
        id = INVALID_PHYSICAL;
    }
    process_unlock(p);
    if (id == INVALID_PHYSICAL) {
        spin_unlock(&ut->lock);
        release_unix_timer(ut);
        goto err_nomem;
    }

    struct sigevent default_sevp;
    if (!sevp) {
        default_sevp.sigev_notify = SIGEV_SIGNAL;
        default_sevp.sigev_signo = SIGALRM;
        zero(&default_sevp.sigev_value, sizeof(sigval_t));
        default_sevp.sigev_value.sival_int = id;
        sevp = &default_sevp;
    }

    ut->info.posix.id = id;
    *timerid = id;
    ut->info.posix.sevp = *sevp;
    ut->info.posix.cputime_thread =
            (cid == CLOCK_THREAD_CPUTIME_ID) ? cputime_thread : INVALID_ADDRESS;
    ut->info.posix.recipient = recipient;

    struct siginfo *si = &ut->info.posix.si;
    zero(si, sizeof(struct siginfo));
    si->si_signo = sevp->sigev_signo;
    si->si_code = SI_TIMER;
    si->sifields.timer.tid = ut->info.posix.id;
    si->sifields.timer.sigval = ut->info.posix.sevp.sigev_value;
    spin_unlock(&ut->lock);
    return 0;
  err_nomem:
    if (recipient != INVALID_ADDRESS)
        thread_release(recipient);
    rv = -ENOMEM;
  release_cputime_t:
    if (cid == CLOCK_THREAD_CPUTIME_ID)
        thread_release(cputime_thread);
    return rv;
}

sysreturn getitimer(int which, struct itimerval *curr_value)
{
    if (which == ITIMER_VIRTUAL) {
        msg_err("timer type %d not yet supported\n", which);
        return -EOPNOTSUPP;
    } else if ((which != ITIMER_REAL) && (which != ITIMER_PROF)) {
        return -EINVAL;
    }

    if (!validate_user_memory(curr_value, sizeof(struct itimerval), true))
        return -EFAULT;

    unix_timer ut = vector_get(current->p->itimers, which);
    context ctx = get_current_context(current_cpu());
    sysreturn rv;
    if (ut) {
        spin_lock(&ut->lock);
        if (!context_set_err(ctx)) {
            itimerval_from_timer(ut, curr_value);
            context_clear_err(ctx);
            rv = 0;
        } else {
            rv = -EFAULT;
        }
        spin_unlock(&ut->lock);
    } else {
        if (!context_set_err(ctx)) {
            curr_value->it_value.tv_sec = curr_value->it_interval.tv_sec = 0;
            curr_value->it_value.tv_usec = curr_value->it_interval.tv_usec = 0;
            context_clear_err(ctx);
            rv = 0;
        } else {
            rv = -EFAULT;
        }
    }
    return rv;
}

define_closure_function(1, 2, void, itimer_expire,
                        unix_timer, ut,
                        u64, expiry, u64, overruns)
{
    unix_timer ut = bound(ut);
    if (overruns != timer_disabled) {
        spin_lock(&ut->lock);
        /* Ignore overruns. Only one itimer signal may be queued. */
        timer_debug("which %d, interval %ld, overruns (ignored) %d\n",
                    ut->info.itimer.which, ut->t.interval, overruns);

        deliver_signal_to_process(ut->p, &ut->info.itimer.si);

        boolean interval = ut->interval;
        spin_unlock(&ut->lock);
        if (interval)
            return;
    }
    release_unix_timer(ut);
}

#define USEC_LIMIT 999999

static sysreturn setitimer_internal(unix_timer ut,
                                    const struct itimerval *new_value,
                                    struct itimerval *old_value)
{
    spin_lock(&ut->lock);
    if (old_value)
        itimerval_from_timer(ut, old_value);

    remove_unix_timer(ut);

    sysreturn rv;
    if (!new_value || (new_value->it_value.tv_sec == 0 && new_value->it_value.tv_usec == 0)) {
        rv = 0;
        goto out;
    }

    timestamp tinit = time_from_timeval(&new_value->it_value);
    timestamp interval = time_from_timeval(&new_value->it_interval);

    timer_debug("register timer: init value %T, interval %T\n", tinit, interval);
    if (interval != 0)
        ut->interval = true;
    reserve_unix_timer(ut);
    register_timer(ut->tq, &ut->t, CLOCK_ID_MONOTONIC, tinit, false, interval,
                   init_closure(&ut->info.itimer.timer_expire, itimer_expire, ut));
    rv = 0;
  out:
    spin_unlock(&ut->lock);
    return rv;
}

static unix_timer unix_timer_from_itimer_index(process p, int which)
{
    unix_timer ut = vector_get(p->itimers, which);
    if (!ut) {
        ut = allocate_unix_timer(UNIX_TIMER_TYPE_ITIMER,
                                 (which == ITIMER_REAL) ? kernel_timers : p->cpu_timers,
                                 CLOCK_ID_MONOTONIC);
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
        assert(vector_set(p->itimers, which, ut));
    }
    return ut;
}

sysreturn setitimer(int which, const struct itimerval *new_value,
                    struct itimerval *old_value)
{
    if (which == ITIMER_VIRTUAL) {
        msg_err("timer type %d not yet supported\n", which);
        return -EOPNOTSUPP;
    } else if ((which != ITIMER_REAL) && (which != ITIMER_PROF)) {
        return -EINVAL;
    }

    if (new_value) {
        if (!fault_in_user_memory(new_value, sizeof(struct itimerval), false))
            return -EFAULT;
        if (new_value->it_value.tv_usec > USEC_LIMIT || new_value->it_interval.tv_usec > USEC_LIMIT)
            return -EINVAL;
    }

    if (old_value && !fault_in_user_memory(old_value, sizeof(struct itimerval), true))
        return -EFAULT;

    process p = current->p;
    sysreturn ret;
    process_lock(p);
    unix_timer ut = unix_timer_from_itimer_index(p, which);
    if (ut == INVALID_ADDRESS)
        ret = -ENOMEM;
    else
        ret = setitimer_internal(ut, new_value, old_value);
    process_unlock(p);
    return ret;
}

#ifdef __x86_64__
sysreturn alarm(unsigned int seconds)
{
    struct itimerval new, old;
    new.it_value.tv_sec = seconds;
    new.it_value.tv_usec = 0;
    new.it_interval.tv_sec = 0;
    new.it_interval.tv_usec = 0;

    process p = current->p;
    boolean error = false;
    process_lock(p);
    unix_timer ut = unix_timer_from_itimer_index(p, ITIMER_REAL);
    if ((ut == INVALID_ADDRESS) || (setitimer_internal(ut, &new, &old) < 0))
        error = true;
    process_unlock(p);
    if (error)
        return 0;               /* no errno here (uint retval), so default to 0? */
    if (old.it_value.tv_sec == 0 && old.it_value.tv_usec != 0)
        return 1;               /* 0 for disarmed timer only, so round up */
    return old.it_value.tv_sec;
}
#endif

void register_timer_syscalls(struct syscall *map)
{
#ifdef __x86_64__
    register_syscall(map, alarm, alarm, 0);
#endif
    register_syscall(map, timerfd_create, timerfd_create, SYSCALL_F_SET_DESC);
    register_syscall(map, timerfd_gettime, timerfd_gettime, SYSCALL_F_SET_DESC);
    register_syscall(map, timerfd_settime, timerfd_settime, SYSCALL_F_SET_DESC);
    register_syscall(map, timer_create, timer_create, 0);
    register_syscall(map, timer_settime, timer_settime, 0);
    register_syscall(map, timer_gettime, timer_gettime, 0);
    register_syscall(map, timer_getoverrun, timer_getoverrun, 0);
    register_syscall(map, timer_delete, timer_delete, 0);
    register_syscall(map, getitimer, getitimer, 0);
    register_syscall(map, setitimer, setitimer, 0);
}

boolean unix_timers_init(unix_heaps uh)
{
    unix_timer_heap = heap_locked((kernel_heaps)uh);
    spin_lock_init(&timer_cancel_lock);
    list_init(&timer_cancel_list);
    return true;
}
