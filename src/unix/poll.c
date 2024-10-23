#include <unix_internal.h>

#define POLL_EXCEPTIONS (EPOLLERR | EPOLLHUP | EPOLLNVAL)

//#define EPOLL_DEBUG
#ifdef EPOLL_DEBUG
#define epoll_debug(x, ...) do {tprintf(sym(poll), 0, ss("%s: " x), func_ss, ##__VA_ARGS__);} while(0)
#else
#define epoll_debug(x, ...)
#endif

typedef struct epollfd *epollfd;

typedef struct epollfd {
    int fd;
    fdesc f;
    struct spinlock lock;   /* protects zombie/registered/eventmask/lastevents */
    u32 eventmask;  /* epoll events registered  */
    u32 lastevents; /* retain last received events; for edge trigger */
    u64 data;       /* may be multiple versions of data? */
    struct refcount refcount;
    closure_struct(thunk, free);
    epoll e;
    boolean registered;
    boolean zombie; /* freed or masked by oneshot */
    notify_entry notify_handle;
} *epollfd;

typedef struct epoll_blocked *epoll_blocked;

enum epoll_type {
    EPOLL_TYPE_SELECT,
    EPOLL_TYPE_POLL,
    EPOLL_TYPE_EPOLL,
};

BSS_RO_AFTER_INIT static heap epoll_heap;

struct epoll_blocked {
    epoll e;
    thread t;
    struct refcount refcount;
    struct spinlock lock;   /* protects the data in the union */
    closure_struct(thunk, free);
    union {
        buffer user_events;
        buffer poll_fds;
        struct {
            int nfds;
            bitmap rset;
            bitmap wset;
            bitmap eset;
        };
    };
    sysreturn retval;
    struct list blocked_list;
};

/* we call it an epoll, but these structs are used for select and poll too */
struct epoll {
    struct fdesc f;             /* must be first */
    struct spinlock blocked_lock;
    struct list blocked_head;   /* an epoll_blocked per thread (in epoll_wait)  */
    struct refcount refcount;
    enum epoll_type epoll_type;
    closure_struct(fdesc_events, fd_events);
    closure_struct(fdesc_close, close);
    closure_struct(thunk, free);
    heap h;
    struct rw_spinlock fds_lock;
    vector events;              /* epollfds indexed by fd */
    int nfds;
    bitmap fds;                 /* fds being watched / epollfd registered */
};

closure_func_basic(thunk, void, epoll_free)
{
    epoll e = struct_from_closure(epoll, free);
    epoll_debug("e %p\n", e);
    deallocate_bitmap(e->fds);
    deallocate_vector(e->events);
    deallocate(epoll_heap, e, sizeof(*e));
}

static epoll epoll_alloc_internal(int epoll_type)
{
    epoll e = allocate_zero(epoll_heap, sizeof(struct epoll));
    if (e == INVALID_ADDRESS)
        return e;

    e->epoll_type = epoll_type;
    list_init(&e->blocked_head);
    init_refcount(&e->refcount, 1, init_closure_func(&e->free, thunk, epoll_free));
    spin_lock_init(&e->blocked_lock);
    spin_rw_lock_init(&e->fds_lock);
    e->h = epoll_heap;
    e->events = allocate_vector(e->h, 8);
    if (e->events == INVALID_ADDRESS)
        goto out_free_epoll;

    e->nfds = 0;
    e->fds = allocate_bitmap(e->h, e->h, infinity);
    if (e->fds == INVALID_ADDRESS)
        goto out_free_events;
    epoll_debug("allocated epoll %p\n", e);
    return e;
  out_free_events:
    deallocate_vector(e->events);
  out_free_epoll:
    deallocate(epoll_heap, e, sizeof(*e));
    return INVALID_ADDRESS;
}

closure_func_basic(thunk, void, epollfd_free)
{
    epollfd efd = struct_from_closure(epollfd, free);
    epoll_debug("fd %d\n", efd->fd);
    refcount_release(&efd->e->refcount); /* release epoll */
    deallocate(epoll_heap, efd, sizeof(*efd));
}

static void reset_epollfd(epollfd efd, u32 eventmask, u64 data)
{
    assert(!efd->registered && efd->notify_handle == 0);
    efd->eventmask = eventmask;
    efd->lastevents = 0;
    efd->zombie = false;
    efd->data = data;
}

static epollfd alloc_epollfd(epoll e, int fd, u32 eventmask, u64 data)
{
    epoll_debug("e %p, fd %d, eventmask 0x%x, data 0x%lx\n", e, fd, eventmask, data);
    epollfd efd = allocate_zero(epoll_heap, sizeof(struct epollfd));
    if (efd == INVALID_ADDRESS)
        return efd;
    efd->fd = fd;
    efd->e = e;
    reset_epollfd(efd, eventmask, data);
    init_refcount(&efd->refcount, 1, init_closure_func(&efd->free, thunk, epollfd_free));
    spin_lock_init(&efd->lock);
    efd->registered = false;
    assert(vector_set(e->events, fd, efd));
    bitmap_set(e->fds, fd, 1);
    if (fd >= e->nfds)
        e->nfds = fd + 1;
    refcount_reserve(&e->refcount);
    return efd;
}

static void unregister_epollfd(epollfd efd)
{
    fdesc f = efd->f;
    assert(f);
    epoll_debug("efd %d, pre refcount %ld, f->ns %p\n", efd->fd, efd->refcount.c, f->ns);
    efd->registered = false;
    efd->notify_handle = 0;
    refcount_release(&efd->refcount); /* registration */
}

static void release_epollfd(epollfd efd)
{
    epoll e = efd->e;
    int fd = efd->fd;
    epoll_debug("e %p, fd %d\n", e, fd);
    assert(vector_get(e->events, fd) == efd);
    assert(vector_set(e->events, fd, 0));
    bitmap_set(e->fds, fd, 0);
    spin_lock(&efd->lock);
    efd->zombie = true;
    spin_unlock(&efd->lock);
    if (efd->registered)
        notify_remove(efd->f->ns, efd->notify_handle, true); /* eh calls unregister */
    refcount_release(&efd->refcount); /* alloc */
}

static inline void poll_notify(epollfd efd, epoll_blocked w, u64 events);
static inline boolean epoll_wait_notify(epollfd efd, epoll_blocked w, u64 report);
static inline void select_notify(epollfd efd, epoll_blocked w, u64 report);
static inline u32 report_from_notify_events(epollfd efd, u64 notify_events);

closure_function(1, 2, u64, wait_notify,
                 epollfd, efd,
                 u64 notify_events, void *t)
{
    epollfd efd = bound(efd);

    spin_lock(&efd->lock);
    /* only path to freedom - even fd removals trigger release */
    if (notify_events == NOTIFY_EVENTS_RELEASE) {
        /* Unregistration/events are synchronized by notify set lock */
        epoll_debug("efd->fd %d unregistered\n", efd->fd);
        unregister_epollfd(efd);
        spin_unlock(&efd->lock);
        closure_finish();
        return 0;
    }

    if (efd->zombie || !efd->registered) {
        spin_unlock(&efd->lock);
        return 0;
    }

    u32 events = (u32)notify_events;
    epoll e = efd->e;
    enum epoll_type epoll_type = e->epoll_type;
    if (epoll_type == EPOLL_TYPE_EPOLL)
        events = report_from_notify_events(efd, events);
    u64 rv = 0;
    epoll_blocked w;
    spin_lock(&e->blocked_lock);
    list l = list_get_next(&e->blocked_head);
  notify_blocked:
    w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    epoll_debug("efd->fd %d, events 0x%x, blocked %p, zombie %d\n",
                efd->fd, events, w, efd->zombie);

    if (w) {
        if (t && t != w->t)
            goto out;
    } else if (epoll_type != EPOLL_TYPE_EPOLL) {
        goto out;
    }

    switch (epoll_type) {
    case EPOLL_TYPE_POLL:
        poll_notify(efd, w, events);
        break;
    case EPOLL_TYPE_EPOLL:
        if (w) {
            if (epoll_wait_notify(efd, w, events))
                rv |= NOTIFY_RESULT_CONSUMED;
            if (!(rv & NOTIFY_RESULT_CONSUMED) || !(efd->eventmask & EPOLLEXCLUSIVE)) {
                l = l->next;
                if (l != &e->blocked_head)
                    goto notify_blocked;
            }
        }
        if (events && (!(rv & NOTIFY_RESULT_CONSUMED) || !(efd->eventmask & EPOLLEXCLUSIVE)) &&
            notify_dispatch_for_thread(e->f.ns, EPOLLIN, t))
            rv |= NOTIFY_RESULT_CONSUMED;
        break;
    case EPOLL_TYPE_SELECT:
        select_notify(efd, w, events);
        break;
    default:
        assert(0);
    }
out:
    spin_unlock(&e->blocked_lock);
    spin_unlock(&efd->lock);
    return rv;
}


/* XXX maybe merge alloc and registration */
static boolean register_epollfd(epollfd efd)
{
    if (efd->registered)
        return false;

    /* If efd is in fds and also a zombie, it's an epfd that's
       been masked by a oneshot event. */
    if (efd->zombie)
        return false; // XXX
    fdesc f = resolve_fd(current->p, efd->fd);
    efd->f = f;
    efd->registered = true;
    refcount_reserve(&efd->refcount); /* registration */
    event_handler eh = closure(efd->e->h, wait_notify, efd);
    u64 flags = (efd->eventmask & EPOLLEXCLUSIVE) ? NOTIFY_FLAGS_EXCLUSIVE : 0;
    epoll_debug("fd %d, eventmask 0x%x, handler %p\n", efd->fd, efd->eventmask, eh);
    efd->notify_handle = notify_add_with_flags(f->ns, efd->eventmask | POLL_EXCEPTIONS, flags, eh);
    assert(efd->notify_handle != INVALID_ADDRESS);
    fdesc_put(f);   /* if the file descriptor is deallocated, we will be notified via f->ns */
    return true;
}

static void epoll_release_epollfds(epoll e)
{
    spin_wlock(&e->fds_lock);
    bitmap_foreach_set(e->fds, fd) {
        epollfd efd = vector_get(e->events, fd);
        assert(efd != 0 && efd != INVALID_ADDRESS);
        release_epollfd(efd);
    }
    spin_wunlock(&e->fds_lock);
}

void epoll_finish(epoll e)
{
    epoll_debug("e %p\n", e);
    epoll_release_epollfds(e);
    refcount_release(&e->refcount);
}

closure_func_basic(fdesc_events, u32, epoll_events,
                   thread t)
{
    epoll e = struct_from_closure(epoll, fd_events);
    u32 events = 0;
    spin_rlock(&e->fds_lock);
    bitmap_foreach_set(e->fds, fd) {
        epollfd efd = vector_get(e->events, fd);
        if (efd->zombie)
            continue;
        spin_lock(&efd->lock);
        if (efd->registered) {
            fdesc f = efd->f;
            events = apply(f->events, t) & (efd->eventmask | POLL_EXCEPTIONS);
            events = report_from_notify_events(efd, events);
        }
        spin_unlock(&efd->lock);
        if (events)
            break;
    }
    spin_runlock(&e->fds_lock);
    return events ? EPOLLIN : 0;
}

closure_func_basic(fdesc_close, sysreturn, epoll_close,
                   context ctx, io_completion completion)
{
    epoll e = struct_from_closure(epoll, close);
    release_fdesc(&e->f);
    epoll_finish(e);
    return io_complete(completion, 0);
}

sysreturn epoll_create(int flags)
{
    epoll_debug("flags 0x%x\n", flags);
    epoll e = epoll_alloc_internal(EPOLL_TYPE_EPOLL);
    if (e == INVALID_ADDRESS)
        return -ENOMEM;
    init_fdesc(e->h, &e->f, FDESC_TYPE_EPOLL);
    e->f.events = init_closure_func(&e->fd_events, fdesc_events, epoll_events);
    e->f.close = init_closure_func(&e->close, fdesc_close, epoll_close);
    u64 fd = allocate_fd(current->p, e);
    if (fd == INVALID_PHYSICAL) {
        apply(e->f.close, 0, io_completion_ignore);
        return -EMFILE;
    }
    epoll_debug("   got fd %d\n", fd);
    return fd;
}

#define user_event_count(__w) (buffer_length(__w->user_events)/sizeof(struct epoll_event))

closure_func_basic(thunk, void, epoll_blocked_free)
{
    epoll_blocked w = struct_from_closure(epoll_blocked, free);
    epoll_debug("w %p\n", w);
    thread_release(w->t);
    refcount_release(&w->e->refcount);
    deallocate(epoll_heap, w, sizeof(*w));
}

static void epoll_blocked_release(epoll_blocked w, u64 bq_flags)
{
    epoll_debug("w %p\n", w);

    spin_lock(&w->e->blocked_lock);
    assert(!list_empty(&w->blocked_list));
    list_delete(&w->blocked_list);
    spin_unlock(&w->e->blocked_lock);
    list_init(&w->blocked_list);
    refcount_release(&w->refcount);
}

static inline u32 report_from_notify_events(epollfd efd, u64 notify_events)
{
    u32 events = (u32)notify_events;
    boolean edge_detect = (efd->eventmask & EPOLLET) != 0;

    if (edge_detect) {
        if (efd->f->edge_trigger_handler) {
            efd->lastevents = apply(efd->f->edge_trigger_handler, events, efd->lastevents);
        } else {
            /* catch falling edges for EPOLLET */
            u32 falling = efd->lastevents & ~events;
            if (falling)
                efd->lastevents &= ~falling;
        }
    }

    /* only report rising edges if edge detect */
    return edge_detect ? ~efd->lastevents & events : events;
}

static inline boolean epoll_wait_notify(epollfd efd, epoll_blocked w, u64 report)
{
    if (report == 0)
        return false;

    spin_lock(&w->lock);
    if (!w->user_events || (w->user_events->length - w->user_events->end) <= 0) {
        spin_unlock(&w->lock);
        epoll_debug("   user_events null or full\n");
        return false;
    }
    context ctx = get_current_context(current_cpu());
    if (is_kernel_context(ctx)) {
        /* Borrow the thread's fault handler prior to touching user memory. */
        use_fault_handler(w->t->context.fault_handler);
    }
    if (context_set_err(ctx)) {
        w->retval = -EFAULT;
        goto out;
    }
    struct epoll_event *e, *end;
    e = buffer_ref(w->user_events, 0);
    end = buffer_ref(w->user_events, w->user_events->end);
    while (e < end) {
        if (e->data == efd->data) {
            /* Use the union of reported events so that edge triggers aren't missed. */
            e->events |= report;
            goto reported;
        }
        e++;
    }
    e->data = efd->data;
    e->events = report;
    w->user_events->end += sizeof(struct epoll_event);
  reported:
    epoll_debug("   epoll_event %p, data 0x%lx, events 0x%x\n", e, e->data, e->events);
    context_clear_err(ctx);
  out:
    if (is_kernel_context(ctx))
        clear_fault_handler();
    spin_unlock(&w->lock);
    
    /* XXX check this */
    if (efd->eventmask & EPOLLONESHOT)
        efd->zombie = true;

    /* now that we've reported these events, update last */
    efd->lastevents |= report;
    blockq_wake_one(w->t->thread_bq);
    return true;
}

static epoll_blocked alloc_epoll_blocked(epoll e)
{
    epoll_blocked w = allocate_zero(epoll_heap, sizeof(struct epoll_blocked));
    if (w == INVALID_ADDRESS)
        return w;
    epoll_debug("w %p\n", w);

    /* initial reservation released on thread wakeup (or direct return) */
    init_refcount(&w->refcount, 1, init_closure_func(&w->free, thunk, epoll_blocked_free));
    spin_lock_init(&w->lock);
    w->t = current;
    thread_reserve(w->t);
    w->e = e;
    refcount_reserve(&e->refcount);
    spin_lock(&e->blocked_lock);
    list_insert_after(&e->blocked_head, &w->blocked_list); /* push */
    spin_unlock(&e->blocked_lock);
    return w;
}

/* This bypasses the notify system but gets and handles events in the same fashion */
static void check_fdesc(epollfd efd, epoll_blocked w)
{
    if (efd->zombie)
        return;
    fdesc f = efd->f;
    u32 events = apply(f->events, w->t) & (efd->eventmask | POLL_EXCEPTIONS);

    switch (efd->e->epoll_type) {
    case EPOLL_TYPE_POLL:
        poll_notify(efd, w, events);
        break;
    case EPOLL_TYPE_EPOLL:
        epoll_wait_notify(efd, w, report_from_notify_events(efd, events));
        break;
    case EPOLL_TYPE_SELECT:
        select_notify(efd, w, events);
        break;
    default:
        assert(0);
    }
}

static void epoll_check_epollfds(epoll e, epoll_blocked w)
{
    bitmap_foreach_set(e->fds, fd) {
        epollfd efd = vector_get(e->events, fd);
        if (efd->zombie)
            continue;
        spin_lock(&efd->lock);
        if (efd->registered)
            check_fdesc(efd, w);
        spin_unlock(&efd->lock);
    }
}

/* It would be nice to devise a way to allow a poll waiter to continue
   to collect events between wakeup (first event) and running. */

closure_function(3, 1, sysreturn, epoll_wait_bh,
                 epoll_blocked, w, thread, t, timestamp, timeout,
                 u64 flags)
{
    sysreturn rv;
    thread t = bound(t);
    epoll_blocked w = bound(w);
    timestamp timeout = bound(timeout);
    spin_lock(&w->lock);
    int eventcount = user_event_count(w);

    epoll_debug("w %p on tid %d, timeout %ld, flags 0x%lx, event count %d\n",
                w, t->tid, timeout, flags, eventcount);

    if (w->retval) {
        rv = w->retval;
        goto out_wakeup;
    }

    if (!timeout || (flags & BLOCKQ_ACTION_TIMEDOUT) || eventcount) {
        rv = eventcount;
        goto out_wakeup;
    }

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = (timeout == infinity) ? -ERESTARTSYS : -EINTR;
        goto out_wakeup;
    }
    spin_unlock(&w->lock);

    epoll_debug("  continue blocking\n");
    return blockq_block_required(&bound(t)->syscall->uc, flags);
  out_wakeup:
    unwrap_buffer(w->e->h, w->user_events);
    w->user_events = 0;
    spin_unlock(&w->lock);
    fdesc_put(&w->e->f);
    epoll_debug("   pre refcnt %ld, returning %ld\n", w->refcount.c, rv);
    epoll_blocked_release(w, flags);
    closure_finish();
    return syscall_return(t, rv);
}

/* Depending on the epoll flags given, we may:
   - notify all waiters on a match (default)
   - notify on a match only once until condition is reset (EPOLLET)
   - notify once before removing the registration, handled upstream (EPOLLONESHOT)
   - notify only one matching waiter, even across multiple epoll instances (EPOLLEXCLUSIVE)
*/
sysreturn epoll_wait(int epfd,
                     struct epoll_event *events,
                     int maxevents,
                     int timeout)
{
    if (!validate_user_memory(events, sizeof(struct epoll_event) * maxevents, true))
        return -EFAULT;

    epoll e = resolve_fd(current->p, epfd);
    epoll_blocked w = alloc_epoll_blocked(e);
    if (w == INVALID_ADDRESS) {
        fdesc_put(&e->f);
        return -ENOMEM;
    }

    epoll_debug("tid %d, epoll fd %d, new blocked %p, timeout %d\n", current->tid, epfd, w, timeout);
    spin_lock(&w->lock);
    w->user_events = wrap_buffer(e->h, events, maxevents * sizeof(struct epoll_event));
    w->user_events->end = 0;
    spin_unlock(&w->lock);

    spin_rlock(&e->fds_lock);
    epoll_check_epollfds(e, w);
    spin_runlock(&e->fds_lock);

    timestamp ts = (timeout > 0) ? milliseconds(timeout) : 0;
    return blockq_check_timeout(w->t->thread_bq,
                                contextual_closure(epoll_wait_bh, w, current,
                                (timeout < 0) ? infinity : ts), false,
                                CLOCK_ID_MONOTONIC, ts, false);
}

static epollfd epollfd_from_fd(epoll e, int fd)
{
    if (!bitmap_get(e->fds, fd))
        return INVALID_ADDRESS;
    epollfd efd = vector_get(e->events, fd);
    assert(efd);
    return efd;
}

static void epollfd_update(epollfd efd)
{
    /* It may seem excessive to perform a check for all
       waiters. However, thanks to thread-specific fd events (thanks
       in turn to signalfd), we could have independent events for
       multiple threads that require waking - even on the same fd. */

    spin_lock(&efd->e->blocked_lock);
    list_foreach(&efd->e->blocked_head, l) {
        epoll_blocked w = struct_from_list(l, epoll_blocked, blocked_list);
        epoll_debug("   posting check for blocked waiter (tid %d)\n", w->t->tid);
        check_fdesc(efd, w);
    }
    spin_unlock(&efd->e->blocked_lock);
}

static sysreturn epoll_add_fd(epoll e, int fd, u32 events, u64 data)
{
    epollfd efd = epollfd_from_fd(e, fd);
    if (efd != INVALID_ADDRESS) {
        spin_lock(&efd->lock);
        if (efd->registered) {
            spin_unlock(&efd->lock);
            epoll_debug("   can't add fd %d to epoll %p; already exists\n", fd, e);
            return -EEXIST;
        }
    }

    epoll_debug("   adding %d, events 0x%x, data 0x%lx\n", fd, events, data);
    events |= POLL_EXCEPTIONS;
    if (efd == INVALID_ADDRESS) {
        if (alloc_epollfd(e, fd, events, data) == INVALID_ADDRESS)
            return -ENOMEM;
        efd = epollfd_from_fd(e, fd);
        assert(efd != INVALID_ADDRESS);
        spin_lock(&efd->lock);
    } else {
        reset_epollfd(efd, events, data);
    }
    register_epollfd(efd);

    /* apply check(s) for any current waiters */
    epollfd_update(efd);
    spin_unlock(&efd->lock);
    return 0;
}

static sysreturn remove_fd(epoll e, int fd)
{
    epoll_debug("   removing %d\n", fd);
    epollfd efd = epollfd_from_fd(e, fd);
    if (efd == INVALID_ADDRESS) {
        return -ENOENT;
    }
    release_epollfd(efd);
    return 0;
}

sysreturn epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    epoll_debug("epoll fd %d, op %d, fd %d\n", epfd, op, fd);

    /* A valid event pointer is required for all operations but EPOLL_CTL_DEL */
    if (op != EPOLL_CTL_DEL) {
        if (!fault_in_user_memory(event, sizeof(struct epoll_event), false))
            return -EFAULT;
    }

    sysreturn rv;
    fdesc f = resolve_fd(current->p, fd);
    if ((f->type == FDESC_TYPE_REGULAR) || (f->type == FDESC_TYPE_DIRECTORY))
        rv = -EPERM;
    else
        rv = 0;
    fdesc_put(f);
    if (rv)
        return rv;

    epoll e = resolve_fd(current->p, epfd);
    if ((e->f.type != FDESC_TYPE_EPOLL) || (f == &e->f)) {
        rv = -EINVAL;
        goto out;
    }
    spin_wlock(&e->fds_lock);
    switch(op) {
    case EPOLL_CTL_ADD:
        rv = epoll_add_fd(e, fd, event->events, event->data);
        break;
    case EPOLL_CTL_DEL:
        rv = remove_fd(e, fd);
        break;
    case EPOLL_CTL_MOD:
        epoll_debug("   modifying %d, events 0x%x, data 0x%lx\n", fd, event->events, event->data);
        rv = remove_fd(e, fd);
        if (rv == 0)
            rv = epoll_add_fd(e, fd, event->events, event->data);
        break;
    default:
        msg_err("unknown op %d\n", op);
        rv = -EINVAL;
    }
    spin_wunlock(&e->fds_lock);

  out:
    fdesc_put(&e->f);
    return rv;
}

/* XXX build these out */
#define POLLFDMASK_READ     (EPOLLIN | POLL_EXCEPTIONS)
#define POLLFDMASK_WRITE    (EPOLLOUT | POLL_EXCEPTIONS)
#define POLLFDMASK_EXCEPT   (EPOLLPRI)

static inline void select_notify(epollfd efd, epoll_blocked w, u64 events)
{
    if (efd->fd >= w->nfds)
        return;
    int count = 0;
    spin_lock(&w->lock);
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        w->retval = -EFAULT;
        goto out;
    }
    if (w->rset && (events & POLLFDMASK_READ)) {
        if (!bitmap_test_and_set_atomic(w->rset, efd->fd, 1))
            count++;
    }
    if (w->wset && (events & POLLFDMASK_WRITE)) {
        if (!bitmap_test_and_set_atomic(w->wset, efd->fd, 1))
            count++;
    }
    if (w->eset && (events & POLLFDMASK_EXCEPT)) {
        if (!bitmap_test_and_set_atomic(w->eset, efd->fd, 1))
            count++;
    }
    context_clear_err(ctx);
  out:
    if (w->retval >= 0)
        w->retval += count;
    spin_unlock(&w->lock);
    if (w->retval) {
        epoll_debug("   event on %d, events 0x%x\n", efd->fd, events);
        blockq_wake_one(w->t->thread_bq);
    }
}

closure_function(3, 1, sysreturn, select_bh,
                 epoll_blocked, w, thread, t, timestamp, timeout,
                 u64 flags)
{
    sysreturn rv;
    thread t = bound(t);
    epoll_blocked w = bound(w);
    timestamp timeout = bound(timeout);
    epoll_debug("w %p on tid %d, timeout %ld, flags 0x%lx, retcount %ld\n",
                w, t->tid, timeout, flags, w->retval);

    spin_lock(&w->lock);
    if (!timeout || (flags & BLOCKQ_ACTION_TIMEDOUT) || w->retval) {
        /* XXX error checking? */
        rv = w->retval;
        goto out_wakeup;
    }

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = (timeout == infinity) ? -ERESTARTSYS : -EINTR;
        goto out_wakeup;
    }
    spin_unlock(&w->lock);

    return blockq_block_required(&t->syscall->uc, flags);
  out_wakeup:
    if (w->rset)
        bitmap_unwrap(w->rset);
    if (w->wset)
        bitmap_unwrap(w->wset);
    if (w->eset)
        bitmap_unwrap(w->eset);
    w->nfds = 0;
    w->rset = w->wset = w->eset = 0;
    spin_unlock(&w->lock);
    epoll_blocked_release(w, flags);
    closure_finish();
    return syscall_return(t, rv);
}

static inline epoll thread_get_epoll(enum epoll_type epoll_type)
{
    thread t = current;
    thread_lock(t);
    epoll e = t->select_epoll;
    if (!e) {
        e = epoll_alloc_internal(epoll_type);
        if (e != INVALID_ADDRESS)
            t->select_epoll = e;
    } else {
        e->epoll_type = epoll_type;
    }
    thread_unlock(t);
    return e;
}

static sysreturn select_internal(int nfds,
                                 fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                                 timestamp timeout,
                                 const sigset_t * sigmask)
{
    u64 set_bytes = pad(nfds, 64) / 8;
    if ((readfds && !fault_in_user_memory(readfds, set_bytes, true)) ||
        (writefds && !fault_in_user_memory(writefds, set_bytes, true)) ||
        (exceptfds && !fault_in_user_memory(exceptfds, set_bytes, true)))
        return -EFAULT;

    epoll e = thread_get_epoll(EPOLL_TYPE_SELECT);
    if (e == INVALID_ADDRESS)
        return -ENOMEM;

    epoll_debug("nfds %d, readfds %p, writefds %p, exceptfds %p\n"
                "   timeout %d\n", nfds, readfds, writefds, exceptfds, timeout);
    bitmap_extend(e->fds, nfds - 1);
    u64 dummy = 0;
    u64 * rp = readfds ? readfds : &dummy;
    u64 * wp = writefds ? writefds : &dummy;
    u64 * ep = exceptfds ? exceptfds : &dummy;
    bitmap_foreach_word(e->fds, w, offset) {
        if (offset >= nfds) {
            /* nfds shrunk since an earlier call to select; just nuke
               any epollfds from here forward */
            bitmap_word_foreach_set(w, bit, fd, offset) {
                epoll_debug("   x fd %d\n", fd);
                remove_fd(e, fd);
            }
            continue;
        }

        /* update epollfds based on delta between registered fds and
        union of select fds */
        u64 u = *rp | *wp | *ep;
        u64 d = u ^ w;

        /* get alloc/free out of the way */
        bitmap_word_foreach_set(d, bit, fd, offset) {
            /* either add or remove epollfd */
            if (w & (1ull << bit)) {
                epoll_debug("   - fd %d\n", fd);
                remove_fd(e, fd);
            } else {
                epoll_debug("   + fd %d\n", fd);
                assert(alloc_epollfd(e, fd, 0, 0) != INVALID_ADDRESS);
            }
        }

        /* now process all events */
        bitmap_word_foreach_set(u, bit, fd, offset) {
            u32 eventmask = 0;
            u64 mask = 1ull << bit;
            epollfd efd = vector_get(e->events, fd);
            assert(efd);
            assert(efd->fd == fd);

            if (*rp & mask) {
                eventmask |= POLLFDMASK_READ;
                *rp &= ~mask;
            }
            if (*wp & mask) {
                eventmask |= POLLFDMASK_WRITE;
                *wp &= ~mask;
            }
            if (*ep & mask) {
                eventmask |= POLLFDMASK_EXCEPT;
                *ep &= ~mask;
            }
            epoll_debug("   fd %d eventmask (prev 0x%x, now 0x%x)\n", fd, efd->eventmask, eventmask);
            spin_lock(&efd->lock);
            if (eventmask != efd->eventmask) {
                if (efd->registered) {
                    epoll_debug("   replacing\n");
                    /* make into zombie; kind of brutal...need removal */
                    efd->zombie = true;
                    spin_unlock(&efd->lock);
                    release_epollfd(efd);
                    efd = alloc_epollfd(e, fd, eventmask, 0);
                    assert(efd != INVALID_ADDRESS);
                    spin_lock(&efd->lock);
                } else {
                    epoll_debug("   updating\n");
                    efd->eventmask = eventmask;
                }
            }

            if (!efd->registered)
                register_epollfd(efd);

            spin_unlock(&efd->lock);
        }

        if (readfds)
            rp++;
        if (writefds)
            wp++;
        if (exceptfds)
            ep++;
    }
    epoll_blocked wt = alloc_epoll_blocked(e);
    if (wt == INVALID_ADDRESS)
        return -ENOMEM;
    wt->nfds = nfds;
    if (readfds)
        wt->rset = bitmap_wrap(e->h, readfds, nfds);
    if (writefds)
        wt->wset = bitmap_wrap(e->h, writefds, nfds);
    if (exceptfds)
        wt->eset = bitmap_wrap(e->h, exceptfds, nfds);
    epoll_check_epollfds(e, wt);
    return blockq_check_timeout(wt->t->thread_bq,
                                contextual_closure(select_bh, wt, current, timeout), false,
                                CLOCK_ID_MONOTONIC, timeout != infinity ? timeout : 0, false);
}


sysreturn pselect(int nfds,
                  fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  struct timespec *timeout,
                  const sigset_t * sigmask)
{
    return select_internal(nfds, readfds, writefds, exceptfds, timeout ? time_from_timespec(timeout) : infinity, sigmask);
}

#ifdef __x86_64__
sysreturn select(int nfds,
                 u64 *readfds, u64 *writefds, u64 *exceptfds,
                 struct timeval *timeout)
{
    return select_internal(nfds, readfds, writefds, exceptfds, timeout ? time_from_timeval(timeout) : infinity, 0);
}
#endif

static inline void poll_notify(epollfd efd, epoll_blocked w, u64 events)
{
    if (events == 0)
        return;

    spin_lock(&w->lock);
    if (!w->poll_fds) {
        spin_unlock(&w->lock);
        return;
    }
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        w->retval = -EFAULT;
        goto out;
    }
    struct pollfd *pfd = buffer_ref(w->poll_fds, efd->data * sizeof(struct pollfd));
    if ((pfd->revents == 0) && (w->retval >= 0)) {
        /* Only increment if we're not amending an entry. */
        assert(w->retval++ <
               (w->poll_fds->length / sizeof(struct pollfd)));
    }
    pfd->revents = events;
    epoll_debug("   event on %d (%d), events 0x%x\n", efd->fd, pfd->fd, pfd->revents);
    context_clear_err(ctx);
  out:
    spin_unlock(&w->lock);
    blockq_wake_one(w->t->thread_bq);
}

closure_function(3, 1, sysreturn, poll_bh,
                 epoll_blocked, w, thread, t, timestamp, timeout,
                 u64 flags)
{
    sysreturn rv;
    thread t = bound(t);
    epoll_blocked w = bound(w);
    timestamp timeout = bound(timeout);
    epoll_debug("w %p on tid %d, timeout %ld, flags 0x%lx, poll_retcount %d\n",
                w, t->tid, timeout, flags, w->retval);

    spin_lock(&w->lock);
    if (!timeout || (flags & BLOCKQ_ACTION_TIMEDOUT) || w->retval) {
        /* XXX error checking? */
        rv = w->retval;
        goto out_wakeup;
    }

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = (timeout == infinity) ? -ERESTARTSYS : -EINTR;
        goto out_wakeup;
    }
    spin_unlock(&w->lock);

    return blockq_block_required(&t->syscall->uc, flags);
  out_wakeup:
    unwrap_buffer(w->e->h, w->poll_fds);
    w->poll_fds = 0;
    spin_unlock(&w->lock);
    epoll_blocked_release(w, flags);
    closure_finish();
    return syscall_return(t, rv);
}

static sysreturn poll_internal(struct pollfd *fds, nfds_t nfds,
                               timestamp timeout,
                               const sigset_t * sigmask)
{
    if (!validate_user_memory(fds, sizeof(struct pollfd) * nfds, true))
        return -EFAULT;
    epoll e = thread_get_epoll(EPOLL_TYPE_POLL);
    if (e == INVALID_ADDRESS)
        return -ENOMEM;

    epoll_debug("epoll nfds %ld, timeout %d\n", nfds, timeout);
    bitmap remove_efds = bitmap_clone(e->fds); /* efds to remove */
    for (int i = 0; i < nfds; i++) {
        struct pollfd *pfd = fds + i;
        pfd->revents = 0;
        epollfd efd;

        /* skip ignored events */
        if (pfd->fd < 0) {
            continue;
        }

        /* obtain efd */
        bitmap_extend(e->fds, pfd->fd);
        efd = epollfd_from_fd(e, pfd->fd);
        if (efd != INVALID_ADDRESS) {
            spin_lock(&efd->lock);
            if (!efd->registered) {
                epoll_debug("   = fd %d (registering)\n", pfd->fd);
                reset_epollfd(efd, pfd->events, i);
                register_epollfd(efd);
            } else {
                if (efd->eventmask != pfd->events || efd->data != i) {
                    epoll_debug("   = fd %d (replacing)\n", pfd->fd);
                    efd->zombie = true;
                    spin_unlock(&efd->lock);
                    release_epollfd(efd);
                    efd = alloc_epollfd(e, pfd->fd, pfd->events, i);
                    assert(efd != INVALID_ADDRESS);
                    spin_lock(&efd->lock);
                    register_epollfd(efd);
                } else {
                    epoll_debug("   = fd %d (unchanged)\n", pfd->fd);
                }
            }

            /* unmark for removal */
            bitmap_extend(remove_efds, pfd->fd);
            bitmap_set(remove_efds, pfd->fd, 0);
        } else {
            epoll_debug("   + fd %d\n", pfd->fd);
            efd = alloc_epollfd(e, pfd->fd, pfd->events, i);
            assert(efd != INVALID_ADDRESS);
            spin_lock(&efd->lock);
            register_epollfd(efd);
        }

        spin_unlock(&efd->lock);
    }

    /* clean efds */
    bitmap_foreach_set(remove_efds, fd) {
        epoll_debug("   - fd %d\n", fd);
        epollfd efd = epollfd_from_fd(e, fd);
        assert(efd != INVALID_ADDRESS);
        release_epollfd(efd);
    }
    deallocate_bitmap(remove_efds);

    epoll_blocked w = alloc_epoll_blocked(e);
    if (w == INVALID_ADDRESS)
        return -ENOMEM;
    w->poll_fds = wrap_buffer(e->h, fds, nfds * sizeof(struct pollfd));
    epoll_check_epollfds(e, w);
    return blockq_check_timeout(w->t->thread_bq,
                                contextual_closure(poll_bh, w, current, timeout), false,
                                CLOCK_ID_MONOTONIC, timeout != infinity ? timeout : 0, false);
}

/* archs like aarch64 don't have pause; glibc calls ppoll() with all null arguments to simulate... */
extern sysreturn pause(void);

sysreturn ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)
{
    if (nfds == 0 && !tmo_p)
        return pause();
    return poll_internal(fds, nfds, tmo_p ? time_from_timespec(tmo_p) : infinity, sigmask);
}

#ifdef __x86_64__
sysreturn poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return poll_internal(fds, nfds, timeout >= 0 ? milliseconds(timeout) : infinity, 0);
}
#endif

void register_poll_syscalls(struct syscall *map)
{
#ifdef __x86_64__
    register_syscall(map, epoll_create, epoll_create);
    register_syscall(map, epoll_wait, epoll_wait);
    register_syscall(map, poll, poll);
    register_syscall(map, select, select);
#endif
    register_syscall(map, epoll_create1, epoll_create);
    register_syscall(map, epoll_ctl, epoll_ctl);
    register_syscall(map, ppoll, ppoll);
    register_syscall(map, pselect6, pselect);
    register_syscall(map, epoll_pwait, epoll_wait); /* sigmask unused right now */
}

boolean poll_init(unix_heaps uh)
{
    return ((epoll_heap = heap_locked(get_kernel_heaps())) != INVALID_ADDRESS);
}
