#include <unix_internal.h>

//#define EPOLL_DEBUG
#ifdef EPOLL_DEBUG
#define epoll_debug(x, ...) do {log_printf("POLL", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define epoll_debug(x, ...)
#endif

typedef struct epollfd *epollfd;

declare_closure_struct(1, 0, void, epollfd_free,
                       epollfd, efd);

typedef struct epollfd {
    int fd;
    u32 eventmask;  /* epoll events registered - XXX need lock */
    u32 lastevents; /* retain last received events; for edge trigger */
    u64 data;	    /* may be multiple versions of data? */
    struct refcount refcount;
    closure_struct(epollfd_free, free);
    epoll e;
    boolean registered;
    boolean zombie;		/* freed or masked by oneshot */
    notify_entry notify_handle;
} *epollfd;

typedef struct epoll_blocked *epoll_blocked;

declare_closure_struct(1, 0, void, epoll_blocked_free,
                       epoll_blocked, w);

enum epoll_type {
    EPOLL_TYPE_SELECT,
    EPOLL_TYPE_POLL,
    EPOLL_TYPE_EPOLL,
};

struct epoll_blocked {
    epoll e;
    thread t;
    enum epoll_type epoll_type;
    struct refcount refcount;
    closure_struct(epoll_blocked_free, free);
    union {
	buffer user_events;
        struct {
            buffer poll_fds;
            u64 poll_retcount;
        };
	struct {
            int nfds;
            bitmap rset;
            bitmap wset;
            bitmap eset;
            u64 retcount;
	};
    };
    struct list blocked_list;
};

declare_closure_struct(1, 0, void, epoll_free,
                       epoll, e);

/* we call it an epoll, but these structs are used for select and poll too */
struct epoll {
    struct fdesc f;             /* must be first */
    struct list blocked_head;   /* an epoll_blocked per thread (in epoll_wait)  */
    struct refcount refcount;
    closure_struct(epoll_free, free);
    heap h;
    vector events;		/* epollfds indexed by fd */
    int nfds;
    bitmap fds;			/* fds being watched / epollfd registered */
};
    
define_closure_function(1, 0, void, epoll_free,
                        epoll, e)
{
    epoll e = bound(e);
    epoll_debug("e %p\n", e);
    deallocate_bitmap(e->fds);
    deallocate_vector(e->events);
    if (e->f.close && e->f.close != INVALID_ADDRESS)
        deallocate_closure(e->f.close);
    unix_cache_free(get_unix_heaps(), epoll, e);
}

static epoll epoll_alloc_internal(void)
{
    epoll e = unix_cache_alloc(get_unix_heaps(), epoll);
    if (e == INVALID_ADDRESS)
	return e;

    list_init(&e->blocked_head);
    init_refcount(&e->refcount, 1, init_closure(&e->free, epoll_free, e));
    e->h = heap_general(get_kernel_heaps());
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
    unix_cache_free(get_unix_heaps(), epoll, e);
    return INVALID_ADDRESS;
}

define_closure_function(1, 0, void, epollfd_free,
                        epollfd, efd)
{
    epollfd efd = bound(efd);
    epoll_debug("fd %d\n", efd->fd);
    refcount_release(&efd->e->refcount); /* release epoll */
    unix_cache_free(get_unix_heaps(), epollfd, efd);
}

static epollfd alloc_epollfd(epoll e, int fd, u32 eventmask, u64 data)
{
    epoll_debug("e %p, fd %d, eventmask 0x%x, data 0x%lx\n", e, fd, eventmask, data);
    epollfd efd = unix_cache_alloc(get_unix_heaps(), epollfd);
    if (efd == INVALID_ADDRESS)
	return efd;
    efd->fd = fd;
    efd->eventmask = eventmask;
    efd->lastevents = 0;
    efd->e = e;
    efd->data = data;
    init_refcount(&efd->refcount, 1, init_closure(&efd->free, epollfd_free, efd));
    efd->registered = false;
    efd->zombie = false;
    vector_set(e->events, fd, efd);
    bitmap_set(e->fds, fd, 1);
    if (fd >= e->nfds)
	e->nfds = fd + 1;
    refcount_reserve(&e->refcount);
    return efd;
}

static void unregister_epollfd(epollfd efd)
{
    fdesc f = resolve_fd_noret(current->p, efd->fd);
    assert(f);
    epoll_debug("efd %d, pre refcount %ld, f->ns %p\n", efd->fd, efd->refcount.c, f->ns);
    notify_remove(f->ns, efd->notify_handle, true);
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
    vector_set(e->events, fd, 0);
    bitmap_set(e->fds, fd, 0);
    efd->zombie = true;
    if (efd->registered)
        unregister_epollfd(efd);
    refcount_release(&efd->refcount); /* alloc */
}

/* XXX maybe merge alloc and registration */
static boolean register_epollfd(epollfd efd, event_handler eh)
{
    if (efd->registered)
        return false;

    /* If efd is in fds and also a zombie, it's an epfd that's
       been masked by a oneshot event. */
    if (efd->zombie)
        return false; // XXX
    fdesc f = resolve_fd(current->p, efd->fd);
    efd->registered = true;
    refcount_reserve(&efd->refcount); /* registration */
    epoll_debug("fd %d, eventmask 0x%x, handler %p\n", efd->fd, efd->eventmask, eh);
    efd->notify_handle = notify_add(f->ns, efd->eventmask | (EPOLLERR | EPOLLHUP), eh);
    assert(efd->notify_handle != INVALID_ADDRESS);
    return true;
}

static void epoll_release_epollfds(epoll e)
{
    bitmap_foreach_set(e->fds, fd) {
	epollfd efd = vector_get(e->events, fd);
	assert(efd != 0 && efd != INVALID_ADDRESS);
	release_epollfd(efd);
    }
}

void epoll_finish(epoll e)
{
    epoll_debug("e %p\n", e);
    epoll_release_epollfds(e);
    refcount_release(&e->refcount);
}

closure_function(1, 0, sysreturn, epoll_close,
                 epoll, e)
{
    epoll e = bound(e);
    release_fdesc(&e->f);
    epoll_finish(e);
    return 0;
}

sysreturn epoll_create(int flags)
{
    sysreturn rv;
    epoll_debug("flags 0x%x\n", flags);
    epoll e = epoll_alloc_internal();
    if (e == INVALID_ADDRESS)
        return -ENOMEM;
    u64 fd = allocate_fd(current->p, e);
    if (fd == INVALID_PHYSICAL) {
	rv = -EMFILE;
	goto out_dealloc_epoll;
    }
    init_fdesc(e->h, &e->f, FDESC_TYPE_EPOLL);
    e->f.close = closure(e->h, epoll_close, e);
    if (e->f.close == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out_dealloc_fd;
    }
    epoll_debug("   got fd %d\n", fd);
    return fd;
  out_dealloc_fd:
    deallocate_fd(current->p, fd);
  out_dealloc_epoll:
    refcount_release(&e->refcount);
    return rv;
}

#define user_event_count(__w) (buffer_length(__w->user_events)/sizeof(struct epoll_event))

define_closure_function(1, 0, void, epoll_blocked_free,
                        epoll_blocked, w)
{
    epoll_blocked w = bound(w);
    epoll_debug("w %p\n", w);
    thread_release(w->t);
    refcount_release(&w->e->refcount);
    unix_cache_free(get_unix_heaps(), epoll_blocked, w);
}

static void epoll_blocked_release(epoll_blocked w)
{
    epoll_debug("w %p\n", w);
    assert(!list_empty(&w->blocked_list));
    list_delete(&w->blocked_list);
    list_init(&w->blocked_list);
    refcount_release(&w->refcount);
}

static inline u32 report_from_notify_events(epollfd efd, u64 notify_events)
{
    u32 events = (u32)notify_events;
    boolean edge_detect = (efd->eventmask & EPOLLET) != 0;

    /* catch falling edges for EPOLLET */
    if (edge_detect) {
        u32 falling = efd->lastevents & ~events;
        if (falling)
            efd->lastevents &= ~falling;
    }

    /* only report rising edges if edge detect */
    return edge_detect ? ~efd->lastevents & events : events;
}

closure_function(1, 2, void, epoll_wait_notify,
                 epollfd, efd,
                 u64, notify_events,
                 thread, t)
{
    epollfd efd = bound(efd);
    list l = list_get_next(&efd->e->blocked_head);

    /* only path to freedom - even fd removals trigger release */
    if (notify_events == NOTIFY_EVENTS_RELEASE) {
        epoll_debug("efd->fd %d unregistered\n", efd->fd);
        efd->registered = false;
        closure_finish();
        return;
    }

    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    u32 events = (u32)notify_events;
    u32 report = report_from_notify_events(efd, events);
    assert(efd->registered);
    epoll_debug("efd->fd %d, events 0x%x, report 0x%x, blocked %p, zombie %d\n",
                efd->fd, events, report, w, efd->zombie);

    /* XXX need to do some work to properly dole out to multiple epoll_waits (threads)... */
    if (report == 0 || !w || efd->zombie)
        return;

    if (t && t != w->t)
        return;

    if (!w->user_events || (w->user_events->length - w->user_events->end) <= 0) {
        /* XXX here we should advance to the next blocked head, probably */
        epoll_debug("   user_events null or full\n");
        return;
    }

    struct epoll_event *e = buffer_ref(w->user_events, w->user_events->end);
    e->data = efd->data;
    e->events = report;
    w->user_events->end += sizeof(struct epoll_event);
    epoll_debug("   epoll_event %p, data 0x%lx, events 0x%x\n", e, e->data, e->events);

    /* XXX check this */
    if (efd->eventmask & EPOLLONESHOT)
        efd->zombie = true;

    /* now that we've reported these events, update last */
    efd->lastevents |= report;
    blockq_wake_one(w->t->thread_bq);
}

static epoll_blocked alloc_epoll_blocked(epoll e)
{
    epoll_blocked w = unix_cache_alloc(get_unix_heaps(), epoll_blocked);
    if (w == INVALID_ADDRESS)
	return w;
    epoll_debug("w %p\n", w);

    /* initial reservation released on thread wakeup (or direct return) */
    init_refcount(&w->refcount, 1, init_closure(&w->free, epoll_blocked_free, w));
    w->t = current;
    thread_reserve(w->t);
    w->e = e;
    refcount_reserve(&e->refcount);
    list_insert_after(&e->blocked_head, &w->blocked_list); /* push */
    return w;
}

static void check_fdesc(fdesc f, thread t)
{
    notify_dispatch_for_thread(f->ns, apply(f->events, t), t);
}

/* It would be nice to devise a way to allow a poll waiter to continue
   to collect events between wakeup (first event) and running. */

closure_function(3, 1, sysreturn, epoll_wait_bh,
                 epoll_blocked, w, thread, t, boolean, blockable,
                 u64, flags)
{
    sysreturn rv;
    thread t = bound(t);
    epoll_blocked w = bound(w);
    int eventcount = user_event_count(w);

    epoll_debug("w %p on tid %d, blockable %d, flags 0x%lx, event count %d\n",
                w, t->tid, bound(blockable), flags, eventcount);

    if (!bound(blockable) || (flags & BLOCKQ_ACTION_TIMEDOUT) || eventcount) {
        rv = eventcount;
        goto out_wakeup;
    }

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        /* XXX verify */
        rv = -EAGAIN;
        goto out_wakeup;
    }

    epoll_debug("  continue blocking\n");
    return BLOCKQ_BLOCK_REQUIRED;
  out_wakeup:
    if (flags & BLOCKQ_ACTION_BLOCKED)
        thread_wakeup(t);
    unwrap_buffer(w->e->h, w->user_events);
    w->user_events = 0;
    epoll_debug("   pre refcnt %ld, returning %ld\n", w->refcount.c, rv);
    epoll_blocked_release(w);
    closure_finish();
    return set_syscall_return(t, rv);
}

/* Depending on the epoll flags given, we may:
   - notify all waiters on a match (default)
   - notify on a match only once until condition is reset (EPOLLET)
   - notify once before removing the registration, handled upstream (EPOLLONESHOT)
   - notify only one matching waiter, even across multiple epoll instances (EPOLLEXCLUSIVE)
     - XXX Not implemented; will require tracking reported events on a per fd - not per
           registration - basis.
*/
sysreturn epoll_wait(int epfd,
                     struct epoll_event *events,
                     int maxevents,
                     int timeout)
{
    epoll e = resolve_fd(current->p, epfd);
    epoll_blocked w = alloc_epoll_blocked(e);
    if (w == INVALID_ADDRESS)
	return -ENOMEM;

    epoll_debug("tid %d, epoll fd %d, new blocked %p, timeout %d\n", current->tid, epfd, w, timeout);
    w->epoll_type = EPOLL_TYPE_EPOLL;
    w->user_events = wrap_buffer(e->h, events, maxevents * sizeof(struct epoll_event));
    w->user_events->end = 0;

    bitmap_foreach_set(e->fds, fd) {
	epollfd efd = vector_get(e->events, fd);
	assert(efd);
        assert(efd->fd == fd);

        if (efd->zombie)
            continue;

        fdesc f = resolve_fd_noret(current->p, efd->fd);
        if (!f) {
            epoll_debug("   x fd %d\n", efd->fd);
            release_epollfd(efd);
            continue;
        }

        /* event transitions may in some cases need to be polled for
           (e.g. due to change in lwIP internal state), so request a check */
        if (efd->registered)
            check_fdesc(f, current);
    }

    return blockq_check_timeout(w->t->thread_bq, current,
                                closure(e->h, epoll_wait_bh, w, current, timeout != 0), false,
                                CLOCK_ID_MONOTONIC, timeout > 0 ? milliseconds(timeout) : 0, false);
}

static epollfd epollfd_from_fd(epoll e, int fd)
{
    if (!bitmap_get(e->fds, fd))
	return INVALID_ADDRESS;
    epollfd efd = vector_get(e->events, fd);
    assert(efd);
    return efd;
}

static void epollfd_update(epollfd efd, fdesc f)
{
    /* It may seem excessive to perform a check for all
       waiters. However, thanks to thread-specific fd events (thanks
       in turn to signalfd), we could have independent events for
       multiple threads that require waking - even on the same fd. */

    /* XXX take lock */
    list_foreach(&efd->e->blocked_head, l) {
        epoll_blocked w = struct_from_list(l, epoll_blocked, blocked_list);
        epoll_debug("   posting check for blocked waiter (tid %d)\n", w->t->tid);
        check_fdesc(f, w->t);
    }
    /* XXX release lock */
}

static sysreturn epoll_add_fd(epoll e, int fd, u32 events, u64 data)
{
    if (epollfd_from_fd(e, fd) != INVALID_ADDRESS) {
        epoll_debug("   can't add fd %d to epoll %p; already exists\n", fd, e);
        return -EEXIST;
    }

    epoll_debug("   adding %d, events 0x%x, data 0x%lx\n", fd, events, data);
    if (alloc_epollfd(e, fd, events | EPOLLERR | EPOLLHUP, data) == INVALID_ADDRESS)
        return -ENOMEM;

    epollfd efd = epollfd_from_fd(e, fd);
    assert(efd != INVALID_ADDRESS);
    fdesc f = resolve_fd_noret(current->p, efd->fd);
    assert(f);
    register_epollfd(efd, closure(e->h, epoll_wait_notify, efd));

    /* apply check(s) for any current waiters */
    epollfd_update(efd, f);
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
    epoll e = resolve_fd(current->p, epfd);    
    epoll_debug("epoll fd %d, op %d, fd %d\n", epfd, op, fd);
    fdesc f = resolve_fd(current->p, fd);

    /* A valid event pointer is required for all operations but EPOLL_CTL_DEL */
    if ((op != EPOLL_CTL_DEL) && !event) {
        return set_syscall_error(current, EFAULT);
    }

    /* EPOLLEXCLUSIVE not yet implemented */
    if (event && (event->events & EPOLLEXCLUSIVE)) {
        msg_err("add: EPOLLEXCLUSIVE not supported\n");
        return set_syscall_error(current, EINVAL);
    }

    if ((f->type == FDESC_TYPE_REGULAR) || (f->type == FDESC_TYPE_DIRECTORY)) {
	return set_syscall_error(current, EPERM);
    }

    /* XXX verify that fd is not an epoll instance*/
    switch(op) {
    case EPOLL_CTL_ADD:
        return set_syscall_return(current, epoll_add_fd(e, fd, event->events, event->data));
    case EPOLL_CTL_DEL:
        return set_syscall_return(current, remove_fd(e, fd));
    case EPOLL_CTL_MOD:
	epoll_debug("   modifying %d, events 0x%x, data 0x%lx\n", fd, event->events, event->data);
        sysreturn rv = remove_fd(e, fd);
        if (rv != 0)
            return set_syscall_return(current, rv);

        return set_syscall_return(current, epoll_add_fd(e, fd, event->events, event->data));
    default:
	msg_err("unknown op %d\n", op);
	return set_syscall_error(current, EINVAL);
    }

    return 0;
}

/* XXX build these out */
#define POLLFDMASK_READ		(EPOLLIN | EPOLLHUP | EPOLLERR)
#define POLLFDMASK_WRITE	(EPOLLOUT | EPOLLHUP | EPOLLERR)
#define POLLFDMASK_EXCEPT	(EPOLLPRI)

closure_function(1, 2, void, select_notify,
                 epollfd, efd,
                 u64, notify_events,
                 thread, t)
{
    epollfd efd = bound(efd);
    list l = list_get_next(&efd->e->blocked_head);

    if (notify_events == NOTIFY_EVENTS_RELEASE) {
        epoll_debug("efd->fd %d unregistered\n", efd->fd);
        efd->registered = false;
        closure_finish();
        return;
    }

    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    u32 events = (u32)notify_events;
    epoll_debug("efd->fd %d, events 0x%x, blocked %p, zombie %d\n",
	    efd->fd, events, w, efd->zombie);

    if (efd->zombie || !w || efd->fd >= w->nfds)
        return;

    if (t && t != w->t)
        return;

    assert(w->epoll_type == EPOLL_TYPE_SELECT);
    int count = 0;
    /* XXX need thread safe / cas bitmap ops */
    /* trusting that notifier masked events */
    if (events & POLLFDMASK_READ) {
        bitmap_set(w->rset, efd->fd, 1);
        count++;
    }
    if (events & POLLFDMASK_WRITE) {
        bitmap_set(w->wset, efd->fd, 1);
        count++;
    }
    if (events & POLLFDMASK_EXCEPT) {
        bitmap_set(w->eset, efd->fd, 1);
        count++;
    }
    if (count > 0) {
        fetch_and_add(&w->retcount, count);
        epoll_debug("   event on %d, events 0x%x\n", efd->fd, events);
        blockq_wake_one(w->t->thread_bq);
    }
}

closure_function(3, 1, sysreturn, select_bh,
                 epoll_blocked, w, thread, t, boolean, blockable,
                 u64, flags)
{
    sysreturn rv;
    thread t = bound(t);
    epoll_blocked w = bound(w);
    epoll_debug("w %p on tid %d, blockable %d, flags 0x%lx, retcount %ld\n",
                w, t->tid, bound(blockable), flags, w->retcount);

    if (!bound(blockable) || (flags & BLOCKQ_ACTION_TIMEDOUT) || w->retcount) {
        /* XXX error checking? */
        rv = w->retcount;
        goto out_wakeup;
    }

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        /* XXX verify */
        rv = -EAGAIN;
        goto out_wakeup;
    }

    return BLOCKQ_BLOCK_REQUIRED;
  out_wakeup:
    if (w->rset)
        bitmap_unwrap(w->rset);
    if (w->wset)
        bitmap_unwrap(w->wset);
    if (w->eset)
        bitmap_unwrap(w->eset);
    w->nfds = 0;
    w->rset = w->wset = w->eset = 0;
    epoll_blocked_release(w);
    if (flags & BLOCKQ_ACTION_BLOCKED)
        thread_wakeup(t);
    closure_finish();
    return set_syscall_return(t, rv);
}

static inline epoll select_get_epoll(void)
{
    epoll e = current->select_epoll;
    if (!e) {
        e = epoll_alloc_internal();
        if (e != INVALID_ADDRESS)
            current->select_epoll = e;
    }
    return e;
}

static sysreturn select_internal(int nfds,
				 fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
				 timestamp timeout,
				 const sigset_t * sigmask)
{
    if (nfds == 0 && timeout == infinity)
        return 0;

    epoll e = select_get_epoll();
    if (e == INVALID_ADDRESS)
	return -ENOMEM;
    epoll_blocked w = alloc_epoll_blocked(e);
    if (w == INVALID_ADDRESS)
	return -ENOMEM;
    w->epoll_type = EPOLL_TYPE_SELECT;
    w->nfds = nfds;
    w->rset = w->wset = w->eset = 0;
    w->retcount = 0;

    epoll_debug("nfds %d, readfds %p, writefds %p, exceptfds %p\n"
                "   epoll_blocked %p, timeout %d\n", nfds, readfds, writefds, exceptfds,
                w, timeout);
    if (nfds == 0)            /* timeout != infinity */
        goto check_timeout;

    w->rset = readfds ? bitmap_wrap(e->h, readfds, nfds) : 0;
    w->wset = writefds ? bitmap_wrap(e->h, writefds, nfds) : 0;
    w->eset = exceptfds ? bitmap_wrap(e->h, exceptfds, nfds) : 0;

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
            fdesc f = resolve_fd_noret(current->p, efd->fd);
            if (!f) {
                epoll_debug("   x fd %d\n", efd->fd);
                release_epollfd(efd);
                continue;
            }

	    /* XXX again these need to be thread/int-safe / cas access */
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
            if (eventmask != efd->eventmask) {
                if (efd->registered) {
                    epoll_debug("   replacing\n");
                    /* make into zombie; kind of brutal...need removal */
                    release_epollfd(efd);
                    efd = alloc_epollfd(e, fd, eventmask, 0);
                    assert(efd != INVALID_ADDRESS);
		} else {
		    epoll_debug("   updating\n");
		    efd->eventmask = eventmask;
		}
	    }

	    if (!efd->registered)
                register_epollfd(efd, closure(e->h, select_notify, efd));

            check_fdesc(f, current);
	}

	if (readfds)
	    rp++;
	if (writefds)
	    wp++;
	if (exceptfds)
	    ep++;
    }
  check_timeout:
    return blockq_check_timeout(w->t->thread_bq, current,
                                closure(e->h, select_bh, w, current, timeout != 0), false,
                                CLOCK_ID_MONOTONIC, timeout != infinity ? timeout : 0, false);
}


sysreturn pselect(int nfds,
		  fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		  struct timespec *timeout,
		  const sigset_t * sigmask)
{
    return select_internal(nfds, readfds, writefds, exceptfds, timeout ? time_from_timespec(timeout) : infinity, sigmask);
}

sysreturn select(int nfds,
		 u64 *readfds, u64 *writefds, u64 *exceptfds,
		 struct timeval *timeout)
{
    return select_internal(nfds, readfds, writefds, exceptfds, timeout ? time_from_timeval(timeout) : infinity, 0);
}

closure_function(1, 2, void, poll_notify,
                 epollfd, efd,
                 u64, notify_events,
                 thread, t)
{
    epollfd efd = bound(efd);
    list l = list_get_next(&efd->e->blocked_head);

    if (notify_events == NOTIFY_EVENTS_RELEASE) {
        epoll_debug("efd->fd %d unregistered\n", efd->fd);
        efd->registered = false;
        closure_finish();
        return;
    }

    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    u32 events = (u32)notify_events;
    epoll_debug("efd->fd %d, events 0x%x, blocked %p, zombie %d\n",
            efd->fd, events, w, efd->zombie);
    assert(efd->registered);

    if (events == 0 || !w || efd->zombie)
        return;

    if (t && t != w->t)
        return;

    struct pollfd *pfd = buffer_ref(w->poll_fds, efd->data * sizeof(struct pollfd));
    fetch_and_add(&w->poll_retcount, 1);
    pfd->revents = events;
    epoll_debug("   event on %d (%d), events 0x%x\n", efd->fd, pfd->fd, pfd->revents);
    blockq_wake_one(w->t->thread_bq);
}

closure_function(3, 1, sysreturn, poll_bh,
                 epoll_blocked, w, thread, t, boolean, blockable,
                 u64, flags)
{
    sysreturn rv;
    thread t = bound(t);
    epoll_blocked w = bound(w);
    epoll_debug("w %p on tid %d, blockable %d, flags 0x%lx, poll_retcount %d\n",
                w, t->tid, bound(blockable), flags, w->poll_retcount);

    if (!bound(blockable) || (flags & BLOCKQ_ACTION_TIMEDOUT) || w->poll_retcount) {
        /* XXX error checking? */
        rv = w->poll_retcount;
        goto out_wakeup;
    }

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        /* XXX verify */
        rv = -EAGAIN;
        goto out_wakeup;
    }

    return BLOCKQ_BLOCK_REQUIRED;
  out_wakeup:
    unwrap_buffer(w->e->h, w->poll_fds);
    w->poll_fds = 0;
    epoll_blocked_release(w);
    if (flags & BLOCKQ_ACTION_BLOCKED)
        thread_wakeup(t);
    closure_finish();
    return set_syscall_return(t, rv);
}

static sysreturn poll_internal(struct pollfd *fds, nfds_t nfds,
                               timestamp timeout,
                               const sigset_t * sigmask)
{
    epoll e = select_get_epoll();
    if (e == INVALID_ADDRESS)
        return -ENOMEM;
    epoll_blocked w = alloc_epoll_blocked(e);
    if (w == INVALID_ADDRESS)
        return -ENOMEM;

    epoll_debug("epoll nfds %ld, new blocked %p, timeout %d\n", nfds, w, timeout);
    w->epoll_type = EPOLL_TYPE_POLL;
    w->poll_fds = wrap_buffer(e->h, fds, nfds * sizeof(struct pollfd));
    w->poll_retcount = 0;

    bitmap remove_efds = bitmap_clone(e->fds); /* efds to remove */
    for (int i = 0; i < nfds; i++) {
        struct pollfd *pfd = fds + i;
        epollfd efd;

        /* skip ignored events */
        if (pfd->fd < 0) {
            pfd->revents = 0;
            continue;
        }

        /* obtain efd */
        bitmap_extend(e->fds, pfd->fd);
        efd = epollfd_from_fd(e, pfd->fd);
        if (efd != INVALID_ADDRESS) {
            if (!efd->registered) {
                epoll_debug("   = fd %d (registering)\n", pfd->fd);
                efd->eventmask = pfd->events;
                efd->data = i;
                register_epollfd(efd, closure(e->h, poll_notify, efd));
            } else {
                if (efd->eventmask != pfd->events || efd->data != i) {
                    epoll_debug("   = fd %d (replacing)\n", pfd->fd);
                    release_epollfd(efd);
                    efd = alloc_epollfd(e, pfd->fd, pfd->events, i);
                    assert(efd != INVALID_ADDRESS);
                    register_epollfd(efd, closure(e->h, poll_notify, efd));
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
            fdesc f = resolve_fd_noret(current->p, efd->fd);
            assert(f);
            register_epollfd(efd, closure(e->h, poll_notify, efd));
        }

        fdesc f = resolve_fd_noret(current->p, efd->fd);
        if (!f) {
            epoll_debug("   x fd %d\n", pfd->fd);
            release_epollfd(efd);
            continue;
        }

        epoll_debug("   register fd %d, eventmask 0x%x, applying check\n",
            efd->fd, efd->eventmask);
        check_fdesc(f, current);
    }

    /* clean efds */
    bitmap_foreach_set(remove_efds, fd) {
        epoll_debug("   - fd %d\n", fd);
        epollfd efd = epollfd_from_fd(e, fd);
        assert(efd != INVALID_ADDRESS);
        release_epollfd(efd);
    }
    deallocate_bitmap(remove_efds);

    return blockq_check_timeout(w->t->thread_bq, current,
                                closure(e->h, poll_bh, w, current, timeout != 0), false,
                                CLOCK_ID_MONOTONIC, timeout != infinity ? timeout : 0, false);
}

sysreturn ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)
{
    return poll_internal(fds, nfds, tmo_p ? time_from_timespec(tmo_p) : infinity, sigmask);
}

sysreturn poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return poll_internal(fds, nfds, timeout >= 0 ? milliseconds(timeout) : infinity, 0);
}

void register_poll_syscalls(struct syscall *map)
{
    register_syscall(map, epoll_create, epoll_create);
    register_syscall(map, epoll_create1, epoll_create);
    register_syscall(map, epoll_ctl, epoll_ctl);
    register_syscall(map, poll, poll);
    register_syscall(map, ppoll, ppoll);
    register_syscall(map, select, select);
    register_syscall(map, pselect6, pselect);
    register_syscall(map, epoll_wait, epoll_wait);
    register_syscall(map, epoll_pwait, epoll_wait); /* sigmask unused right now */
}

boolean poll_init(unix_heaps uh)
{
    heap general = heap_general((kernel_heaps)uh);
    heap backed = heap_backed((kernel_heaps)uh);

    if ((uh->epoll_cache = allocate_objcache(general, backed, sizeof(struct epoll), PAGESIZE))
	== INVALID_ADDRESS)
	return false;
    if ((uh->epollfd_cache = allocate_objcache(general, backed, sizeof(struct epollfd), PAGESIZE))
	== INVALID_ADDRESS)
	return false;
    if ((uh->epoll_blocked_cache = allocate_objcache(general, backed, sizeof(struct epoll_blocked), PAGESIZE))
	== INVALID_ADDRESS)
	return false;

    return true;
}
