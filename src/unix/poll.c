#include <unix_internal.h>

#ifdef EPOLL_DEBUG
#define epoll_debug(x, ...) do {log_printf("POLL", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define epoll_debug(x, ...)
#endif

typedef struct epoll *epoll;

typedef struct epollfd {
    int fd;
    u32 eventmask;  /* epoll events registered - XXX need lock */
    u32 lastevents; /* retain last received events; for edge trigger */
    u64 data;	    /* may be multiple versions of data? */
    u64 refcnt;
    epoll e;
    boolean registered;
    boolean zombie;		/* freed or masked by oneshot */
    notify_entry notify_handle;
} *epollfd;

typedef struct epoll_blocked *epoll_blocked;

enum epoll_type {
    EPOLL_TYPE_SELECT,
    EPOLL_TYPE_POLL,
    EPOLL_TYPE_EPOLL,
};

struct epoll_blocked {
    epoll e;
    u64 refcnt;
    thread t;
    boolean sleeping;
    enum epoll_type epoll_type;
    timer timeout;
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

struct epoll {
    struct fdesc f;             /* must be first */
    // xxx - multiple threads can block on the same e with epoll_wait
    struct list blocked_head;
    vector events;		/* epollfds indexed by fd */
    int nfds;
    bitmap fds;			/* fds being watched / epollfd registered */
};
    
static epollfd epollfd_from_fd(epoll e, int fd)
{
    if (!bitmap_get(e->fds, fd))
	return INVALID_ADDRESS;
    epollfd efd = vector_get(e->events, fd);
    assert(efd);
    return efd;
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
    efd->refcnt = 1;
    efd->registered = false;
    efd->zombie = false;
    vector_set(e->events, fd, efd);
    bitmap_set(e->fds, fd, 1);
    if (fd >= e->nfds)
	e->nfds = fd + 1;
    return efd;
}

static void release_epollfd(epollfd efd)
{
    epoll_debug("fd %d, refcnt %ld\n", efd->fd, efd->refcnt);
    assert(efd->refcnt > 0);
    if (fetch_and_add(&efd->refcnt, -1) == 1) {
        epoll_debug("  deallocating efd %p\n", efd);
	unix_cache_free(get_unix_heaps(), epollfd, efd);
    }
}

static void unregister_epollfd(epollfd efd)
{
    epoll_debug("efd %d\n", efd->fd);

    fdesc f = resolve_fd_noret(current->p, efd->fd);
    assert(f);
    epoll_debug("f->ns %p\n", f->ns);
    notify_remove(f->ns, efd->notify_handle);
    efd->registered = false;
    efd->notify_handle = 0;
}

static void free_epollfd(epollfd efd)
{
    epoll e = efd->e;
    int fd = efd->fd;
    epoll_debug("e %p, fd %d\n", e, fd);
    assert(vector_get(e->events, fd) == efd);
    vector_set(e->events, fd, 0);
    bitmap_set(e->fds, fd, 0);
    assert(efd->refcnt > 0);
    efd->zombie = true;
    if (efd->registered)
        unregister_epollfd(efd);
    release_epollfd(efd);
}

boolean register_epollfd(epollfd efd, event_handler eh)
{
    if (efd->registered)
        return false;

    /* If efd is in fds and also a zombie, it's an epfd that's
       been masked by a oneshot event. */
    if (efd->zombie)
        return false; // XXX
    fdesc f = resolve_fd(current->p, efd->fd);
    efd->registered = true;
    fetch_and_add(&efd->refcnt, 1);
    epoll_debug("fd %d, eventmask 0x%x, handler %p\n", efd->fd, efd->eventmask, eh);
    efd->notify_handle = notify_add(f->ns, efd->eventmask | (EPOLLERR | EPOLLHUP), eh);
    assert(efd->notify_handle != INVALID_ADDRESS);
    return true;
}

static CLOSURE_1_0(epoll_close, sysreturn, epoll);
static sysreturn epoll_close(epoll e)
{
    epoll_debug("e %p\n", e);
    bitmap_foreach_set(e->fds, fd) {
	epollfd efd = vector_get(e->events, fd);
	assert(efd != INVALID_ADDRESS);
	free_epollfd(efd);
    }
    deallocate_bitmap(e->fds);
    release_fdesc(&e->f);
    unix_cache_free(get_unix_heaps(), epoll, e);
    return 0;
}

sysreturn epoll_create(int flags)
{
    sysreturn rv;
    epoll_debug("flags 0x%x\n", flags);
    heap h = heap_general(get_kernel_heaps());
    epoll e = unix_cache_alloc(get_unix_heaps(), epoll);
    if (e == INVALID_ADDRESS)
	return -ENOMEM;
    u64 fd = allocate_fd(current->p, e);
    if (fd == INVALID_PHYSICAL) {
	rv = -EMFILE;
	goto out_cache_free;
    }
    init_fdesc(h, &e->f, FDESC_TYPE_EPOLL);
    e->f.close = closure(h, epoll_close, e);
    list_init(&e->blocked_head);
    e->events = allocate_vector(h, 8);
    if (e->events == INVALID_ADDRESS) {
	rv = -ENOMEM;
	goto out_dealloc_fd;
    }
    e->nfds = 0;
    e->fds = allocate_bitmap(h, infinity);
    if (e->fds == INVALID_ADDRESS) {
	rv = -ENOMEM;
	goto out_free_events;
    }
    epoll_debug("   got fd %d\n", fd);
    return fd;
  out_free_events:
    deallocate_vector(e->events);
  out_dealloc_fd:
    deallocate_fd(current->p, fd);
  out_cache_free:
    unix_cache_free(get_unix_heaps(), epoll, e);
    return rv;
}

#define user_event_count(__w) (buffer_length(__w->user_events)/sizeof(struct epoll_event))

static void epoll_blocked_release(epoll_blocked w)
{
    epoll_debug("w %p\n", w);
    if (!list_empty(&w->blocked_list)) {
	list_delete(&w->blocked_list);
        list_init(&w->blocked_list);
	epoll_debug("   removed from epoll list\n");
    }
    if (fetch_and_add(&w->refcnt, -1) == 1) {
	unix_cache_free(get_unix_heaps(), epoll_blocked, w);
	epoll_debug("   deallocated\n");
    }
}

static CLOSURE_2_0(epoll_blocked_finish, void, epoll_blocked, boolean);
static void epoll_blocked_finish(epoll_blocked w, boolean timedout)
{
#ifdef EPOLL_DEBUG
    epoll_debug("w %p, refcnt %ld\n", w, w->refcnt);
    if (w->sleeping)
	epoll_debug("   sleeping\n");
    if (timedout)
	epoll_debug("   timed out %p\n", w->timeout);
#endif
    heap h = heap_general(get_kernel_heaps());

    if (w->sleeping) {
        w->sleeping = false;
        thread_wakeup(w->t);
        sysreturn rv = 0;

        switch (w->epoll_type) {
        case EPOLL_TYPE_SELECT:
	    if (w->rset)
		bitmap_unwrap(w->rset);
	    if (w->wset)
		bitmap_unwrap(w->wset);
	    if (w->eset)
		bitmap_unwrap(w->eset);
            w->nfds = 0;
	    w->rset = w->wset = w->eset = 0;
	    rv = w->retcount;	/* XXX error check */
            break;
        case EPOLL_TYPE_POLL:
            unwrap_buffer(h, w->poll_fds);
            w->poll_fds = 0;
            rv = w->poll_retcount;
            break;
        case EPOLL_TYPE_EPOLL:
	    rv = user_event_count(w);
	    unwrap_buffer(h, w->user_events);
	    w->user_events = 0;
            break;
	}

	epoll_debug("   syscall return %ld\n", rv);
	set_syscall_return(w->t, rv);

	/* We'll let the timeout run to expiry until we can be sure
	   that we have a race-free way to disable the timer if waking
	   on an event.

	   XXX This will have to be revisited, for we'll accumulate a
	   bunch of zombie epoll_blocked and timer objects until they
	   start timing out.
	*/
#ifdef EPOLL_DEBUG
	if (w->timeout && !timedout)
	    epoll_debug("      timer remains; refcount %ld\n", w->refcnt);
#endif
	epoll_blocked_release(w);
    } else if (timedout) {
	epoll_debug("   timer expiry after syscall return; ignored\n");
	assert(w->refcnt == 1);
	epoll_blocked_release(w);
    } else {
	epoll_debug("   in syscall or zombie event\n");
    }
}

static inline u32 report_from_notify_events(epollfd efd, u32 events)
{
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

static CLOSURE_1_1(epoll_wait_notify, void, epollfd, u32);
static void epoll_wait_notify(epollfd efd, u32 events)
{
    list l = list_get_next(&efd->e->blocked_head);

    if (events == NOTIFY_EVENTS_RELEASE) {
        epoll_debug("efd->fd %d unregistered\n", efd->fd);
        efd->registered = false;
        return;
    }

    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    u32 report = report_from_notify_events(efd, events);
    assert(efd->registered);
    epoll_debug("efd->fd %d, events 0x%x, report 0x%x, blocked %p, zombie %d\n",
                efd->fd, events, report, w, efd->zombie);

    /* XXX need to do some work to properly dole out to multiple epoll_waits (threads)... */
    if (report && w && !efd->zombie) {
	if (w->user_events && (w->user_events->length - w->user_events->end)) {
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
	} else {
            /* XXX here we should advance to the next blocked head, probably */
	    epoll_debug("   user_events null or full\n");
	    return;
	}
	epoll_blocked_finish(w, false);
    }
}

static epoll_blocked alloc_epoll_blocked(epoll e)
{
    epoll_blocked w = unix_cache_alloc(get_unix_heaps(), epoll_blocked);
    if (w == INVALID_ADDRESS)
	return w;
    w->refcnt = 1;
    w->t = current;
    w->e = e;
    w->sleeping = false;
    w->timeout = 0;
    list_insert_after(&e->blocked_head, &w->blocked_list); /* push */
    return w;
}

static void check_fdesc(fdesc f)
{
    notify_dispatch(f->ns, apply(f->events));
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
    heap h = heap_general(get_kernel_heaps());
    epoll e = resolve_fd(current->p, epfd);
    epoll_blocked w = alloc_epoll_blocked(e);
    if (w == INVALID_ADDRESS)
	return -ENOMEM;

    epoll_debug("epoll fd %d, new blocked %p, timeout %d\n", epfd, w, timeout);
    w->epoll_type = EPOLL_TYPE_EPOLL;
    w->user_events = wrap_buffer(h, events, maxevents * sizeof(struct epoll_event));
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
            free_epollfd(efd);
            continue;
        }

        /* event transitions may in some cases need to be polled for
           (e.g. due to change in lwIP internal state), so request a check */
        if (efd->registered)
            check_fdesc(f);
    }

    int eventcount = w->user_events->end/sizeof(struct epoll_event);
    if (timeout == 0 || w->user_events->end) {
	epoll_debug("   immediate return; eventcount %d\n", eventcount);
	epoll_blocked_release(w);
        return eventcount;
    }

    if (timeout > 0) {
	w->timeout = register_timer(milliseconds(timeout), closure(h, epoll_blocked_finish, w, true));
	fetch_and_add(&w->refcnt, 1);
	epoll_debug("   registered timer %p\n", w->timeout);
    }
    epoll_debug("   sleeping...\n");
    w->sleeping = true;
    thread_sleep_uninterruptible(); /* XXX move to blockq */
    return 0;			/* suppress warning */
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
    register_epollfd(efd, closure(heap_general(get_kernel_heaps()), epoll_wait_notify, efd));

    /* apply check if we have a waiter */
    if (!list_empty(&efd->e->blocked_head)) {
        epoll_debug("   posting check for blocked waiter\n");
        check_fdesc(f);
    }

    return 0;
}

static sysreturn remove_fd(epoll e, int fd)
{
    epoll_debug("   removing %d\n", fd);
    epollfd efd = epollfd_from_fd(e, fd);
    if (efd == INVALID_ADDRESS) {
        return -ENOENT;
    }
    free_epollfd(efd);
    return 0;
}

sysreturn epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    epoll e = resolve_fd(current->p, epfd);    
    epoll_debug("epoll fd %d, op %d, fd %d\n", epfd, op, fd);
    fdesc f = resolve_fd(current->p, fd);

    /* EPOLLEXCLUSIVE not yet implemented */
    if (event->events & EPOLLEXCLUSIVE) {
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

static CLOSURE_1_1(select_notify, void, epollfd, u32);
static void select_notify(epollfd efd, u32 events)
{
    list l = list_get_next(&efd->e->blocked_head);

    if (events == NOTIFY_EVENTS_RELEASE) {
        epoll_debug("efd->fd %d unregistered\n", efd->fd);
        efd->registered = false;
        return;
    }

    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    epoll_debug("efd->fd %d, events 0x%x, blocked %p, zombie %d\n",
	    efd->fd, events, w, efd->zombie);

    if (!efd->zombie && w && efd->fd < w->nfds) {
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
	    epoll_blocked_finish(w, false);
	}
    }
}

static epoll select_get_epoll()
{
    epoll e = current->select_epoll;
    if (!e) {
	heap h = heap_general(get_kernel_heaps());
	file f = unix_cache_alloc(get_unix_heaps(), epoll);
	if (f == INVALID_ADDRESS)
	    return INVALID_ADDRESS;
 	e = (epoll)f;
	list_init(&e->blocked_head);
	e->events = allocate_vector(h, 8);
	assert(e->events != INVALID_ADDRESS);
	e->fds = allocate_bitmap(h, infinity);
	assert(e->fds != INVALID_ADDRESS);
	current->select_epoll = e;
    }
    return e;
}

static sysreturn select_internal(int nfds,
				 fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
				 timestamp timeout,
				 const sigset_t * sigmask)
{
    unix_heaps uh = get_unix_heaps();
    heap h = heap_general((kernel_heaps)uh);
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
    sysreturn rv = 0;

    epoll_debug("nfds %d, readfds %p, writefds %p, exceptfds %p\n"
	    "   epoll_blocked %p, timeout %d\n", nfds, readfds, writefds, exceptfds,
	    w, timeout);
    if (nfds == 0)
	goto check_rv_timeout;

    w->rset = readfds ? bitmap_wrap(h, readfds, nfds) : 0;
    w->wset = writefds ? bitmap_wrap(h, writefds, nfds) : 0;
    w->eset = exceptfds ? bitmap_wrap(h, exceptfds, nfds) : 0;

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
		if (alloc_epollfd(e, fd, 0, 0) == INVALID_ADDRESS) {
		    rv = -EBADF;
		    goto check_rv_timeout;
		}
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
                free_epollfd(efd);
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
                    free_epollfd(efd);
                    efd = alloc_epollfd(e, fd, eventmask, 0);
                    assert(efd != INVALID_ADDRESS);
		} else {
		    epoll_debug("   updating\n");
		    efd->eventmask = eventmask;
		}
	    }

	    if (!efd->registered)
                register_epollfd(efd, closure(h, select_notify, efd));

            check_fdesc(f);
	}

	if (readfds)
	    rp++;
	if (writefds)
	    wp++;
	if (exceptfds)
	    ep++;
    }
    rv = w->retcount;
  check_rv_timeout:
    if (timeout == 0 || rv != 0) {
	epoll_debug("   immediate return; return %ld\n", rv);
	epoll_blocked_release(w);
	return rv;
    }

    if (timeout != infinity) {
	w->timeout = register_timer(timeout, closure(h, epoll_blocked_finish, w, true));
	fetch_and_add(&w->refcnt, 1);
	epoll_debug("   registered timer %p\n", w->timeout);
    }
    epoll_debug("   sleeping...\n");
    w->sleeping = true;
    thread_sleep_uninterruptible(); /* XXX move to blockq */
    return 0;			/* suppress warning */
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

static CLOSURE_1_1(poll_notify, void, epollfd, u32);
static void poll_notify(epollfd efd, u32 events)
{
    list l = list_get_next(&efd->e->blocked_head);

    if (events == NOTIFY_EVENTS_RELEASE) {
        epoll_debug("efd->fd %d unregistered\n", efd->fd);
        efd->registered = false;
        return;
    }

    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    epoll_debug("efd->fd %d, events 0x%x, blocked %p, zombie %d\n",
            efd->fd, events, w, efd->zombie);
    assert(efd->registered);

    if (events && w && !efd->zombie) {
        struct pollfd *pfd = buffer_ref(w->poll_fds, efd->data * sizeof(struct pollfd));
        fetch_and_add(&w->poll_retcount, 1);
        pfd->revents = events;
        epoll_debug("   event on %d (%d), events 0x%x\n", efd->fd, pfd->fd, pfd->revents);
        epoll_blocked_finish(w, false);
    }
}

static sysreturn poll_internal(struct pollfd *fds, nfds_t nfds,
                               timestamp timeout,
                               const sigset_t * sigmask)
{
    heap h = heap_general(get_kernel_heaps());
    epoll e = select_get_epoll();
    if (e == INVALID_ADDRESS)
        return -ENOMEM;
    epoll_blocked w = alloc_epoll_blocked(e);
    if (w == INVALID_ADDRESS)
        return -ENOMEM;

    epoll_debug("epoll nfds %ld, new blocked %p, timeout %d\n", nfds, w, timeout);
    w->epoll_type = EPOLL_TYPE_POLL;
    w->poll_fds = wrap_buffer(h, fds, nfds * sizeof(struct pollfd));
    w->poll_retcount = 0;
    sysreturn rv = 0;

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
                register_epollfd(efd, closure(h, poll_notify, efd));
            } else {
                if (efd->eventmask != pfd->events || efd->data != i) {
                    epoll_debug("   = fd %d (replacing)\n", pfd->fd);
                    free_epollfd(efd);
                    efd = alloc_epollfd(e, pfd->fd, pfd->events, i);
                    assert(efd != INVALID_ADDRESS);
                    register_epollfd(efd, closure(h, poll_notify, efd));
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
            if (efd == INVALID_ADDRESS) {
                rv = -EBADF;
                goto check_rv_timeout;
            }
            fdesc f = resolve_fd_noret(current->p, efd->fd);
            assert(f);
            register_epollfd(efd, closure(h, poll_notify, efd));
        }

        fdesc f = resolve_fd_noret(current->p, efd->fd);
        if (!f) {
            epoll_debug("   x fd %d\n", pfd->fd);
            free_epollfd(efd);
            continue;
        }

        fetch_and_add(&efd->refcnt, 1);
        epoll_debug("   register fd %d, eventmask 0x%x, applying check\n",
            efd->fd, efd->eventmask);
        check_fdesc(f);
    }

    /* clean efds */
    bitmap_foreach_set(remove_efds, fd) {
        epoll_debug("   - fd %d\n", fd);
        epollfd efd = epollfd_from_fd(e, fd);
        assert(efd != INVALID_ADDRESS);
        free_epollfd(efd);
    }

    rv = w->poll_retcount;

check_rv_timeout:
    deallocate_bitmap(remove_efds);

    if (timeout == 0 || rv) {
        epoll_debug("   immediate return; return %d\n", rv);
        epoll_blocked_release(w);
        return rv;
    }

    if (timeout != infinity) {
        w->timeout = register_timer(timeout, closure(h, epoll_blocked_finish, w, true));
        fetch_and_add(&w->refcnt, 1);
        epoll_debug("   registered timer %p\n", w->timeout);
    }
    epoll_debug("   sleeping...\n");
    w->sleeping = true;
    thread_sleep_uninterruptible(); /* XXX move to blockq */
    return 0; /* suppress warning */
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
