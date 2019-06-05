#include <unix_internal.h>

#ifdef EPOLL_DEBUG
#define epoll_debug(x, ...) do {log_printf("POLL", x, ##__VA_ARGS__);} while(0)
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

static void epollfd_release(epollfd efd)
{
    epoll_debug("epollfd_release: efd %p, fd %d, refcnt %ld\n", efd, efd->fd, efd->refcnt);
    assert(efd->refcnt > 0);
    if (fetch_and_add(&efd->refcnt, -1) == 1) {
        epoll_debug("epollfd_release: deallocating efd %p\n", efd);
	unix_cache_free(get_unix_heaps(), epollfd, efd);
    }
}

static void free_epollfd(epollfd efd)
{
    epoll e = efd->e;
    int fd = efd->fd;
    assert(vector_get(e->events, fd) == efd);
    vector_set(e->events, fd, 0);
    bitmap_set(e->fds, fd, 0);
    assert(efd->refcnt > 0);
    efd->zombie = true;
    epollfd_release(efd);
}

static CLOSURE_1_0(epoll_close, sysreturn, epoll);
static sysreturn epoll_close(epoll e)
{
    bitmap_foreach_set(e->fds, fd) {
	epollfd efd = vector_get(e->events, fd);
	assert(efd != INVALID_ADDRESS);
	free_epollfd(efd);
    }
    deallocate_bitmap(e->fds);
    unix_cache_free(get_unix_heaps(), epoll, e);
    return 0;
}

sysreturn epoll_create(int flags)
{
    sysreturn rv;
    epoll_debug("epoll_create: flags 0x%x\n", flags);
    heap h = heap_general(get_kernel_heaps());
    epoll e = unix_cache_alloc(get_unix_heaps(), epoll);
    if (e == INVALID_ADDRESS)
	return -ENOMEM;
    u64 fd = allocate_fd(current->p, e);
    if (fd == INVALID_PHYSICAL) {
	rv = -EMFILE;
	goto out_cache_free;
    }
    fdesc_init(&e->f, FDESC_TYPE_EPOLL);
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
    epoll_debug("epoll_blocked_release: w %p\n", w);
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

/* XXX need to check for races as completions may come from timer and
   other interrupts */
static CLOSURE_2_0(epoll_blocked_finish, void, epoll_blocked, boolean);
static void epoll_blocked_finish(epoll_blocked w, boolean timedout)
{
#ifdef EPOLL_DEBUG
    epoll_debug("epoll_blocked_finish: w %p, refcnt %ld\n", w, w->refcnt);
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

	epoll_debug("\n   syscall return %ld\n", rv);
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

// associated with the current blocking function
static CLOSURE_1_1(epoll_wait_notify, boolean, epollfd, u32);
static boolean epoll_wait_notify(epollfd efd, u32 events)
{
    boolean reported = false;
    list l = list_get_next(&efd->e->blocked_head);

    /* XXX we should be walking the whole blocked list unless
       EPOLLEXCLUSIVE is set */
    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    epoll_debug("epoll_wait_notify: efd->fd %d, events 0x%x, blocked %p, zombie %d\n",
	    efd->fd, events, w, efd->zombie);
    efd->registered = false;
    if (w && !efd->zombie && events != NOTIFY_EVENTS_RELEASE) {
	// strided vectors?
	if (w->user_events && (w->user_events->length - w->user_events->end)) {
	    struct epoll_event *e = buffer_ref(w->user_events, w->user_events->end);
	    e->data = efd->data;
	    e->events = events;
	    w->user_events->end += sizeof(struct epoll_event);
	    epoll_debug("   epoll_event %p, data 0x%lx, events 0x%x\n", e, e->data, e->events);
	    if (efd->eventmask & EPOLLONESHOT)
		efd->zombie = true;
            reported = true;
	} else {
	    epoll_debug("   user_events null or full\n");
	    return false;
	}
	epoll_blocked_finish(w, false);
    }

    epollfd_release(efd);
    return reported;
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

static boolean epoll_check(heap h, epollfd efd, fdesc f)
{
    /* If efd is in fds and also a zombie, it's an epfd that's
       been masked by a oneshot event. */
    if (!efd->registered && !efd->zombie) {
        if (f->check) {
            efd->registered = true;
            fetch_and_add(&efd->refcnt, 1);
            epoll_debug("   register fd %d, eventmask 0x%x, applying check\n",
                        efd->fd, efd->eventmask);
            if (!apply(f->check, efd->eventmask | (EPOLLERR | EPOLLHUP),
                       &efd->lastevents,
                       closure(h, epoll_wait_notify, efd)))
                return false;
        } else {
            msg_err("requested fd %d (eventmask 0x%x) missing check\n", efd->fd, efd->eventmask);
        }
    }
    return true;
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

    epoll_debug("epoll_wait: epoll fd %d, new blocked %p, timeout %d\n", epfd, w, timeout);
    w->epoll_type = EPOLL_TYPE_EPOLL;
    w->user_events = wrap_buffer(h, events, maxevents * sizeof(struct epoll_event));
    w->user_events->end = 0;

    bitmap_foreach_set(e->fds, fd) {
	epollfd efd = vector_get(e->events, fd);
	assert(efd);
        assert(efd->fd == fd);
        fdesc f = resolve_fd_noret(current->p, efd->fd);
        if (!f) {
            epoll_debug("   x fd %d\n", efd->fd);
            free_epollfd(efd);
            continue;
        }

        if (!epoll_check(h, efd, f))
            break;
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
    thread_sleep(current);
    return 0;			/* suppress warning */
}

sysreturn epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    heap h = heap_general(get_kernel_heaps());
    epoll e = resolve_fd(current->p, epfd);    
    epoll_debug("epoll_ctl: epoll fd %d, op %d, fd %d\n", epfd, op, fd);
    /* XXX verify that fd is not an epoll instance*/
    epollfd efd;
    switch(op) {
    case EPOLL_CTL_ADD:
	/* EPOLLEXCLUSIVE not yet implemented */
	if (event->events & EPOLLEXCLUSIVE) {
	    msg_err("add: EPOLLEXCLUSIVE not supported\n");
	    return set_syscall_error(current, EINVAL);
	}
	epoll_debug("   adding %d, events 0x%x, data 0x%lx\n", fd, event->events, event->data);
	if (alloc_epollfd(e, fd, event->events | EPOLLERR | EPOLLHUP, event->data) == INVALID_ADDRESS)
	    return set_syscall_error(current, ENOMEM);
        /* if we have a blocked waiter, see if we can post any events
           XXX add lock */
        efd = epollfd_from_fd(e, fd);
        assert(efd != INVALID_ADDRESS);
        fdesc f = resolve_fd_noret(current->p, efd->fd);
        assert(f);
        if (!list_empty(&efd->e->blocked_head)) {
            epoll_debug("   posting check for blocked waiter\n");
            epoll_check(h, efd, f);
        }
	break;
    case EPOLL_CTL_DEL:
	epoll_debug("   removing %d\n", fd);
	efd = epollfd_from_fd(e, fd);
	if (efd == INVALID_ADDRESS) {
	    msg_err("delete for unregistered fd %d\n", fd);
	    return set_syscall_error(current, ENOENT);
	}
	free_epollfd(efd);
	break;
    case EPOLL_CTL_MOD:
	/* EPOLLEXCLUSIVE not allowed in modify */
	if (event->events & EPOLLEXCLUSIVE)
	    return set_syscall_error(current, EINVAL);
	epoll_debug("   modifying %d, events 0x%x, data 0x%lx\n", fd, event->events, event->data);
	efd = epollfd_from_fd(e, fd);
	if (efd == INVALID_ADDRESS) {
	    msg_err("modify for unregistered fd %d\n", fd);
	    return set_syscall_error(current, ENOENT);
	}
	free_epollfd(efd);
	if (alloc_epollfd(e, fd, event->events | EPOLLERR | EPOLLHUP, event->data) == INVALID_ADDRESS)
	    return set_syscall_error(current, ENOMEM);
	break;
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

static CLOSURE_1_1(select_notify, boolean, epollfd, u32);
static boolean select_notify(epollfd efd, u32 events)
{
    boolean reported = false;
    list l = list_get_next(&efd->e->blocked_head);
    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    epoll_debug("select_notify: efd->fd %d, events 0x%x, blocked %p, zombie %d\n",
	    efd->fd, events, w, efd->zombie);
    efd->registered = false;
    if (!efd->zombie && w && efd->fd < w->nfds && events != NOTIFY_EVENTS_RELEASE) {
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
	assert(count);
	fetch_and_add(&w->retcount, count);
        reported = true;
	epoll_debug("   event on %d, events 0x%x\n", efd->fd, events);
	epoll_blocked_finish(w, false);
    }
    epollfd_release(efd);
    return reported;
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

static inline void free_fd(epoll e, int fd)
{
    epollfd efd = epollfd_from_fd(e, fd);
    assert(efd != INVALID_ADDRESS);
    free_epollfd(efd);
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

    epoll_debug("select_internal: nfds %d, readfds %p, writefds %p, exceptfds %p\n"
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
                free_fd(e, fd);
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
                free_fd(e, fd);
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

	    if (!efd->registered) {
		efd->registered = true;
		fetch_and_add(&efd->refcnt, 1);
		epoll_debug("      register epollfd %d, eventmask 0x%x, applying check\n",
			efd->fd, efd->eventmask);
		apply(f->check, efd->eventmask, &efd->lastevents, closure(h, select_notify, efd));
	    }
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
    thread_sleep(current);
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

static CLOSURE_1_1(poll_wait_notify, boolean, epollfd, u32);
static boolean poll_wait_notify(epollfd efd, u32 events)
{
    boolean reported = false;
    list l = list_get_next(&efd->e->blocked_head);

    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
    epoll_debug("poll_wait_notify: efd->fd %d, events 0x%x, blocked %p, zombie %d\n",
            efd->fd, events, w, efd->zombie);
    efd->registered = false;
    if (w && !efd->zombie && events != NOTIFY_EVENTS_RELEASE) {
        struct pollfd *pfd = buffer_ref(w->poll_fds, efd->data * sizeof(struct pollfd));
        fetch_and_add(&w->poll_retcount, 1);
        reported = true;
        pfd->revents = events;
        epoll_debug("   event on %d (%d), events 0x%x\n", efd->fd, pfd->fd, pfd->revents);
        epoll_blocked_finish(w, false);
    }

    epollfd_release(efd);
    return reported;
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

    epoll_debug("poll_internal: epoll nfds %ld, new blocked %p, timeout %d\n", nfds, w, timeout);
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
            if (efd->registered) {
                epoll_debug("   = fd %d (replacing)\n", pfd->fd);
                /* make into zombie; kind of brutal...need removal */
                free_epollfd(efd);
                efd = alloc_epollfd(e, pfd->fd, pfd->events, i);
                assert(efd != INVALID_ADDRESS);
            } else {
                epoll_debug("   = fd %d (updating)\n", pfd->fd);
                efd->eventmask = pfd->events;
                efd->data = i;
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
        }
        fdesc f = resolve_fd_noret(current->p, efd->fd);
        if (!f) {
            epoll_debug("   x fd %d\n", pfd->fd);
            free_epollfd(efd);
            continue;
        }

        if (!f->check) {
            msg_err("requested fd %d (eventmask 0x%x) missing check\n", pfd->fd, pfd->events);
            continue;
        }

        assert(!efd->registered);
        efd->registered = true;
        fetch_and_add(&efd->refcnt, 1);
        epoll_debug("   register fd %d, eventmask 0x%x, applying check\n",
            efd->fd, efd->eventmask);
        if (!apply(f->check, efd->eventmask | (EPOLLERR | EPOLLHUP),
                   &efd->lastevents,
                   closure(h, poll_wait_notify, efd)))
            break;
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
    thread_sleep(current);
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
