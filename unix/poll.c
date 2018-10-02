#include <unix_internal.h>

//#define EPOLL_DEBUG

typedef struct epoll *epoll;

typedef struct epollfd {
    int fd; //debugging only - XXX REMOVE
    file f;
    u32 eventmask;		/* epoll events registered - XXX need lock */
    u64 data; // may be multiple versions of data?
    u64 refcnt;
    epoll e;
    boolean registered;
    boolean zombie;
    // xxx bind fd to first blocked that cares
} *epollfd;

typedef struct epoll_blocked *epoll_blocked;

struct epoll_blocked {
    epoll e;
    u64 refcnt;
    thread t;
    boolean sleeping;
    boolean select;
    timer timeout;
    union {
	buffer user_events;
	struct {
	    bitmap rset;
	    bitmap wset;
	    bitmap eset;
	    u64 retcount;
	};
    };
    struct list blocked_list;
};

struct epoll {
    struct file f;
    // xxx - multiple threads can block on the same e with epoll_wait
    struct list blocked_head;
    vector events;		/* epollfds indexed by fd */
    int nfds;
    bitmap fds;			/* fds being watched / epollfd registered */
};
    
static CLOSURE_1_0(epoll_close, sysreturn, epoll);
static sysreturn epoll_close(epoll e)
{
    // XXX need to dealloc epollfd and epoll_blocked structs too
    unix_cache_free(get_unix_heaps(), epoll, e);
    return 0;
}

sysreturn epoll_create(u64 flags)
{
#ifdef EPOLL_DEBUG
    rprintf("epoll_create: flags %P, ", flags);
#endif
    heap h = heap_general(get_kernel_heaps());
    file f = unix_cache_alloc(get_unix_heaps(), epoll);
    if (f == INVALID_ADDRESS)
	return -ENOMEM;
    u64 fd = allocate_fd(current->p, f);
    if (fd == INVALID_PHYSICAL) {
	unix_cache_free(get_unix_heaps(), epoll, f);
	return -EMFILE;
    }
    epoll e = (epoll)f;
    f->close = closure(h, epoll_close, e);
    list_init(&e->blocked_head);
    e->events = allocate_vector(h, 8);
    e->nfds = 0;
    e->fds = allocate_bitmap(h, infinity);
#ifdef EPOLL_DEBUG
    rprintf("got fd %d\n", fd);
#endif
    return fd;
}

#define user_event_count(__w) (buffer_length(__w->user_events)/sizeof(struct epoll_event))

static void epoll_blocked_release(epoll_blocked w)
{
    epoll e = w->e;
#ifdef EPOLL_DEBUG
    rprintf("epoll_blocked_release: w %p", w);
#endif
    if (!list_empty(&w->blocked_list)) {
	list_delete(&w->blocked_list);
#ifdef EPOLL_DEBUG
	rprintf(", removed from epoll list");
#endif
    }
    if (fetch_and_add(&w->refcnt, -1) == 0) {
	unix_cache_free(get_unix_heaps(), epoll_blocked, w);
#ifdef EPOLL_DEBUG
	rprintf(", deallocated");
#endif
    }
#ifdef EPOLL_DEBUG
    rprintf("\n");
#endif
}

/* XXX need to check for races as completions may come from timer and
   other interrupts */
static CLOSURE_2_0(epoll_blocked_finish, void, epoll_blocked, boolean);
static void epoll_blocked_finish(epoll_blocked w, boolean timedout)
{
#ifdef EPOLL_DEBUG
    rprintf("epoll_blocked_finish: w %p, refcnt %d", w, w->refcnt);
    if (w->sleeping)
	rprintf(", sleeping");
    if (timedout)
	rprintf(", timed out %p", w->timeout);
#endif
    heap h = heap_general(get_kernel_heaps());

    if (w->sleeping) {
        w->sleeping = false;
        thread_wakeup(w->t);
	sysreturn rv;

	if (w->select) {
	    if (w->rset)
		bitmap_unwrap(w->rset);
	    if (w->wset)
		bitmap_unwrap(w->wset);
	    if (w->eset)
		bitmap_unwrap(w->eset);
	    w->rset = w->wset = w->eset = 0;
	    rv = w->retcount;	/* XXX error check */
	} else {
	    rv = user_event_count(w);
	    unwrap_buffer(h, w->user_events);
	    w->user_events = 0;
	}

#ifdef EPOLL_DEBUG
	rprintf("\n   syscall return %d\n", rv);
#endif
	set_syscall_return(w->t, rv);

	/* We'll let the timeout run to expiry until we can be sure
	   that we have a race-free way to disable the timer if waking
	   on an event.

	   This will have to be revisited, for we'll accumulate a
	   bunch of zombie epoll_blocked and timer objects until they
	   start timing out.
	*/
#ifdef EPOLL_DEBUG
	if (w->timeout && !timedout)
	    rprintf("      timer remains; refcount %d\n", w->refcnt);
#endif
	epoll_blocked_release(w);
    } else if (timedout) {
#ifdef EPOLL_DEBUG
	rprintf("\n   timer expiry after syscall return; ignored\n");
#endif
	assert(w->refcnt == 1);
	epoll_blocked_release(w);
    } else {
#ifdef EPOLL_DEBUG
	rprintf("\n   ignored: in syscall or zombie event\n");
#endif
    }
}

static void epollfd_release(epollfd f)
{
#ifdef EPOLL_DEBUG
    rprintf("epollfd_release: f->fd %d, refcnt %d\n", f->fd, f->refcnt);
#endif
    assert(f->refcnt > 0);
    if (fetch_and_add(&f->refcnt, -1) == 0)
	unix_cache_free(get_unix_heaps(), epollfd, f);
}

// associated with the current blocking function
static CLOSURE_1_1(epoll_wait_notify, boolean, epollfd, u32);
static boolean epoll_wait_notify(epollfd f, u32 events)
{
    list l = list_get_next(&f->e->blocked_head);
    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
#ifdef EPOLL_DEBUG
    rprintf("epoll_wait_notify: f->fd %d, events %P, blocked %p, zombie %d\n",
	    f->fd, events, w, f->zombie);
#endif
    f->registered = false;
    if (!f->zombie && w) {
	// strided vectors?
	if (w->user_events && (w->user_events->length - w->user_events->end)) {
	    struct epoll_event *e = buffer_ref(w->user_events, w->user_events->end);
	    e->data = f->data;
	    e->events = events;
	    w->user_events->end += sizeof(struct epoll_event);
#ifdef EPOLL_DEBUG
	    rprintf("   epoll_event %p, data %P, events %P\n", e, e->data, e->events);
#endif
	} else {
#ifdef EPOLL_DEBUG
	    rprintf("   user_events null or full\n");
#endif
	    return false;
	}
	epoll_blocked_finish(w, false);
    }
    epollfd_release(f);
    return true;
}

static epoll_blocked alloc_epoll_blocked(epoll e)
{
    epoll_blocked w = unix_cache_alloc(get_unix_heaps(), epoll_blocked);
    w->refcnt = 1;
    w->t = current;
    w->e = e;
    w->sleeping = false;
    w->timeout = 0;
    list_insert_after(&e->blocked_head, &w->blocked_list); /* push */
    return w;
}

sysreturn epoll_wait(int epfd,
               struct epoll_event *events,
               int maxevents,
               int timeout)
{
    heap h = heap_general(get_kernel_heaps());
    epoll e = resolve_fd(current->p, epfd);
    epoll_blocked w = alloc_epoll_blocked(e);
    w->select = false;
#ifdef EPOLL_DEBUG
    rprintf("epoll_wait: epoll fd %d, new blocked %p, timeout %d\n", epfd, w, timeout);
#endif
    w->user_events = wrap_buffer(h, events, maxevents * sizeof(struct epoll_event));
    w->user_events->end = 0;

    bitmap_foreach_set(e->fds, fd) {
	assert(bitmap_get(e->fds, fd));
        epollfd f = vector_get(e->events, fd);
	assert(f);
        if (!f->registered) {
            f->registered = true;
	    fetch_and_add(&f->refcnt, 1);
#ifdef EPOLL_DEBUG
	    rprintf("   register fd %d, eventmask %P, applying check\n",
		    f->fd, f->eventmask);
#endif
            if (!apply(f->f->check, f->eventmask, closure(h, epoll_wait_notify, f)))
		break;
        }
    }

    int eventcount = w->user_events->end/sizeof(struct epoll_event);
    if (timeout == 0 || w->user_events->end) {
#ifdef EPOLL_DEBUG
	rprintf("   immediate return; eventcount %d\n", eventcount);
#endif
	epoll_blocked_release(w);
        return eventcount;
    }

    if (timeout > 0) {
	w->timeout = register_timer(/* looks wrong */milliseconds(timeout), closure(h, epoll_blocked_finish, w, true));
	fetch_and_add(&w->refcnt, 1);
#ifdef EPOLL_DEBUG
	rprintf("   registered timer %p\n", w->timeout);
#endif
    }
#ifdef EPOLL_DEBUG
    rprintf("   sleeping...\n");
#endif
    w->sleeping = true;
    thread_sleep(current);
    return 0;			/* suppress warning */
}

static epollfd alloc_epollfd(epoll e, int fd, u32 eventmask, u64 data)
{
    file fp = resolve_fd_noret(current->p, fd);
    if (!fp)
	return 0;
    epollfd f = unix_cache_alloc(get_unix_heaps(), epollfd);
    f->f = fp;
    f->eventmask = eventmask;
    f->fd = fd;
    f->e = e;
    f->data = data;
    f->refcnt = 1;
    f->registered = false;
    f->zombie = false;
    vector_set(e->events, fd, f);
    bitmap_set(e->fds, fd, 1);
    if (fd >= e->nfds)
	e->nfds = fd + 1;
    return f;
}

static void free_epollfd(epoll e, int fd)
{
    epollfd f;
    
    if (fd >= e->nfds ||
	!(f = vector_get(e->events, fd))) {
	msg_err("epollfd not found for fd %d\n", fd);
	return;
    }
    vector_set(e->events, fd, 0);
    bitmap_set(e->fds, fd, 0);
    assert(!bitmap_get(e->fds, fd));
    assert(f->refcnt > 0);
    f->zombie = true;
    epollfd_release(f);
}

sysreturn epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    epoll e = resolve_fd(current->p, epfd);    
#ifdef EPOLL_DEBUG
    rprintf("epoll_ctl: epoll fd %d, op %d, fd %d\n", epfd, op, fd);
#endif
    file fp = resolve_fd(current->p, fd); /* may return on error */
    switch(op) {
    case EPOLL_CTL_ADD:
#ifdef EPOLL_DEBUG
	rprintf("   adding %d\n", fd);
#endif
	if (!alloc_epollfd(e, fd, event->events | EPOLLERR | EPOLLHUP, event->data))
	    return -EBADF;
	break;
    case EPOLL_CTL_DEL:
#ifdef EPOLL_DEBUG
	rprintf("   removing %d\n", fd);
#endif
	free_epollfd(e, fd);
	break;
    case EPOLL_CTL_MOD:
	halt("no epoll_ctl mod\n");
#ifdef EPOLL_DEBUG
	rprintf("   modifying %d\n", fd);
#endif
	/* XXX share w select */
    default:
	msg_err("unknown op %d\n", op);
	return -EINVAL;
    }

    return 0;
}

/* XXX build these out */
#define POLLFDMASK_READ		(EPOLLIN | EPOLLHUP | EPOLLERR)
#define POLLFDMASK_WRITE	(EPOLLOUT | EPOLLHUP | EPOLLERR)
#define POLLFDMASK_EXCEPT	(EPOLLPRI)

static CLOSURE_1_1(select_notify, boolean, epollfd, u32);
static boolean select_notify(epollfd f, u32 events)
{
    list l = list_get_next(&f->e->blocked_head);
    epoll_blocked w = l ? struct_from_list(l, epoll_blocked, blocked_list) : 0;
#ifdef EPOLL_DEBUG
    rprintf("select_notify: f->fd %d, events %P, blocked %p, zombie %d\n",
	    f->fd, events, w, f->zombie);
#endif
    f->registered = false;
    if (!f->zombie && w) {
	assert(w->select);
	int count = 0;
	/* XXX need thread safe / cas bitmap ops */
	/* trusting that notifier masked events */
	if (events & POLLFDMASK_READ) {
	    bitmap_set(w->rset, f->fd, 1);
	    count++;
	}
	if (events & POLLFDMASK_WRITE) {
	    bitmap_set(w->wset, f->fd, 1);
	    count++;
	}
	if (events & POLLFDMASK_EXCEPT) {
	    bitmap_set(w->eset, f->fd, 1);
	    count++;
	}
	assert(count);
	fetch_and_add(&w->retcount, count);
#ifdef EPOLL_DEBUG
	rprintf("   event on %d, events %P\n", f->fd, events);
#endif
	epoll_blocked_finish(w, false);
    }
    epollfd_release(f);
    return true;
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
	e->fds = allocate_bitmap(h, infinity);
	current->select_epoll = e;
    }
    return e;
}

static sysreturn select_internal(int nfds,
				 fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
				 time timeout,
				 const sigset_t * sigmask)
{
    unix_heaps uh = get_unix_heaps();
    heap h = heap_general((kernel_heaps)uh);
    epoll e = select_get_epoll();
    if (e == INVALID_ADDRESS)
	return -ENOMEM;
    epoll_blocked w = alloc_epoll_blocked(e);
    w->select = true;
    w->rset = w->wset = w->eset = 0;
    w->retcount = 0;
    sysreturn rv = 0;

#ifdef EPOLL_DEBUG
    rprintf("select_internal: nfds %d, readfds %p, writefds %p, exceptfds %p\n"
	    "   epoll_blocked %p, timeout %d\n", nfds, readfds, writefds, exceptfds,
	    w, timeout);
#endif
    if (nfds == 0)
	goto check_rv_timeout;

    w->rset = readfds ? bitmap_wrap(h, readfds, nfds) : 0;
    w->wset = writefds ? bitmap_wrap(h, writefds, nfds) : 0;
    w->eset = exceptfds ? bitmap_wrap(h, exceptfds, nfds) : 0;

    bitmap_extend(e->fds, nfds - 1);
    u64 * regp = bitmap_base(e->fds);
    u64 dummy = 0;
    u64 * rp = readfds ? readfds : &dummy;
    u64 * wp = writefds ? writefds : &dummy;
    u64 * ep = exceptfds ? exceptfds : &dummy;
    int words = pad(nfds, 64) >> 6;
    for (int i = 0; i < words; i++) {
	/* update epollfds based on delta between registered fds and
 	   union of select fds */
	u64 u = *rp | *wp | *ep;
	u64 d = u ^ *regp;

	/* get alloc/free out of the way */
	bitmap_word_foreach_set(d, bit, fd, (i << 6)) {
	    /* either add or remove epollfd */
	    if (*regp & (1ull << bit)) {
#ifdef EPOLL_DEBUG
		rprintf("   - fd %d\n", fd);
#endif
		free_epollfd(e, fd);
	    } else {
#ifdef EPOLL_DEBUG
		rprintf("   + fd %d\n", fd);
#endif
		if (!alloc_epollfd(e, fd, 0, 0)) {
		    rv = -EBADF;
		    goto check_rv_timeout;
		}
	    }
	}

	/* now process all events */
	bitmap_word_foreach_set(u, bit, fd, (i << 6)) {
	    u32 eventmask = 0;
	    u64 mask = 1ull << bit;
	    epollfd f = vector_get(e->events, fd);
	    assert(f);

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
#ifdef EPOLL_DEBUG
	    rprintf("   fd %d eventmask %P\n", fd, eventmask);
#endif
	    if (eventmask != f->eventmask) {
#ifdef EPOLL_DEBUG
		rprintf("      (was %P, ", f->eventmask);
#endif
		if (f->registered) {
#ifdef EPOLL_DEBUG
		    rprintf("replacing)\n");
#endif
		    /* make into zombie; kind of brutal...need removal */
		    free_epollfd(e, fd);
		    f = alloc_epollfd(e, fd, eventmask, 0);
		    assert(f);
		} else {
#ifdef EPOLL_DEBUG
		    rprintf("updating)\n");
#endif
		    f->eventmask = eventmask;
		}
	    }

	    if (!f->registered) {
		f->registered = true;
		fetch_and_add(&f->refcnt, 1);
#ifdef EPOLL_DEBUG
		rprintf("      register epollfd %d, eventmask %P, applying check\n",
			f->fd, f->eventmask);
#endif
		apply(f->f->check, f->eventmask, closure(h, select_notify, f));
	    }
	}

	if (readfds)
	    rp++;
	if (writefds)
	    wp++;
	if (exceptfds)
	    ep++;
	regp++;
    }
    rv = w->retcount;
  check_rv_timeout:
    if (timeout == 0 || rv != 0) {
#ifdef EPOLL_DEBUG
	rprintf("   immediate return; return %d\n", rv);
#endif
	epoll_blocked_release(w);
	return rv;
    }

    if (timeout != infinity) {
	w->timeout = register_timer(timeout, closure(h, epoll_blocked_finish, w, true));
	fetch_and_add(&w->refcnt, 1);
#ifdef EPOLL_DEBUG
	rprintf("   registered timer %p\n", w->timeout);
#endif
    }
#ifdef EPOLL_DEBUG
    rprintf("   sleeping...\n");
#endif
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

void register_poll_syscalls(void **map)
{
    register_syscall(map, SYS_epoll_create, epoll_create);    
    register_syscall(map, SYS_epoll_create1, epoll_create);
    register_syscall(map, SYS_epoll_ctl, epoll_ctl);
    register_syscall(map, SYS_select, select);
    register_syscall(map, SYS_pselect6, pselect);
    register_syscall(map, SYS_epoll_wait,epoll_wait);
    register_syscall(map, SYS_epoll_pwait,epoll_wait); /* sigmask unused right now */
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
