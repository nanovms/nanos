#include <unix_internal.h>

//#define EPOLL_DEBUG

typedef struct epoll *epoll;

typedef struct epollfd {
    int fd; //debugging only
    file f;
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
    timer timeout;
    buffer user_events;
    struct list blocked_list;
};

struct epoll {
    struct file f;
    // xxx - multiple threads can block on the same e with epoll_wait
    struct list blocked_head;
    table events;
};
    
static CLOSURE_1_0(epoll_close, int, epoll);
static int epoll_close(epoll e)
{
    kernel k = current->p->k;
    // XXX need to dealloc epollfd and epoll_blocked structs too
    deallocate(k->epoll_cache, e, sizeof(struct epoll));
}

u64 epoll_create(u64 flags)
{
    kernel k = current->p->k;
    heap h = k->general;
    file f = allocate(k->epoll_cache, sizeof(struct epoll));
    if (f == INVALID_ADDRESS)
	return -ENOMEM;
    u64 fd = allocate_fd(current->p, f);
    if (fd == INVALID_PHYSICAL) {
	deallocate(k->epoll_cache, f, sizeof(struct epoll));
	return -EMFILE;
    }
    epoll e = (epoll)f;
    f->close = closure(h, epoll_close, e);
    list_init(&e->blocked_head);
    e->events = allocate_table(h, identity_key, pointer_equal);
    return fd;
}

#define user_event_count(__w) (buffer_length(__w->user_events)/sizeof(struct epoll_event))

static void epoll_blocked_release(epoll_blocked w)
{
    epoll e = w->e;
    kernel k = current->p->k;
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
	deallocate(k->epoll_blocked_cache, w, sizeof(struct epoll_blocked));
#ifdef EPOLL_DEBUG
	rprintf(", deallocated");
#endif
    }
#ifdef EPOLL_DEBUG
    rprintf("\n");
#endif
}

static CLOSURE_1_0(epoll_blocked_finish, void, epoll_blocked);
static void epoll_blocked_finish(epoll_blocked w)
{
#ifdef EPOLL_DEBUG
    rprintf("epoll_blocked_finish: w %p, refcnt %d", w, w->refcnt);
    if (w->sleeping)
	rprintf(", sleeping");
    if (w->timeout)
	rprintf(", timeout %p\n", w->timeout);
#endif
    kernel k = current->p->k;
    heap h = k->general;

    /* If we're not sleeping, we're in the middle of a (to be
       non-blocking) epoll_wait(), so do nothing here and allow other
       notifications, if any, to be applied. */
    if (w->sleeping) {
#ifdef EPOLL_DEBUG
	rprintf("   syscall return %d\n", user_event_count(w));
#endif
        set_syscall_return(w->t, user_event_count(w));
        w->sleeping = false;
        thread_wakeup(w->t);
	unwrap_buffer(h, w->user_events);
	w->user_events = 0;
	if (w->timeout) {
	    /* We'll let the timeout run until expiry until we can be sure
	       that we have a race-free way to disable the timer if waking
	       on an event. Thus bump the refcnt to make sure this
	       epoll_blocked is still around after syscall return.

	       This will have to be revisited, for we'll accumulate a
	       bunch of zombie epoll_blocked and timer objects until they
	       start timing out.
	    */
	    fetch_and_add(&w->refcnt, 1);
	}
	epoll_blocked_release(w);
    } else if (w->timeout) {
	/* expiry after syscall return */
	assert(w->refcnt == 1);
	epoll_blocked_release(w);
    }
}

static void epollfd_release(epollfd f)
{
    kernel k = current->p->k;
#ifdef EPOLL_DEBUG
    rprintf("epollfd_release: f->fd %d, refcnt %d\n", f->fd, f->refcnt);
#endif
    assert(f->refcnt > 0);
    if (fetch_and_add(&f->refcnt, -1) == 0)
	deallocate(k->epollfd_cache, f, sizeof(struct epollfd));
}

// associated with the current blocking function
static CLOSURE_2_0(epoll_wait_notify, void, epollfd, u32);
static void epoll_wait_notify(epollfd f, u32 events)
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
	}
	epoll_blocked_finish(w);
    }
    epollfd_release(f);
}

int epoll_wait(int epfd,
               struct epoll_event *events,
               int maxevents,
               int timeout)
{
    kernel k = current->p->k;
    heap h = k->general;
    epoll e = resolve_fd(current->p, epfd);
    epollfd i;
    
    epoll_blocked w = allocate(k->epoll_blocked_cache, sizeof(struct epoll_blocked));
#ifdef EPOLL_DEBUG
    rprintf("epoll_wait: epoll fd %d, new blocked %p, timeout %d\n", epfd, w, timeout);
#endif
    w->refcnt = 1;
    w->user_events = wrap_buffer(h, events, maxevents * sizeof(struct epoll_event));
    w->user_events->end = 0;
    w->t = current;
    w->e = e;
    w->sleeping = false;
    w->timeout = 0;
    list_insert_after(&e->blocked_head, &w->blocked_list); /* push */

    table_foreach(e->events, ekey, i) {
        epollfd f = (epollfd)i;
        if (!f->registered) {
            f->registered = true;
	    fetch_and_add(&f->refcnt, 1);
#ifdef EPOLL_DEBUG
	    rprintf("   register epollfd %d, applying check\n", f->fd);
#endif
            apply(f->f->check,
		  closure(h, epoll_wait_notify, f, EPOLLIN),
		  closure(h, epoll_wait_notify, f, EPOLLHUP));
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
	w->timeout = register_timer(milliseconds(timeout), closure(h, epoll_blocked_finish, w));
#ifdef EPOLL_DEBUG
	rprintf("   registered timer %p\n", w->timeout);
#endif
    }

    rprintf("   sleeping...\n");
    w->sleeping = true;
    thread_sleep(current);
}

u64 epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    kernel k = current->p->k;
    value ekey = pointer_from_u64((u64)fd);
    epoll e = resolve_fd(current->p, epfd);    
#ifdef EPOLL_DEBUG
    rprintf("epoll_ctl: epoll fd %d, op %d, fd %d\n", epfd, op, fd);
#endif
    switch(op) {
    case EPOLL_CTL_ADD:
        {
            // EPOLLET means edge instead of level
            epollfd f = allocate(k->epollfd_cache, sizeof(struct epollfd));
            f->f = resolve_fd(current->p, fd);
            f->fd = fd;
            f->e = e;
            f->data = event->data;
	    f->refcnt = 1;
            f->registered = false;
	    f->zombie = false;
            table_set(e->events, ekey, f);
#ifdef EPOLL_DEBUG
	    rprintf("   added %d, epollfd %p\n", fd, f);
#endif
        }
        break;

    case EPOLL_CTL_MOD:
        rprintf ("epoll mod\n");
        break;

    // what does this mean to a currently blocked epoll?
    case EPOLL_CTL_DEL:
        {
	    epollfd f = table_find(e->events, ekey);
	    if (!f) {
		msg_err("epollfd not found for fd %d\n", fd);
		return -EBADF;
	    }
	    table_set(e->events, ekey, 0);
	    assert(f->refcnt > 0);
	    f->zombie = true;
	    epollfd_release(f);
#ifdef EPOLL_DEBUG
	    rprintf("   removed %d, epollfd %p, refcnt %d\n", fd, f, f->refcnt);
#endif
	}
    }
    return 0;
}


static CLOSURE_2_0(select_timeout, void, thread, boolean *);
static void select_timeout(thread t, boolean *dead)
{
    set_syscall_return(t, 0);
    thread_wakeup(t);
}

int pselect(int nfds,
            u64 *readfds, u64 *writefds, u64 *exceptfds,
            struct timespec *timeout,
            u64 *sigmask)
{
    kernel k = current->p->k;

    rprintf("select %p %p %p\n", readfds?*readfds:0, writefds?*writefds:0, exceptfds?*exceptfds:0);
    if (timeout == 0) {
        rprintf("select poll\n");
    } else {
        register_timer(time_from_timespec(timeout), closure(k->general, select_timeout, current, 0));
        thread_sleep(current);
    }
    return 0;
}


void register_poll_syscalls(void **map)
{
    register_syscall(map, SYS_epoll_create, epoll_create);    
    register_syscall(map, SYS_epoll_create1, epoll_create);
    register_syscall(map, SYS_epoll_ctl, epoll_ctl);
    register_syscall(map, SYS_pselect6,pselect);
    register_syscall(map, SYS_epoll_wait,epoll_wait);
}

boolean poll_init(kernel k)
{
    k->epoll_cache = allocate_objcache(k->general, k->backed, sizeof(struct epoll));
    if (k->epoll_cache == INVALID_ADDRESS)
	return false;
    k->epollfd_cache = allocate_objcache(k->general, k->backed, sizeof(struct epollfd));
    if (k->epoll_blocked_cache == INVALID_ADDRESS)
	return false;
    k->epoll_blocked_cache = allocate_objcache(k->general, k->backed, sizeof(struct epoll_blocked));
    if (k->epoll_blocked_cache == INVALID_ADDRESS)
	return false;

    return true;
}
