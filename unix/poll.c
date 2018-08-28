#include <unix_internal.h>

typedef struct epoll *epoll;

typedef struct epollfd {
    int fd; //debugging only
    file f;
    u64 data; // may be multiple versions of data?
    epoll e;
    boolean registered;
    // xxx bind fd to first blocked that cares
} *epollfd;

typedef struct epoll_blocked *epoll_blocked;

struct epoll_blocked {
    epoll e;
    u64 refcnt;
    thread t;
    boolean sleeping;
    vector user_events;
    epoll_blocked next;
};

struct epoll {
    struct file f;
    // xxx - multiple threads can block on the same e with epoll_wait
    epoll_blocked w;
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
    e->events = allocate_table(h, identity_key, pointer_equal);
    return fd;
}

#define user_event_count(__w) (buffer_length(__w->user_events)/sizeof(struct epoll_event))

static CLOSURE_1_0(epoll_blocked_finish, void, epoll_blocked);
static void epoll_blocked_finish(epoll_blocked w)
{
    kernel k = current->p->k;
    if (w->sleeping) {
        set_syscall_return(w->t, user_event_count(w));
        w->sleeping = false;
        thread_wakeup(w->t);
    }
    if (--w->refcnt == 0)
	deallocate(k->epoll_blocked_cache, w, sizeof(struct epoll_blocked));
}

// associated with the current blocking function
static CLOSURE_2_0(epoll_wait_notify, void, epollfd, u32);
static void epoll_wait_notify(epollfd f, u32 events)
{
    f->registered = false;
    epoll_blocked b = f->e->w; 
    // strided vectors?
    if (b && (b->user_events->length - b->user_events->end)) {
        struct epoll_event *e = buffer_ref(b->user_events, b->user_events->end);
        e->data = f->data;
        e->events = events;
        b->user_events->end += sizeof(struct epoll_event);
        epoll_blocked_finish(b);
    }
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

    w->refcnt = 1;
    w->user_events = wrap_buffer(h, events, maxevents * sizeof(struct epoll_event));
    w->user_events->end = 0;
    w->t = current;
    w->e = e;
    w->sleeping = false;
    e->w = w;
    
    table_foreach(e->events, k, i) {
        epollfd f = (epollfd)i;
        if (!f->registered) {
            f->registered = true;
            apply(f->f->check,
		  closure(h, epoll_wait_notify, f, EPOLLIN),
		  closure(h, epoll_wait_notify, f, EPOLLHUP));
        }
    }
    int eventcount = w->user_events->end/sizeof(struct epoll_event);
    if (w->user_events->end) {
        e->w = 0;        
        return eventcount;
    }
    
    if (timeout > 0)
        register_timer(milliseconds(timeout), closure(h, epoll_blocked_finish, w));

    w->sleeping = true;    
    thread_sleep(current);
}

u64 epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    kernel k = current->p->k;
    value ekey = pointer_from_u64((u64)fd);
    epoll e = resolve_fd(current->p, epfd);    
    switch(op) {
    case EPOLL_CTL_ADD:
        {
            // EPOLLET means edge instead of level
            epollfd f = allocate(k->epollfd_cache, sizeof(struct epollfd));
            f->f = resolve_fd(current->p, fd);
            f->fd = fd;
            f->e = e;
            f->data = event->data;
            f->registered = 0;
            table_set(e->events, ekey, f);
        }
        break;

    case EPOLL_CTL_MOD:
        rprintf ("epoll mod\n");
        break;

    // what does this mean to a currently blocked epoll?
    case EPOLL_CTL_DEL:
        {
	    epollfd f = table_find(e->events, ekey);
	    if (f)
		deallocate(k->epollfd_cache, f, sizeof(struct epollfd));
	    else
		msg_err("epollfd not found for fd %d\n", fd);
	    table_set(e->events, ekey, 0);
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
