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
    // xxx - multiple threads can block on the same e with epoll_wait
    epoll_blocked w;
    struct file f;
    heap h;
    table events;
};
    
u64 epoll_create(u64 flags)
{
    int fd;
    epoll e = (epoll)allocate_fd(current->p, sizeof(struct epoll), &fd);
    e->h = current->p->h;
    e->events = allocate_table(current->p->h, identity_key, pointer_equal);
    return fd;
}

#define user_event_count(__w) (buffer_length(__w->user_events)/sizeof(struct epoll_event))

static CLOSURE_1_0(epoll_blocked_finish, void, epoll_blocked);
static void epoll_blocked_finish(epoll_blocked w)
{
    if (w->sleeping) {
        set_syscall_return(w->t, user_event_count(w));
        w->sleeping = false;
        thread_wakeup(w->t);
    }
    w->refcnt--;
    // eventually we should be able to free this thing..now actually?
}

// associated with the current blocking function
static CLOSURE_1_0(epoll_wait_notify, void, epollfd)
static void epoll_wait_notify(epollfd f)
{
    f->registered = false;
    epoll_blocked b = f->e->w; 
    // strided vectors?
    if (b && (b->user_events->length - b->user_events->end)) {
        struct epoll_event *e = buffer_ref(b->user_events, b->user_events->end);
        e->data = f->data;
        e->events = EPOLLIN;
        b->user_events->end += sizeof(struct epoll_event);
        epoll_blocked_finish(b);
    }
}

int epoll_wait(int epfd,
               struct epoll_event *events,
               int maxevents,
               int timeout)
{
    epoll e = resolve_fd(current->p, epfd);
    epollfd i;
    
    epoll_blocked w = allocate(e->h, sizeof(struct epoll_blocked));

    w->user_events = wrap_buffer(e->h, events, maxevents * sizeof(struct epoll_event));
    w->user_events->end = 0;
    w->t = current;
    w->e = e;
    w->sleeping = false;
    e->w = w;
    
    table_foreach(e->events, k, i) {
        epollfd f = (epollfd)i;
        if (!f->registered) {
            f->registered = true;
            apply(f->f->check, closure(current->p->h, epoll_wait_notify, f));
        }
    }
    int eventcount = w->user_events->end/sizeof(struct epoll_event);
    if (w->user_events->end) {
        e->w = 0;        
        return eventcount;
    }
    
    if (timeout > 0)
        register_timer(milliseconds(timeout), closure(e->h, epoll_blocked_finish, w));

    w->sleeping = true;    
    thread_sleep(current);
}

u64 epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    value ekey = pointer_from_u64((u64)fd);
    epoll e = resolve_fd(current->p, epfd);    
    switch(op) {
    case EPOLL_CTL_ADD:
        {
            // EPOLLET means edge instead of level
            epollfd f = allocate(e->h, sizeof(struct epollfd));
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
        table_set(e->events, ekey, 0);
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
    if (timeout == 0) {
        rprintf("select poll\n");
    } else {
        register_timer(time_from_timespec(timeout), closure(current->p->h, select_timeout, current, 0));
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
