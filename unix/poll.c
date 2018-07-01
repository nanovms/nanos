#include <unix_internal.h>

typedef struct epollfd {
    int fd; //debuggin
    file f;
    u64 data;
} *epollfd;

typedef struct epoll *epoll;
typedef struct epoll_blocked {
    epoll e;
    u64 refcnt;
    thread t;
    vector user_events;
} *epoll_blocked;

struct epoll {
    epoll_blocked w;
    struct file f;
    heap h;
    vector events;
};
    
u64 epoll_create(u64 flags)
{
    int fd;
    epoll e = (epoll)allocate_fd(current->p, sizeof(struct epoll), &fd);
    e->h = current->p->h;
    e->events = allocate_vector(current->p->h, 10);
    return fd;
}

static CLOSURE_1_0(epoll_blocked_finish, void, epoll_blocked);
static void epoll_blocked_finish(epoll_blocked w)
{
    if (w->e->w == w) {
        u64 fds = buffer_length(w->user_events)/sizeof(struct epoll_event);
        set_syscall_return(w->t, fds);                            
        w->e->w = 0;
        thread_wakeup(w->t);
    }
    // eventually we should be able to free this thing
    w->refcnt--;
}

// associated with the current blocking function
static CLOSURE_2_0(epoll_wait_notify, void, epoll_blocked, epollfd)
static void epoll_wait_notify(epoll_blocked w, epollfd f)
{
    thread_log(w->t, "notify", f->fd);
    if (w->user_events->length - w->user_events->end) {
        struct epoll_event *e = buffer_ref(w->user_events, w->user_events->end);
        e->data = f->data;
        e->events = EPOLLIN;
        w->user_events->end += sizeof(struct epoll_event);
    }
    epoll_blocked_finish(w);
}

int epoll_wait(int epfd,
               struct epoll_event *events,
               int maxevents,
               int timeout)
{
    epoll e = (epoll)current->p->files[epfd];
    epollfd i;
    
    epoll_blocked w = allocate(e->h, sizeof(struct epoll_blocked));
    // kind of sad to allocate this all for the polling case, but bear with me
    w->user_events = wrap_buffer(e->h, events, maxevents * sizeof(struct epoll_event));
    w->user_events->end = 0;
    w->t = current;
    w->e = e;

    // race
    vector_foreach(e->events, i) 
        apply(i->f->check, closure(current->p->h, epoll_wait_notify, w, i));
    e->w = w;
    
    if (timeout > 0)
        register_timer(milliseconds(timeout), closure(e->h, epoll_blocked_finish, w));
    
    thread_sleep(current);
}

u64 epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    epoll e = (epoll)current->p->files[epfd];
    switch(op) {
    case EPOLL_CTL_ADD:
        {
            epollfd f = allocate(e->h, sizeof(struct epollfd));
            f->f = current->p->files[fd];
            f->fd = fd;
            f->data = event->data;
            vector_push(e->events, f);
            // subscribe while waiting?
            if (e->w)  {
                apply(f->f->check, closure(current->p->h, epoll_wait_notify, e->w, f));
            }
        }
        break;

    case EPOLL_CTL_MOD:
        rprintf ("epoll mod\n");
        break;

    case EPOLL_CTL_DEL:
        rprintf ("epoll del\n");
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
