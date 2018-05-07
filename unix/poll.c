#include <sruntime.h>
#include <unix.h>

typedef struct epollfd {
    file f;
    int events;
    u64 data;
} *epollfd;

typedef struct epoll {
    struct file f;
    heap h;
    boolean fired; // mediate timeout. more than one?
    vector events;
} *epoll;
    
u64 epoll_create1(u64 flags)
{
    int fd;
    epoll e = (epoll)allocate_fd(current->p, sizeof(struct epoll), &fd);
    e->h = current->p->h;
    e->events = allocate_vector(current->p->h, 10);
    return fd;
}

static CLOSURE_2_0(epoll_timeout, void, epoll, thread);
static void epoll_timeout(epoll e, thread t)
{
    if (!e->fired) enqueue(runqueue, t);
}

static CLOSURE_5_0(event, void, epoll, thread, epollfd, struct epoll_event *, int);
static void event(epoll e,
                  thread t,
                  epollfd f,
                  struct epoll_event *events,
                  int maxevents)
{
    rprintf("event signal\n");
    e->fired = 1;
    t->frame[FRAME_RAX] = 1;
    events[0].data = f->data;
    events[0].events = EPOLLIN;    
    enqueue(runqueue, t);
}


int epoll_wait(int epfd, struct epoll_event *events,
               int maxevents, int timeout)
{
    epoll e = (epoll)current->p->files[epfd];
    epollfd f = vector_get(e->events, 0);
    rprintf ("epoll wait: %d\n", timeout);
    enqueue(f->f->notify, closure(current->p->h, event, e, current, f, events, maxevents));
    if (timeout > 0){
        register_timer(milliseconds(timeout), closure(e->h, epoll_timeout, e, current));
        runloop();
    }
    if (timeout == -1)
        runloop();
    // polling needs to work
    return 0;
}

u64 epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    epoll e = (epoll)current->p->files[epfd];
    switch(op) {
    case EPOLL_CTL_ADD:
        {
            rprintf ("epoll add %p %d %p\n", e, fd, event);
            epollfd f = allocate(e->h, sizeof(struct epollfd));
            f->f = current->p->files[fd];
            f->data = event->data;
            vector_push(e->events, f);
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
static void select_timeout(thread f, boolean *dead)
{
    rprintf("select timeout\n");
    f->frame[FRAME_RAX] = 0;
    // xxx need to abort  if something happened
    enqueue(runqueue, f->run);
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
        runloop(); // sleep
    }
    return 0;
}


void register_poll_syscalls(void **map)
{
    register_syscall(map, SYS_epoll_create1, epoll_create1);
    register_syscall(map, SYS_epoll_ctl, epoll_ctl);
    register_syscall(map, SYS_pselect6,pselect);
    register_syscall(map, SYS_epoll_wait,epoll_wait);
}
