#include <sruntime.h>
#include <unix.h>

typedef struct epoll {
} *epoll;
    
u64 epoll_create1(u64 flags)
{
    return 0;
}

static CLOSURE_1_0(event, void, file);
static void event(file f)
{
    rprintf("signal\n");
}

u64 epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    file f = current->p->files[fd];
    switch(op) {
    case EPOLL_CTL_ADD:
        enqueue(f->notify, closure(current->p->h, event, f));
        rprintf ("add %d\n", fd);
        break;

    case EPOLL_CTL_MOD:
        rprintf ("mod\n");
        break;

    case EPOLL_CTL_DEL:
        rprintf ("del\n");
    }
    return 0;
}



void register_poll_syscalls(void **map)
{
    register_syscall(map, SYS_epoll_create1, epoll_create1);
    register_syscall(map, SYS_epoll_ctl, epoll_ctl);    
}
