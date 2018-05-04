#include <sruntime.h>
#include <unix.h>


u64 epoll_create1(u64 flags)
{
    return 0;
}

u64 epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    switch(op) {
    case EPOLL_CTL_ADD:
        rprintf ("add\n");
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
