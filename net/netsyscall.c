#include <sruntime.h>
#include <unix.h>
#include <net.h>

// the network portion of the syscall interface on top of lwip

typedef struct sock {
    // or..
    struct tcp_pcb *pcb;
} *sock;

static inline s64 lwip_to_errno(s8 err)
{
    switch (err) {
    case ERR_OK: return 0;
    case ERR_MEM: return -ENOMEM;
    case ERR_BUF: return -ENOMEM;
    case ERR_TIMEOUT: return -ENOMEM;
    case ERR_RTE: return -ENOMEM;
    case ERR_INPROGRESS: return -EAGAIN;
    case ERR_VAL: return -EINVAL;
    case ERR_WOULDBLOCK: return -EAGAIN;
    case ERR_USE: return -EBUSY;
    case ERR_ALREADY: return -EBUSY;
    case ERR_ISCONN: return -EINVAL;
    case ERR_CONN: return -EINVAL;
    case ERR_IF: return -EINVAL;
    case ERR_ABRT: return -EINVAL;
    case ERR_RST: return -EINVAL;
    case ERR_CLSD: return -EPIPE;
    case ERR_ARG: return -EINVAL;
    }
}

// try keeping an overlay map instead of blowing out the fd closures, or having a type, or..
static sock sockfds[FDS];
    
int socket(int domain, int type, int protocol)
{
    sock s = allocate(current->p->h, sizeof(struct sock));
    if (!(s->pcb = tcp_new_ip_type(IPADDR_TYPE_ANY)))
        return -ENOMEM;
    
    tcp_setprio(s->pcb, HTTPD_TCP_PRIO);
    /* set SOF_REUSEADDR here to explicitly bind httpd to multiple interfaces */

}

int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    sock s = sockfds[sockfd];
    // 0 success
    return lwip_to_errno(tcp_bind(s->pcb, IP_ANY_TYPE, HTTPD_SERVER_PORT));
}

int connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    sock s = sockfds[sockfd];
    return 0;
}

int listen(int sockfd, int backlog)
{
    sock s = sockfds[sockfd];
    // ??
    s->pcb = tcp_listen(s->pcb);
    return 0;    
}

static err_t accept_callback(void *arg, struct tcp_pcb *pcb, err_t err)
{
    sock s = arg;
    // child - allocate a new socket and an fd for it
}
    
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = sockfds[sockfd];;
    tcp_accept(s->pcb, accept_callback);
    return 0;    
}

// sendmsg, send, recv, etc..


int net_syscall(int f, u64 *a)
{
    switch(f) {
    case SYS_socket:
        return socket(a[0], a[1], a[2]);
    case SYS_bind:
        return bind(a[0], pointer_from_u64(a[1]), a[2]);
    case SYS_listen:
        return listen(a[0], a[1]);
    case SYS_accept:
        return accept(a[0], pointer_from_u64(a[1]), pointer_from_u64(a[2]));
    case SYS_connect:
        return(bind(a[0], pointer_from_u64(a[1]), a[2]));
    case SYS_sendto:
    case SYS_sendmsg:
    case SYS_recvmsg:
    case SYS_recvfrom:
    default:
        return -ENOENT;
    }
}
