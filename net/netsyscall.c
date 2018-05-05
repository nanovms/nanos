#include <sruntime.h>
#include <unix.h>
#include <net_internal.h>

typedef u32 socklen_t;

typedef closure_type(pbuf_handler, void, struct pbuf *);
typedef closure_type(pcb_handler, void, struct tcp_pcb *);

// the network portion of the syscall interface on top of lwip

typedef struct sock {
    struct file f;
    heap h;
    struct tcp_pcb *p;
    queue incoming;
} *sock;

static void local_sockaddr_in(struct tcp_pcb *p, struct sockaddr_in *sin)
{
    sin->family = AF_INET;
    sin->port = ntohs(p->local_port);
    sin->address = ntohl(*(u32 *)&p->local_ip);
}

static void remote_sockaddr_in(struct tcp_pcb *p, struct sockaddr_in *sin)
{
    sin->family = AF_INET;
    sin->port = ntohs(p->remote_port);
    sin->address = ntohl(*(u32 *)&p->remote_ip);
}

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

static inline void pbuf_consume(struct pbuf *p, u64 length)
{
    p->len -= length;
    p->payload += length;
}

// racy
static CLOSURE_4_0(read_complete, void, sock, thread, void *, u64);
static void read_complete(sock s, thread t, void *dest, u64 length)
{
    struct pbuf *p = queue_peek(s->incoming);
    u64 xfer = MIN(length, p->len);
    runtime_memcpy(dest, p->payload, xfer);
    pbuf_consume(p, xfer);
    t->frame[FRAME_RAX] = xfer;
    enqueue(runqueue, t);
    if (p->len == 0) {
        dequeue(s->incoming);
        pbuf_free(p);
    }
    // tcp_recved() to move the receive window
}


static CLOSURE_1_3(socket_read, int, sock, void *, u64, u64);
static int socket_read(sock s, void *dest, u64 length, u64 offset)
{
    buffer b;
    struct pbuf *in;
    // dating app
    if ((in = queue_peek(s->incoming))) {
        // we'd.. like to just return, but this collapses the hit case and the asynch
        read_complete(s, current, dest, length);
    } else {
        // it doesn't make sense to enqueue multiple readers, but..
        enqueue(s->f.notify, closure(s->h, read_complete, s, current, dest, length));
    }
    runloop();    
}

static CLOSURE_1_3(socket_write, int, sock, void *, u64, u64);
static int socket_write(sock s, void *source, u64 length, u64 offset)
{
    // error code..backpressure
    tcp_write(s->p, source, length, TCP_WRITE_FLAG_COPY);
    return length;
}

static int allocate_sock(process p, struct tcp_pcb *pcb)
{
    int fd;
    file f = allocate_fd(p, sizeof(struct sock), &fd);
    sock s = (sock)f;    
    f->read =  closure(p->h, socket_read, s);
    f->write =  closure(p->h, socket_write, s);    
    s->h = p->h;
    s->p = pcb;
    s->incoming = allocate_queue(p->h, 32);
    return fd;
}

int socket(int domain, int type, int protocol)
{
    struct tcp_pcb *p;
    if (!(p = tcp_new_ip_type(IPADDR_TYPE_ANY)))
        return -ENOMEM;
    
    int fd = allocate_sock(current->p, p);
    return fd;
}

static err_t input_lower (void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    sock s = z;
    if (p) {
        // dating app
        thunk z;
        rprintf ("posty data input\n");        
        enqueue(s->incoming, p);
        rprintf ("postq data input %p \n", z);
        if ((z = dequeue(s->f.notify))) {
            rprintf ("apply handler %p\n", z);
            apply(z);
        }
    }
    return ERR_OK;
}

int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    sock s = (sock)current->p->files[sockfd];
    buffer b = alloca_wrap_buffer(addr, addrlen);
    // 0 success
    // xxx - extract address and port
    //
    rprintf ("binding: %d\n", ntohs(sin->port));
    return lwip_to_errno(tcp_bind(s->p, IP_ANY_TYPE, ntohs(sin->port)));
}

int connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    sock s = (sock)current->p->files[sockfd];    
    return 0;
}

static err_t accept_from_lwip(void *z, struct tcp_pcb *pcb, err_t b)
{
    rprintf ("accept from lwip %p\n", z);
    sock s = z;
    thunk p;
    rprintf ("posty\n");        
    enqueue(s->incoming, pcb);
    rprintf ("post\n");        
    if ((p = dequeue(s->f.notify))) {
        rprintf("calling notify handler %p\n", p);
        apply(p);
        rprintf("accept result: %p\n", pcb);
    }
    return ERR_OK;
}


int listen(int sockfd, int backlog)
{
    sock s = (sock)current->p->files[sockfd];        
    s->p = tcp_listen_with_backlog(s->p, backlog);
    tcp_arg(s->p, s);
    tcp_accept(s->p, accept_from_lwip);
    return 0;    
}

static CLOSURE_4_0(accept_finish, void, sock, thread, struct sockaddr *, socklen_t *);
static void accept_finish(sock s, thread target, struct sockaddr *addr, socklen_t *addrlen)
{
    struct tcp_pcb * p= dequeue(s->incoming);
    int newfd;
    int fd = allocate_sock(target->p, p);
    rprintf ("accept finish %p\n",target->p->files[fd]);

    tcp_arg(p, target->p->files[fd]);
    tcp_recv(p, input_lower);    
    remote_sockaddr_in(p, (struct sockaddr_in *)addr); 
    *addrlen = sizeof(struct sockaddr_in);
    target->frame[FRAME_RAX] = newfd;
    enqueue(runqueue, target);    
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = (sock)current->p->files[sockfd];
    // ok, this is a reasonable interlock to build, the dating app
    enqueue(s->f.notify, closure(s->h, accept_finish, s, current, addr, addrlen));
    runloop();
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    return(accept(sockfd, addr, addrlen));
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = (sock)current->p->files[sockfd];    
    local_sockaddr_in(s->p, (struct sockaddr_in *)addr);
    return 0;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = (sock)current->p->files[sockfd];
    remote_sockaddr_in(s->p, (struct sockaddr_in *)addr);
    return 0;    
}


void register_net_syscalls(void **map)
{
    register_syscall(map, SYS_socket, socket);
    register_syscall(map, SYS_bind, bind);
    register_syscall(map, SYS_listen, listen);
    register_syscall(map, SYS_accept, accept);
    register_syscall(map, SYS_accept4, accept4);    
    register_syscall(map, SYS_connect, connect);
    register_syscall(map, SYS_setsockopt, syscall_ignore);
    register_syscall(map, SYS_connect, connect);
    register_syscall(map, SYS_getsockname, getsockname);
    register_syscall(map, SYS_getpeername, getpeername);    
}
