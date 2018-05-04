#include <sruntime.h>
#include <unix.h>
#include <net_internal.h>

typedef u32 socklen_t;

typedef closure_type(pbuf_handler, void, struct pbuf *);
typedef closure_type(pcb_handler, void, struct tcp_pcb *);

// the network portion of the syscall interface on top of lwip

typedef struct sock {
    heap h;
    struct tcp_pcb *p;
    queue incoming;
    queue waiting;    
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


// try keeping an overlay map instead of blowing out the fd closures, or having a type, or..
// but needs to be per process really
static sock sockfds[FDS];

static inline void pbuf_consume(struct pbuf *p, u64 length)
{
    p->len -= length;
    p->payload += length;
}

static CLOSURE_4_1(read_complete, void, sock, thread, void *, u64, struct pbuf *);
static void read_complete(sock s, thread t, void *dest, u64 length, struct pbuf *in)
{
    struct pbuf *p = queue_peek(s->incoming);
    u64 xfer = MIN(length, p->len);
    runtime_memcpy(dest, p->payload, xfer);
    pbuf_consume(in, xfer);
    t->frame[FRAME_RAX] = xfer;
    enqueue(runqueue, t);
}


static CLOSURE_1_3(socket_read, int, sock, void *, u64, u64);
static int socket_read(sock s, void *dest, u64 length, u64 offset)
{
    buffer b;
    struct pbuf *in;
    // dating app
    if ((in = queue_peek(s->incoming))) {
        read_complete(s, current, dest, length, in);
        if (in->len == 0) {
            dequeue(s->incoming);
            pbuf_free(in);
        }
        // we'd.. like to just return, but this collapses the hit case and the asynch
    } else {
        // it doesn't make sense to enqueue multiple readers, but..
        enqueue(s->waiting, closure(s->h, read_complete, s, current, dest, length));
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
    sock s = allocate(current->p->h, sizeof(struct sock));
    s->h = p->h;
    int fd = allocate_fd(p,
                         closure(s->h, socket_read, s),
                         closure(s->h, socket_write, s));
    s->p = pcb;
    s->incoming = allocate_queue(p->h, 32);
    s->waiting = allocate_queue(p->h, 32);    
    sockfds[fd] = s;
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
        pbuf_handler z;
        if ((z = dequeue(s->waiting))) {
            apply(z, p);
            if (p->len == 0) {
                pbuf_free(p);
                return ERR_OK;
            }
        }
        enqueue(s->incoming, p);
    }
    return ERR_OK;
}



int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    sock s = sockfds[sockfd];
    buffer b = alloca_wrap_buffer(addr, addrlen);
    // 0 success
    // xxx - extract address and port
    //

    return lwip_to_errno(tcp_bind(s->p, IP_ANY_TYPE, ntohl(sin->port)));
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
    s->p = tcp_listen(s->p);
    return 0;    
}


static CLOSURE_4_1(accept_finish, void, sock, thread, struct sockaddr *, socklen_t *, struct tcp_pcb *);
static void accept_finish(sock s, thread target, struct sockaddr *addr, socklen_t *addrlen, struct tcp_pcb *p)
{
    int new = allocate_sock(target->p, p);
    tcp_arg(p, sockfds[new]);    
    tcp_recv(p, input_lower);    
    remote_sockaddr_in(p, (struct sockaddr_in *)addr); 
    *addrlen = sizeof(struct sockaddr_in);
    target->frame[FRAME_RAX] = allocate_sock(current->p, p);        
    enqueue(runqueue, target);    
}

static err_t accept_lower(void *z, struct tcp_pcb *pcb, err_t b)
{
    sock s = z;
    pcb_handler p;
   
    if ((p = dequeue(s->waiting))) {
        apply(p, pcb);
        rprintf("accept result: %p\n", pcb);
    } else {
        enqueue(s->incoming, pcb);
    }
    return ERR_OK;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = sockfds[sockfd];
    // ok, this is a reasonable interlock to build, the dating app
    enqueue(s->waiting, closure(s->h, accept_finish, s, current, addr, addrlen));
    runloop();
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    return(accept(sockfd, addr, addrlen));
}

    
// sendmsg, send, recv, etc..

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
}
