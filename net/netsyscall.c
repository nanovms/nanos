#include <sruntime.h>
#include <unix.h>
#include <net.h>

// the network portion of the syscall interface on top of lwip

typedef struct sock {
    // safety, other issues..multiple waiting threads, which is a mess
    struct tcp_pcb *p;
    thread read_waiting;
    thread accept_waiting;
    struct buffer reader;
    // buffer? offset is in pbuf space
    void *read_dest;
    u64 read_length;
    u64 offset; // into pbuf queue head
    heap h;
    queue incoming;
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
// but needs to be per process really
static sock sockfds[FDS];


static int read_dequeue(sock s)
{
    struct pbuf *p = queue_peek(s->incoming);
    u64 xfer = MIN(s->read_length, p->len);
    runtime_memcpy(s->read_dest, p->payload + s->offset, xfer);
    if (xfer == p->len) {
        dequeue(s->incoming);
        pbuf_free(p);
        s->offset = 0;
    } else {
        s->offset += xfer;
    }
    return xfer;
}


static CLOSURE_1_3(socket_read, int, sock, void *, u64, u64);
static int socket_read(sock s, void *dest, u64 length, u64 offset)
{
    buffer b;
    s->read_dest = dest;
    s->read_length = length;
    // race
    if (queue_peek(s->incoming)){
        return(read_dequeue(s));
    } else {
        s->read_waiting = current;
        runloop();
    }
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
    s->read_waiting = 0;
    s->accept_waiting = 0;    
    s->offset = 0;
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
        enqueue(s->incoming, p);
        
        if (s->read_waiting) {
            s->read_waiting->frame[FRAME_RAX] = read_dequeue(s);
            enqueue(runqueue, s->read_waiting->run);                
            s->read_waiting = 0;
        }
    }
    return ERR_OK;
}

static err_t accept_lower(void *z, struct tcp_pcb *pcb, err_t b)
{
    sock s = z;
   
    if (s->accept_waiting) {    
        int new = allocate_sock(s->accept_waiting->p, pcb);
        tcp_arg(pcb, sockfds[new]);    
        tcp_recv(pcb, input_lower);         
        s->accept_waiting->frame[FRAME_RAX] = new;
        enqueue(runqueue, s->accept_waiting->run);
        s->accept_waiting = 0;
    }
    // else queue
    return ERR_OK;
}


int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    sock s = sockfds[sockfd];
    // 0 success
    // xxx - extract address and port
    return lwip_to_errno(tcp_bind(s->p, IP_ANY_TYPE, 8800));
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
    
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = sockfds[sockfd];
    tcp_arg(s->p, s);       
    tcp_accept(s->p, accept_lower);
    s->accept_waiting = current;
    runloop();
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
    case SYS_setsockopt:
        return 0;
    case SYS_sendto:
    case SYS_sendmsg:
    case SYS_recvmsg:
    case SYS_recvfrom:
    default:
        return -ENOENT;
    }
}
