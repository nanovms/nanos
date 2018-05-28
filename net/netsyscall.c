#include <unix_internal.h>
#include <lwip.h>


#define AF_INET 10

struct sockaddr_in {
    u16 family;
    u16 port;
    u32 address;
} *sockaddr_in;
    
struct sockaddr {
    u16 family;
} *sockaddr;
    

typedef u32 socklen_t;

typedef closure_type(pbuf_handler, void, struct pbuf *);
typedef closure_type(pcb_handler, void, struct tcp_pcb *);

// the network portion of the syscall interface on top of lwip

typedef struct sock {
    struct file f;
    heap h;
    struct tcp_pcb *p;
    queue incoming;
    queue notify;
    queue waiting; // service waiting before notify, do we really need 2 queues here?
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
    rprintf ("servicing read: %d\n", length);
    struct pbuf *p = queue_peek(s->incoming);
    u64 xfer = MIN(length, p->len);
    runtime_memcpy(dest, p->payload, xfer);
    pbuf_consume(p, xfer);
    t->frame[FRAME_RAX] = xfer;
    enqueue(runqueue, t->run);
    if (p->len == 0) {
        dequeue(s->incoming);
        pbuf_free(p);
    }
    // tcp_recved() to move the receive window
}


static CLOSURE_1_3(socket_read, int, sock, void *, u64, u64);
static int socket_read(sock s, void *dest, u64 length, u64 offset)
{
    rprintf ("socket read\n");
    apply(s->f.check, closure(s->h, read_complete, s, current, dest, length));    
    runloop();    
}

static CLOSURE_1_3(socket_write, int, sock, void *, u64, u64);
static int socket_write(sock s, void *source, u64 length, u64 offset)
{
    rprintf ("socket write\n");
    // error code..backpressure
    tcp_write(s->p, source, length, TCP_WRITE_FLAG_COPY);
    return length;
}

static CLOSURE_1_1(socket_check, void, sock, thunk);
static void socket_check(sock s, thunk t)
{
    rprintf("check %\n", s);
    // safety
    if (queue_length(s->incoming)) {
        apply(t);
    } else {
        enqueue(s->notify, t);
    }
}

static int allocate_sock(process p, struct tcp_pcb *pcb)
{
    int fd;
    file f = allocate_fd(p, sizeof(struct sock), &fd);
    sock s = (sock)f;    
    f->read =  closure(p->h, socket_read, s);
    f->write =  closure(p->h, socket_write, s);
    s->notify = allocate_queue(p->h, 32);
    s->waiting = allocate_queue(p->h, 32);    
    f->check = closure(p->h, socket_check, s);
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
        rprintf("data from lwip %p\n", s);
        // dating app
        thunk z;
        enqueue(s->incoming, p);
        if ((z = dequeue(s->notify))) {
            rprintf("data notify %p\n", s);
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
    sock s = z;
    thunk p;
    enqueue(s->incoming, pcb);
    rprintf("accept from lwip %d %d %d\n", queue_length(s->notify), s->notify->read, s->notify->write);
    if ((p = dequeue(s->waiting))) {
        apply(p);
    }  else {
        if ((p = dequeue(s->notify))) {
            apply(p);
        }
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
    rprintf("likky\n");
    rprintf("accept finish notify %d %d %d\n", queue_length(s->notify), s->notify->read, s->notify->write);
    rprintf("              sockets  %d %d %d\n", queue_length(s->incoming), s->incoming->read, s->incoming->write);        
    struct tcp_pcb * p= dequeue(s->incoming);
    int fd = allocate_sock(target->p, p);
    tcp_arg(p, target->p->files[fd]);
    tcp_recv(p, input_lower);    
    remote_sockaddr_in(p, (struct sockaddr_in *)addr); 
    *addrlen = sizeof(struct sockaddr_in);
    target->frame[FRAME_RAX] = fd;
    enqueue(runqueue, target->run);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = (sock)current->p->files[sockfd];
    rprintf ("userspace accept %d\n", queue_length(s->incoming));

    // ok, this is a reasonable interlock to build, the dating app    
    if (queue_length(s->incoming)) {
        rprintf("lykka\n");
        accept_finish(s, current, addr, addrlen);
    } else {
        rprintf("bubby?\n");
        enqueue(s->waiting, closure(s->h, accept_finish, s, current, addr, addrlen));
        rprintf("babblo?\n");        
    }
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

// tuplify
#define SOCK_NONBLOCK 00004000
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */
#define TCP_THIN_LINEAR_TIMEOUTS 16      /* Use linear timeouts for thin streams*/
#define TCP_THIN_DUPACK         17      /* Fast retrans. after 1 dupack */
#define TCP_USER_TIMEOUT	18	/* How long for loss retry before timeout */
#define TCP_REPAIR		19	/* TCP sock is under repair right now */
#define TCP_REPAIR_QUEUE	20
#define TCP_QUEUE_SEQ		21
#define TCP_REPAIR_OPTIONS	22
#define TCP_FASTOPEN		23	/* Enable FastOpen on listeners */
#define TCP_TIMESTAMP		24
#define TCP_NOTSENT_LOWAT	25	/* limit number of unsent bytes in write queue */
#define TCP_CC_INFO		26	/* Get Congestion Control (optional) info */
#define TCP_SAVE_SYN		27	/* Record SYN headers for new connections */
#define TCP_SAVED_SYN		28	/* Get SYN headers recorded for connection */


int setsockopt(int sockfd,
               int level,
               int optname,
               void *optval,
               socklen_t optlen)
{
    rprintf("sockopt %d %d\n", sockfd, optname);
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
    register_syscall(map, SYS_setsockopt, setsockopt);
    register_syscall(map, SYS_connect, connect);
    register_syscall(map, SYS_getsockname, getsockname);
    register_syscall(map, SYS_getpeername, getpeername);    
}
