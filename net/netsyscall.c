#include <unix_internal.h>
#include <net_system_structs.h>
#include <lwip.h>

enum socket_state {
  SOCK_UNDEFINED =0,
  SOCK_CREATED=1,
  SOCK_IN_CONNECTION=2,
  SOCK_OPEN=3,
  SOCK_CLOSED=4
};

typedef closure_type(pbuf_handler, void, struct pbuf *);
typedef closure_type(pcb_handler, void, struct tcp_pcb *);

typedef struct sock {
    struct file f;
    process p;
    heap h;
    struct tcp_pcb *lw;
    queue incoming;
    queue notify;
    queue waiting; // service waiting before notify, do we really need 2 queues here?
    // the notion is that 'waiters' should take priority    
    int fd;
    enum socket_state state; // half open?
    status s;
} *sock;

static void wakeup(sock s)
{
    thunk n;
    status_handler fstatus;

    // return status if not handled so someone else can try?
    // shouldnt a close event wake up everyone?
    if ((fstatus = dequeue(s->waiting))) {
        apply(fstatus, NULL);
    }  else {
        if ((n = dequeue(s->notify))) {
            apply(n);
        }
    }
}

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

static inline sysreturn lwip_errno(s8 err)
{
    u64 unix_errno;

    // xxx - go over these again, its not entirely clear what
    // the intent is inside lwip
    switch (err) {
    case ERR_OK: return 0;
    case ERR_MEM: unix_errno =  ENOMEM; break;
    case ERR_BUF: unix_errno =  ENOBUFS; break;
    case ERR_TIMEOUT: unix_errno =  EBUSY; break;
    case ERR_RTE: unix_errno = EHOSTUNREACH; break;
    case ERR_INPROGRESS: unix_errno = EAGAIN; break;
    case ERR_VAL: unix_errno = EINVAL; break;
    case ERR_WOULDBLOCK: unix_errno = EAGAIN; break;
    case ERR_USE: unix_errno = EADDRINUSE; break;
    case ERR_ALREADY: unix_errno = EISCONN; break;
    case ERR_ISCONN: unix_errno = EISCONN; break;
    case ERR_CONN: unix_errno = ECONNREFUSED; break;
    case ERR_IF: unix_errno = EINVAL; break;
    case ERR_ABRT: unix_errno = EINVAL; break;
    case ERR_RST: unix_errno = ECONNRESET; break;
    case ERR_CLSD: unix_errno = EPIPE; break;
    case ERR_ARG: unix_errno = EINVAL; break;
    }
    return unix_errno;
    // lwip error string? caller?
    //    return timm("lwip_error", value_from_u64(h, err), "errno", value_from_u64(h, unix_errno));
}

static inline void pbuf_consume(struct pbuf *p, u64 length)
{
    p->len -= length;
    p->payload += length;
}

// racy
static CLOSURE_5_0(read_complete, void, sock, thread, void *, u64, boolean);
static void read_complete(sock s, thread t, void *dest, u64 length, boolean sleeping)
{
    if (s->state != SOCK_OPEN)
        s->s = timmf("errno", "%d", ENOTCONN);
    if (s->s) {
        set_syscall_error(t, errno_from_status(s->s));
        thread_wakeup(t);
        return;
    }

    // could copy in multiple pbufs just to save them from coming back tomorrow
    struct pbuf *p = queue_peek(s->incoming);
    u64 xfer = MIN(length, p->len);
    runtime_memcpy(dest, p->payload, xfer);
    pbuf_consume(p, xfer);
    set_syscall_return(t, xfer);    
    if (p->len == 0) {
        dequeue(s->incoming);
        pbuf_free(p);
    }
    tcp_recved(s->lw, xfer);
    if (sleeping) thread_wakeup(t);
}

static CLOSURE_2_0(read_hup, void, sock, thread);
static void read_hup(sock s, thread t)
{
    set_syscall_return(t, 0);
    enqueue(runqueue, t->run);
}

static CLOSURE_1_3(socket_read, sysreturn, sock, void *, u64, u64);
static sysreturn socket_read(sock s, void *dest, u64 length, u64 offset)
{
    if (SOCK_OPEN != s->state) 
        return set_syscall_error(current, ENOTCONN);

    // xxx - there is a fat race here between checking queue length and posting on the waiting queue
    if (queue_length(s->incoming)) {
        read_complete(s, current, dest, length, false);
        return sysreturn_value(current);        
    } else {
        // should be an atomic operation
        enqueue(s->waiting, closure(s->h, read_complete, s, current, dest, length, true));
        thread_sleep(current);
    }
}

static CLOSURE_1_3(socket_write, sysreturn, sock, void *, u64, u64);
static sysreturn socket_write(sock s, void *source, u64 length, u64 offset)
{
    err_t err;
    if (SOCK_OPEN != s->state) 		/* XXX maybe defer to lwip for connect state */
        return set_syscall_error(current, EPIPE);
    // blocking writes is a pretty important feature 
    err = tcp_write(s->lw, source, length, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
        return set_syscall_error(current, lwip_errno(err));
    err = tcp_output(s->lw);
    if (err != ERR_OK)
        return set_syscall_error(current, lwip_errno(err));        
    return length;
}

static CLOSURE_1_2(socket_check, void, sock, thunk, thunk);
static void socket_check(sock s, thunk t_in, thunk t_hup)
{
    // thread safety
    if (queue_length(s->incoming)) {
        apply(t_in);
    } else {
        if (SOCK_OPEN == s->state) {
	    enqueue(s->notify, t_in);
	} else {
	    apply(t_hup);
	}
    }
}

#define SOCK_QUEUE_LEN 32

static CLOSURE_1_0(socket_close, sysreturn, sock);
static sysreturn socket_close(sock s)
{
    heap h = heap_general(get_kernel_heaps());
    if (s->state == SOCK_OPEN) {
        tcp_close(s->lw);
    }
    // xxx - we should really be cleaning this up, but tcp_close apparently
    // doesnt really stop everything synchronously, causing weird things to
    // happen when the stale references to these objects get used. investigate.
    //    deallocate_queue(s->notify, SOCK_QUEUE_LEN);
    //    deallocate_queue(s->waiting, SOCK_QUEUE_LEN);
    //    deallocate_queue(s->incoming, SOCK_QUEUE_LEN);
    //    unix_cache_free(get_unix_heaps(), socket, s);
}

static int allocate_sock(process p, struct tcp_pcb *pcb)
{
    file f = unix_cache_alloc(get_unix_heaps(), socket);
    if (f == INVALID_ADDRESS) {
	msg_err("failed to allocate struct sock\n");
	return -ENOMEM;
    }
    int fd = allocate_fd(p, f);
    if (fd == INVALID_PHYSICAL) {
	unix_cache_free(get_unix_heaps(), socket, f);
	return -EMFILE;
    }
    sock s = (sock)f;
    heap h = heap_general(get_kernel_heaps());
    f->read = closure(h, socket_read, s);
    f->write = closure(h, socket_write, s);
    f->close = closure(h, socket_close, s);
    f->check = closure(h, socket_check, s);
    
    s->notify = allocate_queue(h, SOCK_QUEUE_LEN);
    s->waiting = allocate_queue(h, SOCK_QUEUE_LEN);

    s->s = STATUS_OK;
    s->p = p;
    s->h = h;
    s->lw = pcb;
    s->fd = fd;
    // defer to lwip here? ideally, but its racy - it looks like
    // pcb->state as defined in include/lwip/tcp.h is the right
    // connection state variable
    s->state = SOCK_CREATED;
    s->incoming = allocate_queue(h, SOCK_QUEUE_LEN);
    return fd;
}

sysreturn socket(int domain, int type, int protocol)
{
    struct tcp_pcb *p;
    if (!(p = tcp_new_ip_type(IPADDR_TYPE_ANY)))
        return -ENOMEM;
    
    int fd = allocate_sock(current->p, p);
    return fd;
}

static err_t connection_data_from_lwip (void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    sock s = z;

    if (err) {
        s->s = timmf("lwip error", "%d", err);
    }
    
    if (p) {
        enqueue(s->incoming, p);
    } else {
        s->state = SOCK_CLOSED;
    }
    wakeup(s);
    return ERR_OK;
}

sysreturn bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    sock s = resolve_fd(current->p, sockfd);
    buffer b = alloca_wrap_buffer(addr, addrlen);
    // 0 success
    // xxx - extract address and port
    //
    err_t err = tcp_bind(s->lw, IP_ANY_TYPE, ntohs(sin->port));
    if(ERR_OK == err){
      s->state = SOCK_OPEN;
    }
    return set_syscall_error(current, lwip_errno(err));
}

void error_handler_tcp(void* arg, err_t err)
{
    rprintf ("error handler tcp\n");
    sock s = (sock)(arg);
    status_handler sp = NULL;
    // xxx - why would this ever be zero?
    if(!s) return;
    if(ERR_OK != err)
        s->state = SOCK_UNDEFINED;
    if ((sp = dequeue(s->waiting))) {
        // wrap
       apply(sp, timm("errno", value_from_u64(s->h, lwip_errno(err))));        
    }
}

static CLOSURE_1_1(set_completed_state,void,thread,u64*);
static void set_completed_state( thread th, u64 *code)
{
  set_syscall_return(th, *code);
  thread_wakeup(th);
}

static err_t connect_complete(void* arg, struct tcp_pcb* tpcb, err_t err)
{
    rprintf("connect complete\n");
    status_handler sp = NULL;
    sock s = (sock)(arg);
    s->state = SOCK_OPEN;
    if ((sp = dequeue(s->waiting))) 
        apply(sp, timm("errno", value_from_u64(s->h, lwip_errno(err))));
}

static sysreturn connect_tcp(sock s, const ip_addr_t* address, unsigned short port)
{
    enqueue(s->waiting, closure(s->h, set_completed_state, current));
    tcp_arg(s->lw, s);
    tcp_err(s->lw, error_handler_tcp);
    rprintf ("connect %p %p\n", *address, port);
    s->state = SOCK_IN_CONNECTION;
    int err = tcp_connect(s->lw, address, port, connect_complete);
    if (ERR_OK != err) 
        return set_syscall_error(current, lwip_errno(err));

    if (s->f.blocking) 
        thread_sleep(current);
    return set_syscall_error(current, EINPROGRESS);
}

sysreturn connect(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    struct sockaddr_in* sin = (struct sockaddr_in*)addr;
    if (!s) {
        return -EINVAL;
    }

    if (SOCK_IN_CONNECTION == s->state)
    {
        // which code?
        return -EISCONN;
    } else if (SOCK_OPEN == s->state)
    {
        return -EISCONN;
    }

    enum protocol_type type = SOCK_STREAM;
    switch (type) {
    case SOCK_DGRAM: {
        // TODO: Uncomment when UDP socket support will have been added
        // err = udp_connect(s->lw, (const ip_addr_t*)&sin->address, sin->port);
    } break;
    case SOCK_RAW: {
        // TODO: Uncomment when raw socket support will have been added
        // err = raw_connect(s->lw, (const ip_addr_t*)&sin->address );
    } break;
    case SOCK_STREAM: {
        rprintf("sinad: %p\n", *(u32 *)&sin->address);
        return connect_tcp(s, (const ip_addr_t*)&sin->address, sin->port);
    } break;
    default:
        return -EINVAL;
    }
}

static void lwip_conn_err(void* z, err_t b) {
    sock s = z;
    s->state = SOCK_UNDEFINED;
}

static err_t accept_from_lwip(void *z, struct tcp_pcb *lw, err_t err)
{
    sock s = z;
    thunk p;
    status_handler sp;
    int fd = allocate_sock(s->p, lw);
    if (fd < 0)
	return ERR_MEM;

    sock sn = vector_get(s->p->files, fd);
    sn->state = SOCK_OPEN;
    sn->fd = fd;
    tcp_arg(lw, sn);
    tcp_recv(lw, connection_data_from_lwip);
    tcp_err(lw, lwip_conn_err);
    enqueue(s->incoming, sn);

    //  using an empty queue plus notify as the error signal
    // isnt really the most robust
    if ((sp = dequeue(s->waiting))) {
        apply(sp, timm("errno", value_from_u64(s->h, lwip_errno(err))));                
    }  else {
        if ((p = dequeue(s->notify))) {
            apply(p);
        }
    }
    return ERR_OK;
}

sysreturn listen(int sockfd, int backlog)
{
    sock s = resolve_fd(current->p, sockfd);        
    s->lw = tcp_listen_with_backlog(s->lw, backlog);
    tcp_arg(s->lw, s);
    tcp_accept(s->lw, accept_from_lwip);
    tcp_err(s->lw, lwip_conn_err);
    return 0;    
}

static CLOSURE_4_1(accept_finish, void, sock, thread, struct sockaddr *, socklen_t *, u64);
static void accept_finish(sock s, thread target, struct sockaddr *addr, socklen_t *addrlen, u64 status)
{
    sock sn = dequeue(s->incoming);
    remote_sockaddr_in(sn->lw, (struct sockaddr_in *)addr); 
    *addrlen = sizeof(struct sockaddr_in);
    set_syscall_return(target, sn->fd);                                
    thread_wakeup(target);
}

sysreturn accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);        

    // ok, this is a reasonable interlock to build, the dating app
    // it would be nice if we didn't have to sleep and wakeup for the nonblocking case
    if (queue_length(s->incoming)) {
        accept_finish(s, current, addr, addrlen, ERR_OK);
    } else {
        enqueue(s->waiting, closure(s->h, accept_finish, s, current, addr, addrlen));
    }
    thread_sleep(current);
}

sysreturn accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    return(accept(sockfd, addr, addrlen));
}

sysreturn getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);        
    local_sockaddr_in(s->lw, (struct sockaddr_in *)addr);
    *addrlen = sizeof(struct sockaddr_in);
    return 0;
}

sysreturn getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);        
    remote_sockaddr_in(s->lw, (struct sockaddr_in *)addr);
    return 0;    
}

sysreturn setsockopt(int sockfd,
                     int level,
                     int optname,
                     void *optval,
                     socklen_t optlen)
{
    //    rprintf("sockopt %d %d\n", sockfd, optname);
    return 0;
}

void register_net_syscalls(void **map)
{
    register_syscall(map, SYS_socket, socket);
    register_syscall(map, SYS_bind, bind);
    register_syscall(map, SYS_listen, listen);
    register_syscall(map, SYS_accept, accept);
    register_syscall(map, SYS_accept4, accept4);    
    register_syscall(map, SYS_setsockopt, setsockopt);
    register_syscall(map, SYS_connect, connect);
    register_syscall(map, SYS_getsockname, getsockname);
    register_syscall(map, SYS_getpeername, getpeername);    
}

boolean netsyscall_init(unix_heaps uh)
{
    kernel_heaps kh = (kernel_heaps)uh;
    heap socket_cache = allocate_objcache(heap_general(kh), heap_backed(kh),
					  sizeof(struct sock), PAGESIZE);
    if (socket_cache == INVALID_ADDRESS)
	return false;
    uh->socket_cache = socket_cache;
    return true;
}
