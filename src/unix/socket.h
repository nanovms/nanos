struct sockaddr {
    u16 family;
    u8 sa_data[14];
} *sockaddr;

struct sockaddr_storage {
    u16 family;
    u8 ss_data[126];
};

typedef u32 socklen_t;

struct sock {
    struct fdesc f;              /* must be first */
    int fd;
    int domain;
    int type;
    heap h;
    blockq rxbq;
    blockq txbq;
    unsigned int msg_count;
    sysreturn (*bind)(struct sock *sock, struct sockaddr *addr,
            socklen_t addrlen);
    sysreturn (*listen)(struct sock *sock, int backlog);
    sysreturn (*connect)(struct sock *sock, struct sockaddr *addr,
            socklen_t addrlen);
    sysreturn (*accept4)(struct sock *sock, struct sockaddr *addr,
            socklen_t *addrlen, int flags);
    sysreturn (*sendto)(struct sock *sock, void *buf, u64 len, int flags,
             struct sockaddr *dest_addr, socklen_t addrlen);
    sysreturn (*recvfrom)(struct sock *sock, void *buf, u64 len, int flags,
             struct sockaddr *dest_addr, socklen_t *addrlen);
    sysreturn (*shutdown)(struct sock *sock, int how);
};

static inline int socket_init(process p, heap h, int type, u32 flags,
        struct sock *s)
{
    runtime_memset((u8 *) s, 0, sizeof(*s));
    s->fd = allocate_fd(p, s);
    if (s->fd == INVALID_PHYSICAL) {
        msg_err("failed to allocate fd\n");
        goto err_fd;
    }
    s->rxbq = allocate_blockq(h, "sock receive");
    if (s->rxbq == INVALID_ADDRESS) {
        msg_err("failed to allocate blockq\n");
        goto err_rx;
    }
    s->txbq = allocate_blockq(h, "sock transmit");
    if (s->txbq == INVALID_ADDRESS) {
        msg_err("failed to allocate blockq\n");
        goto err_tx;
    }
    init_fdesc(h, &s->f, FDESC_TYPE_SOCKET);
    s->f.flags = flags;
    s->type = type;
    s->h = h;
    return s->fd;

err_tx:
    deallocate_blockq(s->rxbq);
err_rx:
    deallocate_fd(p, s->fd);
err_fd:
    return -ENOMEM;
}

static inline void socket_deinit(struct sock *s)
{
    release_fdesc(&s->f);
    deallocate_blockq(s->txbq);
    deallocate_blockq(s->rxbq);
}

static inline void socket_flush_q(struct sock *s)
{
    blockq_flush(s->rxbq);
    blockq_flush(s->txbq);
}

static inline sysreturn socket_ioctl(struct sock *s, unsigned long request,
        vlist ap)
{
    switch (request) {
    case FIONBIO: {
        int *opt = varg(ap, int *);
        if (!validate_user_memory(opt, sizeof(int), false))
            return -EFAULT;
        if (*opt) {
            s->f.flags |= SOCK_NONBLOCK;
        }
        else {
            s->f.flags &= ~SOCK_NONBLOCK;
        }
        return 0;
    }
    default:
        return -ENOSYS;
    }
}

sysreturn unixsock_open(int type, int protocol);
