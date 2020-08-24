typedef struct sockaddr {
    u16 family;
    u8 sa_data[14];
} *sockaddr;

struct sockaddr_storage {
    u16 family;
    u8 ss_data[126];
};

typedef u32 socklen_t;

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    u64 msg_iovlen;
    void *msg_control;
    u64 msg_controllen;
    int msg_flags;
};

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
    sysreturn (*sendmsg)(struct sock *sock, const struct msghdr *msg,
            int flags);
    sysreturn (*recvmsg)(struct sock *sock, struct msghdr *msg, int flags);
    sysreturn (*shutdown)(struct sock *sock, int how);
};

static inline int socket_init(process p, heap h, int domain, int type, u32 flags,
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
    s->f.flags = (flags & ~O_ACCMODE) | O_RDWR;
    s->domain = domain;
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
    return ioctl_generic(&s->f, request, ap);
}

static inline boolean validate_msghdr(const struct msghdr *mh, boolean write)
{
    if (!validate_user_memory(mh, sizeof(struct msghdr), false))
        return false;
    if (mh->msg_name && !validate_user_memory(mh->msg_name, mh->msg_namelen, false))
        return false;
    if (mh->msg_control && !validate_user_memory(mh->msg_control, mh->msg_controllen, write))
        return false;
    return validate_iovec(mh->msg_iov, mh->msg_iovlen, write);
}

sysreturn unixsock_open(int type, int protocol);
