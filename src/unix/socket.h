#define SOCK_FLAGS_MASK (SOCK_NONBLOCK | SOCK_CLOEXEC)

typedef struct sockaddr {
    u16 family;
    u8 sa_data[14];
} *sockaddr;

struct sockaddr_storage {
    u16 family;
    u8 ss_data[126];
};

struct sockaddr_un {
    u16 sun_family;
    char sun_path[108];
};

struct sockaddr_vm {
    u16 svm_family;
    u16 svm_rsvd;
    u32 svm_port;
    u32 svm_cid;
    u8 svm_zero[4];
};

#define VMADDR_CID_ANY  (-1U)

#define VMADDR_PORT_ANY (-1U)

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

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

#define IFNAMSIZ    16

struct ifmap {
    unsigned long mem_start;
    unsigned long mem_end;
    unsigned short base_addr;
    unsigned char irq;
    unsigned char dma;
    unsigned char port;
};

struct ifreq {
    char ifr_name[IFNAMSIZ];
    union {
        struct sockaddr ifr_addr;
        struct sockaddr ifr_dstaddr;
        struct sockaddr ifr_broadaddr;
        struct sockaddr ifr_netmask;
        struct sockaddr ifr_hwaddr;
        short ifr_flags;
        int ifr_ivalue;
        int ifr_mtu;
        struct ifmap ifru_map;
        char ifr_slave[IFNAMSIZ];
        char ifr_newname[IFNAMSIZ];
        void *ifr_data;
    } ifr;
};

struct sock {
    struct fdesc f;              /* must be first */
    int fd;
    int domain;
    int type;
    heap h;
    blockq rxbq;
    blockq txbq;
    u64 rx_len;
    sysreturn (*bind)(struct sock *sock, struct sockaddr *addr,
            socklen_t addrlen);
    sysreturn (*listen)(struct sock *sock, int backlog);
    sysreturn (*connect)(struct sock *sock, struct sockaddr *addr,
            socklen_t addrlen);
    sysreturn (*accept4)(struct sock *sock, struct sockaddr *addr,
                         socklen_t *addrlen, int flags, context ctx, boolean in_bh,
                         io_completion completion);
    sysreturn (*getsockname)(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen);
    sysreturn (*getsockopt)(struct sock *sock, int level,
                            int optname, void *optval, socklen_t *optlen);
    sysreturn (*setsockopt)(struct sock *sock, int level,
                            int optname, void *optval, socklen_t optlen);
    sysreturn (*sendto)(struct sock *sock, void *buf, u64 len, int flags,
                        struct sockaddr *dest_addr, socklen_t addrlen, context ctx, boolean in_bh,
                        io_completion completion);
    sysreturn (*recvfrom)(struct sock *sock, void *buf, u64 len, int flags,
                          struct sockaddr *dest_addr, socklen_t *addrlen, context ctx,
                          boolean in_bh, io_completion completion);
    sysreturn (*sendmsg)(struct sock *sock, const struct msghdr *msg,
                         int flags, boolean in_bh, io_completion completion);
    sysreturn (*recvmsg)(struct sock *sock, struct msghdr *msg, int flags, boolean in_bh,
                         io_completion completion);
    sysreturn (*shutdown)(struct sock *sock, int how);
};

#define socket_release(s) fdesc_put(&(s)->f)

static inline int socket_init(heap h, int domain, int type, u32 flags, struct sock *s)
{
    runtime_memset((u8 *) s, 0, sizeof(*s));
    s->rxbq = allocate_blockq(h, ss("sock receive"));
    if (s->rxbq == INVALID_ADDRESS) {
        msg_err("%s: failed to allocate blockq", func_ss);
        goto err_rx;
    }
    s->txbq = allocate_blockq(h, ss("sock transmit"));
    if (s->txbq == INVALID_ADDRESS) {
        msg_err("%s: failed to allocate blockq", func_ss);
        goto err_tx;
    }
    s->rx_len = 0;
    init_fdesc(h, &s->f, FDESC_TYPE_SOCKET);
    s->f.flags = (flags & ~O_ACCMODE) | O_RDWR;
    s->domain = domain;
    s->type = type;
    s->h = h;
    return 0;

err_tx:
    deallocate_blockq(s->rxbq);
err_rx:
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

sysreturn socket_ioctl(struct sock *s, unsigned long request, vlist ap);
sysreturn socket_accept4(fdesc f, struct sockaddr *addr, socklen_t *addrlen, int flags, context ctx,
                         boolean in_bh, io_completion completion);
sysreturn socket_send(fdesc f, void *buf, u64 len, context ctx, boolean in_bh,
                      io_completion completion);
sysreturn socket_recv(fdesc f, void *buf, u64 len, context ctx, boolean in_bh,
                      io_completion completion);

static inline boolean validate_msghdr(const struct msghdr *mh, boolean write)
{
    if (!validate_user_memory(mh, sizeof(struct msghdr), false))
        return false;
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx)) {
        boolean ok;
        ok = (!mh->msg_name || validate_user_memory(mh->msg_name, mh->msg_namelen, false)) &&
             (!mh->msg_control || validate_user_memory(mh->msg_control, mh->msg_controllen, write));
        context_clear_err(ctx);
        if (!ok)
            return false;
    } else {
        return false;
    }
    return validate_iovec(mh->msg_iov, mh->msg_iovlen, write);
}

static inline sysreturn sockopt_copy_from_user(void *uval, socklen_t ulen, void *val, socklen_t len)
{
    if (ulen != len)
        return -EINVAL;
    if (!copy_from_user(uval, val, len))
        return -EFAULT;
    return 0;
}

static inline sysreturn sockopt_copy_to_user(void *uval, socklen_t *ulen, void *val, socklen_t len)
{
    if (!uval || !ulen)
        return 0;
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(ulen, sizeof(socklen_t), true) || context_set_err(ctx))
        return -EFAULT;
    len = MIN(*ulen, len);
    sysreturn rv;
    if (validate_user_memory(uval, len, true)) {
        runtime_memcpy(uval, val, len);
        *ulen = len;
        rv = 0;
    } else {
        rv = -EFAULT;
    }
    context_clear_err(ctx);
    return rv;
}

sysreturn unixsock_open(int type, int protocol);

void netlink_init(void);
sysreturn netlink_open(int type, int family);

void vsock_init(void);
sysreturn vsock_open(int type, int family);

extern int so_rcvbuf;
