#include <net_system_structs.h>
#include <unix_internal.h>
#include <filesystem.h>
#include <socket.h>

#define UNIXSOCK_BUF_MAX_SIZE   PAGESIZE
#define UNIXSOCK_QUEUE_MAX_LEN  64

struct sockaddr_un {
    u16 sun_family;
    char sun_path[108];
};

typedef struct unixsock {
    struct sock sock; /* must be first */
    queue data;
    tuple fs_entry;
    struct sockaddr_un local_addr;
    queue conn_q;
    boolean connecting;
    struct unixsock *peer;
} *unixsock;

/* A socket is in connecting state when connect() has been called but the
 * connection has not yet been accepted by the peer. */
static inline boolean unixsock_is_connecting(unixsock s)
{
    return (s->connecting && !s->peer);
}

static inline boolean unixsock_is_connected(unixsock s)
{
    return (!s->connecting && s->peer);
}

static unixsock unixsock_alloc(heap h, int type, u32 flags);

static void unixsock_dealloc(unixsock s)
{
    deallocate_queue(s->data);
    deallocate_closure(s->sock.f.read);
    deallocate_closure(s->sock.f.write);
    deallocate_closure(s->sock.f.events);
    deallocate_closure(s->sock.f.close);
    socket_deinit(&s->sock);
    deallocate(s->sock.h, s, sizeof(*s));
}

static inline void unixsock_notify_reader(unixsock s)
{
    blockq_wake_one(s->sock.rxbq);
    notify_dispatch(s->sock.f.ns, EPOLLIN);
}

static inline void unixsock_notify_writer(unixsock s)
{
    blockq_wake_one(s->sock.txbq);
    notify_dispatch(s->sock.f.ns, EPOLLOUT);
}

closure_function(5, 1, sysreturn, unixsock_read_bh,
                 unixsock, s, thread, t, void *, dest, u64, length, io_completion, completion,
                 u64, flags)
{
    unixsock s = bound(s);
    void *dest = bound(dest);
    u64 length = bound(length);

    buffer b;
    sysreturn rv;

    if ((flags & BLOCKQ_ACTION_NULLIFY) && s->peer) {
        rv = -EINTR;
        goto out;
    }

    b = queue_peek(s->data);
    if (b == INVALID_ADDRESS) {
        if (!s->peer) {
            rv = 0;
            goto out;
        }
        else if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    rv = 0;
    do {
        u64 xfer = MIN(buffer_length(b), length);
        buffer_read(b, dest, xfer);
        rv += xfer;
        dest = (u8 *) dest + xfer;
        length -= xfer;
        if (!buffer_length(b) || (s->sock.type == SOCK_DGRAM)) {
            assert(dequeue(s->data) == b);
            deallocate_buffer(b);
            b = queue_peek(s->data);
            if (b == INVALID_ADDRESS) { /* no more data available to read */
                fdesc_notify_events(&s->sock.f);
                break;
            }
        }
    } while ((s->sock.type == SOCK_STREAM) && (length > 0));
    if (s->peer) {
        unixsock_notify_writer(s->peer);
    }
out:
    blockq_handle_completion(s->sock.rxbq, flags, bound(completion), bound(t),
            rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, unixsock_read,
                 unixsock, s,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    unixsock s = bound(s);
    if ((s->sock.type == SOCK_STREAM) && (length == 0)) {
        return 0;
    }

    blockq_action ba = closure(s->sock.h, unixsock_read_bh, s, t, dest, length,
            completion);
    return blockq_check(s->sock.rxbq, t, ba, bh);
}

static sysreturn unixsock_write_to(void *src, u64 length, unixsock dest)
{
    if (queue_full(dest->data)) {
        return -EAGAIN;
    }

    sysreturn rv = 0;
    do {
        u64 xfer = MIN(UNIXSOCK_BUF_MAX_SIZE, length);
        buffer b = allocate_buffer(dest->sock.h, xfer);
        if (b == INVALID_ADDRESS) {
            if (rv == 0) {
                rv = -ENOMEM;
            }
            break;
        }
        buffer_write(b, src, xfer);
        assert(enqueue(dest->data, b));
        rv += xfer;
        src = (u8 *) src + xfer;
        length -= xfer;
    } while ((length > 0) && !queue_full(dest->data));
    if ((rv > 0) || ((rv == 0) && (dest->sock.type == SOCK_DGRAM))) {
        unixsock_notify_reader(dest);
    }
    return rv;
}

closure_function(5, 1, sysreturn, unixsock_write_bh,
                 unixsock, s, thread, t, void *, src, u64, length, io_completion, completion,
                 u64, flags)
{
    unixsock s = bound(s);
    void *src = bound(src);
    u64 length = bound(length);

    sysreturn rv;

    if ((flags & BLOCKQ_ACTION_NULLIFY) && s->peer) {
        rv = -EINTR;
        goto out;
    }
    if (!s->peer) {
        rv = -EPIPE;
        goto out;
    }

    rv = unixsock_write_to(src, length, s->peer);
    if ((rv == -EAGAIN) && !(s->sock.f.flags & SOCK_NONBLOCK)) {
        return BLOCKQ_BLOCK_REQUIRED;
    }
    if (queue_full(s->peer->data)) { /* no more space available to write */
        fdesc_notify_events(&s->sock.f);
    }
out:
    blockq_handle_completion(s->sock.txbq, flags, bound(completion), bound(t),
            rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, unixsock_write,
                 unixsock, s,
                 void *, src, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    unixsock s = bound(s);
    if ((s->sock.type == SOCK_STREAM) && (length == 0)) {
        return 0;
    }
    if ((s->sock.type == SOCK_DGRAM) && (length > UNIXSOCK_BUF_MAX_SIZE)) {
        return -EMSGSIZE;
    }

    blockq_action ba = closure(s->sock.h, unixsock_write_bh, s, t, src, length,
            completion);
    return blockq_check(s->sock.txbq, t, ba, bh);
}

closure_function(1, 1, u32, unixsock_events,
                 unixsock, s,
                 thread, t /* ignore */)
{
    unixsock s = bound(s);
    u32 events = 0;
    if (s->conn_q) {    /* listening state */
        if (!queue_empty(s->conn_q)) {
            events |= EPOLLIN;
        }
    } else if (s->connecting) {
        if (s->peer) {
            /* An ongoing connection attempt has been accepted by the peer. */
            events |= EPOLLOUT;
        }
    }
    else {
        if (!queue_empty(s->data)) {
            events |= EPOLLIN;
        }
        if (s->peer && !queue_full(s->peer->data)) {
            events |= EPOLLOUT;
        }
        if (!s->peer) {
            events |= EPOLLHUP;
        }
    }
    return events;
}

closure_function(1, 2, sysreturn, unixsock_ioctl,
                 unixsock, s,
                 unsigned long, request, vlist, ap)
{
    unixsock s = bound(s);
    return socket_ioctl(&s->sock, request, ap);
}

closure_function(1, 0, sysreturn, unixsock_close,
                 unixsock, s)
{
    unixsock s = bound(s);
    if (s->peer) {
        s->peer->peer = 0;
        socket_flush_q(&s->peer->sock);
        notify_dispatch(s->peer->sock.f.ns, EPOLLHUP);
    }
    if (s->conn_q) {
        /* Notify any connecting sockets that connection is being refused. */
        unixsock child;
        while ((child = dequeue(s->conn_q)) != INVALID_ADDRESS) {
            child->connecting = false;
            socket_flush_q(&child->sock);
        }

        deallocate_queue(s->conn_q);
    }
    if (s->fs_entry) {
        buffer_clear(table_find(s->fs_entry, sym(socket)));
    }
    unixsock_dealloc(s);
    return 0;
}

static sysreturn unixsock_bind(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    if (!addr) {
        return -EFAULT;
    }

    unixsock s = (unixsock) sock;
    struct sockaddr_un *unixaddr = (struct sockaddr_un *) addr;
    if (s->fs_entry || (addrlen <= sizeof(unixaddr->sun_family))) {
        return -EINVAL;
    }
    if (addrlen > sizeof(*unixaddr)) {
        return -ENAMETOOLONG;
    }

    /* Ensure that the NULL-terminated path string fits in unixaddr->sun_path
     * (add terminator character if not found). */
    int term;
    for (term = 1; term < addrlen - sizeof(unixaddr->sun_family); term++) {
        if (unixaddr->sun_path[term] == '\0') {
            break;
        }
    }
    if (term == addrlen - sizeof(unixaddr->sun_family)) {
        /* Terminator character not found: add it if possible. */
        if (addrlen == sizeof(*unixaddr)) {
            return -ENAMETOOLONG;
        }
        unixaddr->sun_path[term] = '\0';
    }

    s->fs_entry = allocate_tuple();

    /* The "socket" symbol value associated to the filesystem tuple is a buffer
     * containing a pointer to the socket. Since we don't want this pointer to
     * be persisted in the filesystem, the buffer must be empty when
     * filesystem_add_tuple() is called, and must be filled afterwards. */
    buffer b = allocate_buffer(sock->h, sizeof(u64));
    table_set(s->fs_entry, sym(socket), b);
    sysreturn ret = filesystem_add_tuple(unixaddr->sun_path, s->fs_entry);
    if (ret) {
        deallocate_buffer(b);
        deallocate_tuple(s->fs_entry);
        s->fs_entry = 0;
        if (ret == -EEXIST) {
            return -EADDRINUSE;
        }
        else {
            return ret;
        }
    }
    buffer_write_le64(b, u64_from_pointer(s));

    runtime_memcpy(&s->local_addr, addr, addrlen);
    return ret;
}

static sysreturn unixsock_listen(struct sock *sock, int backlog)
{
    unixsock s = (unixsock) sock;
    if (!s->conn_q) {
        s->conn_q = allocate_queue(sock->h, backlog);
        if (s->conn_q == INVALID_ADDRESS) {
            msg_err("failed to allocate connection queue\n");
            s->conn_q = 0;
            return -ENOMEM;
        }
    }
    return 0;
}

closure_function(2, 1, sysreturn, connect_bh,
                 unixsock, s, thread, t,
                 u64, bqflags)
{
    unixsock s = bound(s);
    thread t = bound(t);
    sysreturn rv;

    if ((bqflags & BLOCKQ_ACTION_NULLIFY) && s->connecting) {
        rv = -EINTR;
        goto out;
    }
    if (!s->connecting) {   /* the listening socket has been shut down */
        rv = -ECONNREFUSED;
        goto out;
    }
    if (!s->peer) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EINPROGRESS;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    s->connecting = false;  /* connection has been established */
    rv = 0;
out:
    set_syscall_return(t, rv);
    if (bqflags & BLOCKQ_ACTION_BLOCKED) {
        thread_wakeup(t);
    }
    closure_finish();
    return rv;
}

static sysreturn unixsock_connect(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    if (!addr) {
        return -EFAULT;
    }
    unixsock s = (unixsock) sock;
    if (unixsock_is_connecting(s)) {
        return -EALREADY;
    } else if (unixsock_is_connected(s)) {
        return -EISCONN;
    }

    struct sockaddr_un *unixaddr = (struct sockaddr_un *) addr;
    tuple t;
    buffer b;
    unixsock listener, peer;
    if (filesystem_get_tuple(unixaddr->sun_path, &t) < 0) {
        return -ECONNREFUSED;
    }
    b = table_find(t, sym(socket));
    if (!b || (buffer_length(b) != sizeof(u64))) {
        return -ECONNREFUSED;
    }
    listener = pointer_from_u64(*((u64 *) buffer_ref(b, 0)));
    assert(listener);
    if (!s->connecting) {
        if (!listener->conn_q || queue_full(listener->conn_q)) {
            return -ECONNREFUSED;
        }
        peer = unixsock_alloc(sock->h, sock->type, 0);
        if (!peer) {
            return -ENOMEM;
        }

        peer->peer = s;
        assert(enqueue(listener->conn_q, peer));
        s->connecting = true;
        unixsock_notify_reader(listener);
    }
    blockq_action ba = closure(sock->h, connect_bh, s, current);
    return blockq_check(sock->txbq, current, ba, false);
}

closure_function(5, 1, sysreturn, accept_bh,
                 unixsock, s, thread, t, struct sockaddr *, addr, socklen_t *, addrlen, int, flags,
                 u64, bqflags)
{
    unixsock s = bound(s);
    thread t = bound(t);
    struct sockaddr *addr = bound(addr);
    sysreturn rv;

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }
    unixsock child = dequeue(s->conn_q);
    if (child == INVALID_ADDRESS) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    if (queue_length(s->conn_q) == 0) {
        fdesc_notify_events(&s->sock.f);
    }
    child->sock.f.flags = bound(flags);
    rv = child->sock.fd;
    if (addr) {
        socklen_t *addrlen = bound(addrlen);
        socklen_t actual_len = sizeof(child->peer->local_addr.sun_family);
        if (child->peer->local_addr.sun_path[0]) {  /* pathname socket */
            actual_len += runtime_strlen(child->peer->local_addr.sun_path) + 1;
        }
        runtime_memcpy(addr, &child->peer->local_addr,
                MIN(*addrlen, actual_len));
        *addrlen = actual_len;
    }
    child->peer->peer = child;
    unixsock_notify_writer(child->peer);
out:
    set_syscall_return(t, rv);
    if (bqflags & BLOCKQ_ACTION_BLOCKED) {
        thread_wakeup(t);
    }
    closure_finish();
    return rv;
}

static sysreturn unixsock_accept4(struct sock *sock, struct sockaddr *addr,
        socklen_t *addrlen, int flags)
{
    unixsock s = (unixsock) sock;
    if (addr && !addrlen) {
        return -EFAULT;
    }
    if (!s->conn_q) {
        return -EINVAL;
    }
    blockq_action ba = closure(sock->h, accept_bh, s, current, addr, addrlen,
            flags);
    return blockq_check(sock->rxbq, current, ba, false);
}

sysreturn unixsock_sendto(struct sock *sock, void *buf, u64 len, int flags,
        struct sockaddr *dest_addr, socklen_t addrlen)
{
    /* Non-connected sockets are not supported, so destination address is
     * ignored. */
    return apply(sock->f.write, buf, len, 0, current, false,
            syscall_io_complete);
}

sysreturn unixsock_recvfrom(struct sock *sock, void *buf, u64 len, int flags,
        struct sockaddr *dest_addr, socklen_t *addrlen)
{
    /* Non-connected sockets are not supported, so source address is not set. */
    if (addrlen) {
        *addrlen = 0;
    }
    return apply(sock->f.read, buf, len, 0, current, false,
            syscall_io_complete);
}

static unixsock unixsock_alloc(heap h, int type, u32 flags)
{
    unixsock s = allocate(h, sizeof(*s));
    if (s == INVALID_ADDRESS) {
        msg_err("failed to allocate socket structure\n");
        return 0;
    }
    s->data = allocate_queue(h, UNIXSOCK_QUEUE_MAX_LEN);
    if (s->data == INVALID_ADDRESS) {
        msg_err("failed to allocate data buffer\n");
        goto err_queue;
    }
    if (socket_init(current->p, h, type, flags, &s->sock) < 0) {
        msg_err("failed to initialize socket\n");
        goto err_socket;
    }
    s->sock.f.read = closure(h, unixsock_read, s);
    s->sock.f.write = closure(h, unixsock_write, s);
    s->sock.f.events = closure(h, unixsock_events, s);
    s->sock.f.ioctl = closure(h, unixsock_ioctl, s);
    s->sock.f.close = closure(h, unixsock_close, s);
    s->sock.bind = unixsock_bind;
    s->sock.listen = unixsock_listen;
    s->sock.connect = unixsock_connect;
    s->sock.accept4 = unixsock_accept4;
    s->sock.sendto = unixsock_sendto;
    s->sock.recvfrom = unixsock_recvfrom;
    s->fs_entry = 0;
    s->local_addr.sun_family = AF_UNIX;
    s->local_addr.sun_path[0] = '\0';
    s->conn_q = 0;
    s->connecting = false;
    s->peer = 0;
    return s;
err_socket:
    deallocate_queue(s->data);
err_queue:
    deallocate(h, s, sizeof(*s));
    return 0;
}

sysreturn unixsock_open(int type, int protocol) {
    unix_heaps uh = get_unix_heaps();
    heap h = heap_general((kernel_heaps)uh);
    unixsock s;

    if (((type & SOCK_TYPE_MASK) != SOCK_STREAM) &&
            ((type & SOCK_TYPE_MASK) != SOCK_DGRAM)) {
        return -ESOCKTNOSUPPORT;
    }
    s = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK);
    if (!s) {
        return -ENOMEM;
    }
    return s->sock.fd;
}

sysreturn socketpair(int domain, int type, int protocol, int sv[2]) {
    unix_heaps uh = get_unix_heaps();
    heap h = heap_general((kernel_heaps)uh);
    unixsock s1, s2;

    if (domain != AF_UNIX) {
        return set_syscall_error(current, EAFNOSUPPORT);
    }
    if (((type & SOCK_TYPE_MASK) != SOCK_STREAM) &&
            ((type & SOCK_TYPE_MASK) != SOCK_DGRAM)) {
        return -ESOCKTNOSUPPORT;
    }
    if (!sv) {
        return -EFAULT;
    }
    s1 = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK);
    if (!s1) {
        return -ENOMEM;
    }
    s2 = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK);
    if (!s2) {
        unixsock_dealloc(s1);
        return -ENOMEM;
    }
    s1->peer = s2;
    s2->peer = s1;
    sv[0] = s1->sock.fd;
    sv[1] = s2->sock.fd;
    return 0;
}
