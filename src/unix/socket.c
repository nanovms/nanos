#include <net_system_structs.h>
#include <unix_internal.h>
#include <filesystem.h>
#include <socket.h>

declare_closure_struct(1, 0, void, sharedbuf_free,
    struct sharedbuf *, shb);

declare_closure_struct(1, 2, boolean, unixsock_event_handler,
                       struct unixsock *, s,
                       u64, events, void *, arg);
declare_closure_struct(1, 0, void, unixsock_free,
    struct unixsock *, s);

struct sockaddr_un {
    u16 sun_family;
    char sun_path[108];
};

typedef struct sharedbuf {
    buffer b;
    struct refcount refcount;
    closure_struct(sharedbuf_free, free);
    struct sockaddr_un from_addr;
} *sharedbuf;

#define UNIXSOCK_BUF_MAX_SIZE   PAGESIZE
#define UNIXSOCK_QUEUE_MAX_LEN  64

typedef struct unixsock {
    struct sock sock; /* must be first */
    queue data;
    filesystem fs;
    inode fs_entry;
    struct sockaddr_un local_addr;
    queue conn_q;
    struct unixsock *peer;
    notify_entry notify_handle;
    closure_struct(unixsock_event_handler, event_handler);
    closure_struct(unixsock_free, free);
    struct refcount refcount;
} *unixsock;

#define unixsock_lock(s)    spin_lock(&(s)->sock.f.lock)
#define unixsock_unlock(s)  spin_unlock(&(s)->sock.f.lock)

static inline void sharedbuf_deallocate(sharedbuf shb)
{
    heap h = shb->b->h;
    deallocate_buffer(shb->b);
    deallocate(h, shb, sizeof(*shb));
}

define_closure_function(1, 0, void, sharedbuf_free,
                        sharedbuf, shb)
{
    sharedbuf_deallocate(bound(shb));
}

define_closure_function(1, 2, boolean, unixsock_event_handler,
                        unixsock, s,
                        u64, events, void *, arg)
{
    unixsock s = bound(s);
    if (events == NOTIFY_EVENTS_RELEASE)    /* the peer socket is being closed */
        s->notify_handle = INVALID_ADDRESS;
    fdesc_notify_events(&s->sock.f);
    return false;
}

define_closure_function(1, 0, void, unixsock_free,
                        unixsock, s)
{
    unixsock s = bound(s);
    deallocate(s->sock.h, s, sizeof(*s));
}

static inline sharedbuf sharedbuf_allocate(heap h, u64 len)
{
    sharedbuf shb = allocate(h, sizeof(*shb));
    if (shb == INVALID_ADDRESS)
        return shb;
    shb->b = allocate_buffer(h, len);
    if (shb->b == INVALID_ADDRESS) {
        deallocate(h, shb, sizeof(*shb));
        return INVALID_ADDRESS;
    }
    init_closure(&shb->free, sharedbuf_free, shb);
    init_refcount(&shb->refcount, 1, (thunk)&shb->free);
    return shb;
}

static inline void sharedbuf_reserve(sharedbuf shb)
{
    refcount_reserve(&shb->refcount);
}

static inline void sharedbuf_release(sharedbuf shb)
{
    refcount_release(&shb->refcount);
}

static inline boolean unixsock_is_connected(unixsock s)
{
    return (s->peer && s->peer->data);
}

static void unixsock_conn_internal(unixsock s, unixsock peer)
{
    refcount_reserve(&peer->refcount);
    s->peer = peer;
}

static void unixsock_disconnect(unixsock s)
{
    if (s->peer) {
        refcount_release(&s->peer->refcount);
        s->peer = 0;
    }
}

static unixsock unixsock_alloc(heap h, int type, u32 flags);

/* Called with lock acquired, returns with lock released. */
static void unixsock_dealloc(unixsock s)
{
    deallocate_queue(s->data);
    s->data = 0;
    unixsock_unlock(s);
    unixsock peer = (s->sock.type == SOCK_STREAM) ? s->peer : 0;
    if (peer) {
        unixsock_lock(peer);
        blockq bq = peer->data ? peer->sock.rxbq : 0;
        if (bq)
            blockq_reserve(bq);
        unixsock_unlock(peer);
        if (bq) {
            blockq_flush(bq);
            blockq_release(bq);
        }
    }
    blockq_flush(s->sock.txbq); /* unblock any sockets connecting or writing to this socket */
    if (s->notify_handle != INVALID_ADDRESS)
        notify_remove(s->peer->sock.f.ns, s->notify_handle, false);
    unixsock_disconnect(s);
    deallocate_closure(s->sock.f.read);
    deallocate_closure(s->sock.f.write);
    deallocate_closure(s->sock.f.events);
    deallocate_closure(s->sock.f.close);
    socket_deinit(&s->sock);
    refcount_release(&s->refcount);
}

static inline void unixsock_notify_reader(unixsock s)
{
    blockq_wake_one(s->sock.rxbq);
    fdesc_notify_events(&s->sock.f);
}

/* The argument refers to the destination socket, not to the sending socket. */
static inline void unixsock_notify_writer(unixsock s)
{
    blockq_wake_one(s->sock.txbq);
    fdesc_notify_events(&s->sock.f);
}

closure_function(8, 1, sysreturn, unixsock_read_bh,
                 unixsock, s, thread, t, void *, dest, sg_list, sg, u64, length, io_completion, completion, struct sockaddr_un *, from_addr, socklen_t *, from_length,
                 u64, flags)
{
    unixsock s = bound(s);
    void *dest = bound(dest);
    u64 length = bound(length);

    sharedbuf shb;
    sysreturn rv;

    unixsock_lock(s);
    boolean disconnected = (s->sock.type == SOCK_STREAM) && !(s->peer && s->peer->data);
    boolean read_done = false;
    if ((flags & BLOCKQ_ACTION_NULLIFY) && !disconnected) {
        rv = -ERESTARTSYS;
        goto out;
    }
    shb = queue_peek(s->data);
    if (shb == INVALID_ADDRESS) {
        if (disconnected) {
            rv = 0;
            goto out;
        } else if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        unixsock_unlock(s);
        return BLOCKQ_BLOCK_REQUIRED;
    }
    rv = 0;
    do {
        buffer b = shb->b;
        u64 xfer = MIN(buffer_length(b), length);
        if (dest) {
            buffer_read(b, dest, xfer);
            dest = (u8 *)dest + xfer;
        } else if (xfer > 0) {
            sg_buf sgb = sg_list_tail_add(bound(sg), xfer);
            if (!sgb)
                break;
            sharedbuf_reserve(shb);
            sgb->buf = buffer_ref(b, 0);
            sgb->size = xfer;
            sgb->offset = 0;
            sgb->refcount = &shb->refcount;
            buffer_consume(b, xfer);
        }
        rv += xfer;
        length -= xfer;
        s->sock.rx_len -= xfer;
        if (!buffer_length(b) || (s->sock.type == SOCK_DGRAM)) {
            assert(dequeue(s->data) == shb);
            if (s->sock.type == SOCK_DGRAM) {
                s->sock.rx_len -= buffer_length(b);
                struct sockaddr_un *from_addr = bound(from_addr);
                socklen_t *from_length = bound(from_length);
                if (from_addr && from_length) {
                    runtime_memcpy(from_addr, &shb->from_addr, MIN(*from_length, sizeof(shb->from_addr)));
                    *from_length = __builtin_offsetof(struct sockaddr_un, sun_path) + runtime_strlen(from_addr->sun_path) + 1;
                }
            }
            sharedbuf_release(shb);
            shb = queue_peek(s->data);
            if (shb == INVALID_ADDRESS) { /* no more data available to read */
                break;
            }
        }
    } while ((s->sock.type == SOCK_STREAM) && (length > 0));
    read_done = true;
out:
    unixsock_unlock(s);
    if (read_done)
        unixsock_notify_writer(s);
    blockq_handle_completion(s->sock.rxbq, flags, bound(completion), bound(t),
            rv);
    closure_finish();
    return rv;
}

static sysreturn unixsock_read_with_addr(unixsock s, void *dest, u64 length, u64 offset_arg, thread t, boolean bh, io_completion completion, void *addr, socklen_t *addrlen)
{
    if ((s->sock.type == SOCK_STREAM) && (length == 0))
        return io_complete(completion, t, 0);

    blockq_action ba = closure(s->sock.h, unixsock_read_bh, s, t, dest, 0, length,
            completion, addr, addrlen);
    return blockq_check(s->sock.rxbq, t, ba, bh);
}

closure_function(1, 6, sysreturn, unixsock_read,
                 unixsock, s,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    return unixsock_read_with_addr(bound(s), dest, length, offset_arg, t, bh, completion, 0, 0);
}

static sysreturn unixsock_write_check(unixsock s, u64 len)
{
    if ((s->sock.type == SOCK_STREAM) && (len == 0))
        return 0;
    if ((s->sock.type == SOCK_DGRAM) && (len > UNIXSOCK_BUF_MAX_SIZE))
        return -EMSGSIZE;
    return 1;   /* any value > 0 will do */
}

static sysreturn unixsock_write_to(void *src, sg_list sg, u64 length,
                                   unixsock dest, unixsock from)
{
    if ((dest->sock.rx_len >= so_rcvbuf) || queue_full(dest->data)) {
        return -EAGAIN;
    }

    sysreturn rv = 0;
    do {
        u64 xfer = MIN(UNIXSOCK_BUF_MAX_SIZE, length);
        if (from->sock.type == SOCK_STREAM)
            xfer = MIN(xfer, so_rcvbuf - dest->sock.rx_len);
        sharedbuf shb = sharedbuf_allocate(dest->sock.h, xfer);
        if (shb == INVALID_ADDRESS) {
            if (rv == 0) {
                rv = -ENOMEM;
            }
            break;
        }
        if (from && from->sock.type == SOCK_DGRAM)
            runtime_memcpy(&shb->from_addr, &from->local_addr, sizeof(struct sockaddr_un));
        if (src) {
            assert(buffer_write(shb->b, src, xfer));
            src = (u8 *) src + xfer;
        } else {
            u64 len = sg_copy_to_buf(buffer_ref(shb->b, 0), sg, xfer);
            assert(len == xfer);
            buffer_produce(shb->b, xfer);
        }
        assert(enqueue(dest->data, shb));
        dest->sock.rx_len += xfer;
        rv += xfer;
        length -= xfer;
    } while ((length > 0) && (dest->sock.rx_len < so_rcvbuf) && !queue_full(dest->data));
    return rv;
}

static int lookup_socket(unixsock *s, char *path)
{
    process p = current->p;
    filesystem fs = p->cwd_fs;
    tuple n;
    fs_status fss = filesystem_get_socket(&fs, p->cwd, path, &n, (void **)s);
    if (fss == FS_STATUS_INVAL)
        return -ECONNREFUSED;
    if (fss == FS_STATUS_OK) {
        refcount_reserve(&(*s)->refcount);
        filesystem_put_node(fs, n);
    }
    return sysreturn_from_fs_status(fss);
}

closure_function(7, 1, sysreturn, unixsock_write_bh,
                 unixsock, s, thread, t, void *, src, sg_list, sg, u64, length, io_completion, completion, unixsock, dest,
                 u64, flags)
{
    unixsock s = bound(s);
    void *src = bound(src);
    u64 length = bound(length);
    unixsock dest;
    boolean full = false;

    sysreturn rv;

    dest = bound(dest);
    unixsock_lock(dest);
    if ((flags & BLOCKQ_ACTION_NULLIFY) && dest->data) {
        rv = -ERESTARTSYS;
        goto out;
    }
    if (!dest->data) {
        rv = (s->sock.type == SOCK_STREAM) ? -EPIPE : -ECONNREFUSED;
        goto out;
    }

    rv = unixsock_write_to(src, bound(sg), length, dest, s);
    if ((rv == -EAGAIN) && !(s->sock.f.flags & SOCK_NONBLOCK)) {
        unixsock_unlock(dest);
        return BLOCKQ_BLOCK_REQUIRED;
    }
    full = (dest->sock.rx_len >= so_rcvbuf) || queue_full(dest->data);
out:
    unixsock_unlock(dest);
    if ((rv > 0) || ((rv == 0) && (dest->sock.type != SOCK_STREAM)))
        unixsock_notify_reader(dest);
    if (full)   /* no more space available to write */
        fdesc_notify_events(&s->sock.f);
    blockq_handle_completion(dest->sock.txbq, flags, bound(completion), bound(t),
            rv);
    refcount_release(&dest->refcount);
    closure_finish();
    return rv;
}

static sysreturn unixsock_write_with_addr(unixsock s, void *src, u64 length, u64 offset, thread t,
                                          boolean bh, io_completion completion, unixsock addr)
{
    sysreturn rv = unixsock_write_check(s, length);
    if (rv <= 0) {
        refcount_release(&addr->refcount);
        return io_complete(completion, t, rv);
    }

    blockq_action ba = closure(s->sock.h, unixsock_write_bh, s, t, src, 0, length,
                               completion, addr);
    return blockq_check(addr->sock.txbq, t, ba, bh);
}

closure_function(1, 6, sysreturn, unixsock_write,
                 unixsock, s,
                 void *, src, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    unixsock_lock(bound(s));
    unixsock dest = bound(s)->peer;
    if (dest)
        refcount_reserve(&dest->refcount);
    unixsock_unlock(bound(s));
    if (!dest)
        return io_complete(completion, t, -ENOTCONN);
    return unixsock_write_with_addr(bound(s), src, length, offset, t, bh, completion, dest);
}

closure_function(1, 6, sysreturn, unixsock_sg_read,
                 unixsock, s,
                 sg_list, sg, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    unixsock s = bound(s);
    blockq_action ba = closure(s->sock.h, unixsock_read_bh, s, t, 0, sg, length,
        completion, 0, 0);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, t, -ENOMEM);
    return blockq_check(s->sock.rxbq, t, ba, bh);
}

closure_function(1, 6, sysreturn, unixsock_sg_write,
                 unixsock, s,
                 sg_list, sg, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    unixsock s = bound(s);
    sysreturn rv = unixsock_write_check(s, length);
    if (rv <= 0)
        return io_complete(completion, t, rv);
    unixsock_lock(bound(s));
    unixsock dest = bound(s)->peer;
    if (dest)
        refcount_reserve(&dest->refcount);
    unixsock_unlock(bound(s));
    if (!dest)
        return io_complete(completion, t, -ENOTCONN);
    blockq_action ba = closure(s->sock.h, unixsock_write_bh, s, t, 0, sg, length,
                               completion, dest);
    if (ba == INVALID_ADDRESS) {
        refcount_release(&dest->refcount);
        return io_complete(completion, t, -ENOMEM);
    }
    return blockq_check(dest->sock.txbq, t, ba, bh);
}

closure_function(1, 1, u32, unixsock_events,
                 unixsock, s,
                 thread, t /* ignore */)
{
    unixsock s = bound(s);
    u32 events = 0;
    unixsock_lock(s);
    if (s->conn_q) {    /* listening state */
        if (!queue_empty(s->conn_q)) {
            events |= EPOLLIN;
        }
    } else {
        if (!queue_empty(s->data)) {
            events |= EPOLLIN;
        }
        unixsock peer = s->peer;
        if (peer) {
            refcount_reserve(&peer->refcount);
            unixsock_unlock(s);
            unixsock_lock(peer);
            if (!peer->data)
                events |= (s->sock.type == SOCK_STREAM) ?
                          (EPOLLIN | EPOLLOUT | EPOLLHUP) : EPOLLOUT;
            else if ((peer->sock.rx_len < so_rcvbuf) && !queue_full(peer->data))
                events |= EPOLLOUT;
            unixsock_unlock(peer);
            refcount_release(&peer->refcount);
            return events;
        } else {
            events |= EPOLLOUT;
            if (s->sock.type == SOCK_STREAM)
                events |= EPOLLHUP;
        }
    }
    unixsock_unlock(s);
    return events;
}

closure_function(1, 2, sysreturn, unixsock_ioctl,
                 unixsock, s,
                 unsigned long, request, vlist, ap)
{
    unixsock s = bound(s);
    return socket_ioctl(&s->sock, request, ap);
}

closure_function(1, 2, sysreturn, unixsock_close,
                 unixsock, s,
                 thread, t, io_completion, completion)
{
    unixsock s = bound(s);
    unixsock_lock(s);
    if (s->conn_q) {
        /* Deallocate any sockets in the connection queue. */
        unixsock child;
        while ((child = dequeue(s->conn_q)) != INVALID_ADDRESS) {
            unixsock_lock(child);
            unixsock_dealloc(child);
        }

        deallocate_queue(s->conn_q);
        s->conn_q = 0;
    }
    if (s->fs_entry) {
        filesystem_clear_socket(s->fs, s->fs_entry);
    }
    unixsock_dealloc(s);
    return io_complete(completion, t, 0);
}

static sysreturn unixsock_bind(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    unixsock s = (unixsock) sock;
    struct sockaddr_un *unixaddr = (struct sockaddr_un *) addr;
    unixsock_lock(s);
    sysreturn ret;
    if (s->fs_entry) {
        ret = -EADDRINUSE;
        goto out;
    }

    if (addrlen < sizeof(unixaddr->sun_family)) {
        ret = -EINVAL;
        goto out;
    }

    if (addrlen > sizeof(*unixaddr)) {
        ret = -ENAMETOOLONG;
        goto out;
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
            ret = -ENAMETOOLONG;
            goto out;
        }
        /* TODO: is this string not const? */
        unixaddr->sun_path[term] = '\0';
    }

    process p = current->p;
    s->fs = p->cwd_fs;
    fs_status fss = filesystem_mk_socket(&s->fs, p->cwd, unixaddr->sun_path, s, &s->fs_entry);
    if (fss != FS_STATUS_OK) {
        ret = (fss == FS_STATUS_EXIST) ? -EADDRINUSE : sysreturn_from_fs_status(fss);
        goto out;
    }
    runtime_memcpy(&s->local_addr, addr, addrlen);
    ret = 0;
out:
    unixsock_unlock(s);
    socket_release(sock);
    return ret;
}

static sysreturn unixsock_listen(struct sock *sock, int backlog)
{
    unixsock s = (unixsock) sock;
    sysreturn ret = 0;
    unixsock_lock(s);
    switch (sock->type) {
    case SOCK_STREAM:
        if (!s->conn_q) {
            s->conn_q = allocate_queue(sock->h, backlog);
            if (s->conn_q == INVALID_ADDRESS) {
                msg_err("failed to allocate connection queue\n");
                s->conn_q = 0;
                ret = -ENOMEM;
            }
        }
        break;
    default:
        ret = -EOPNOTSUPP;
    }
    unixsock_unlock(s);
    socket_release(sock);
    return ret;
}

closure_function(3, 1, sysreturn, connect_bh,
                 unixsock, s, thread, t, unixsock, listener,
                 u64, bqflags)
{
    unixsock s = bound(s);
    thread t = bound(t);
    unixsock listener = bound(listener);
    sysreturn rv;

    unixsock_lock(s);
    if (unixsock_is_connected(s)) {
        rv = -EISCONN;
        goto out;
    }
    if ((bqflags & BLOCKQ_ACTION_NULLIFY) && listener->conn_q) {
        rv = -ERESTARTSYS;
        goto out;
    }
    if (!listener->conn_q) {    /* the listening socket has been shut down */
        rv = -ECONNREFUSED;
        goto out;
    }
    if (queue_full(listener->conn_q)) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        unixsock_unlock(s);
        return BLOCKQ_BLOCK_REQUIRED;
    }
    unixsock peer = unixsock_alloc(s->sock.h, s->sock.type, 0);
    if (!peer) {
        rv = -ENOMEM;
        goto out;
    }
    unixsock_conn_internal(s, peer);
    unixsock_conn_internal(peer, s);
    assert(enqueue(listener->conn_q, peer));
    unixsock_notify_reader(listener);
    rv = 0;
out:
    unixsock_unlock(s);
    socket_release(&s->sock);
    syscall_return(t, rv);
    closure_finish();
    return rv;
}

static sysreturn unixsock_connect(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    unixsock s = (unixsock) sock;
    sysreturn rv;

    struct sockaddr_un *unixaddr = (struct sockaddr_un *) addr;
    unixsock listener = 0;
    rv = lookup_socket(&listener, unixaddr->sun_path);
    if (rv != 0)
        goto out;
    switch (s->sock.type) {
    case SOCK_STREAM: {
        blockq_action ba = closure(sock->h, connect_bh, s, current, listener);
        if (ba == INVALID_ADDRESS) {
            rv = -ENOMEM;
            break;
        }
        return blockq_check(listener->sock.txbq, current, ba, false);
    }
    default:
        if (listener->sock.type == s->sock.type) {
            unixsock_lock(s);
            if (s->notify_handle != INVALID_ADDRESS)
                notify_remove(s->peer->sock.f.ns, s->notify_handle, false);
            unixsock_disconnect(s);
            s->notify_handle = notify_add(listener->sock.f.ns, EPOLLOUT | EPOLLERR | EPOLLHUP,
                init_closure(&s->event_handler, unixsock_event_handler, s));
            if (s->notify_handle == INVALID_ADDRESS)
                rv = -ENOMEM;
            else
                unixsock_conn_internal(s, listener);
            unixsock_unlock(s);
        } else {
            rv = -EPROTOTYPE;
        }
    }
out:
    if (listener)
        refcount_release(&listener->refcount);
    socket_release(sock);
    return rv;
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
        rv = -ERESTARTSYS;
        goto out;
    }
    unixsock_lock(s);
    unixsock child = dequeue(s->conn_q);
    boolean empty = queue_empty(s->conn_q);
    unixsock_unlock(s);
    if (child == INVALID_ADDRESS) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    if (empty) {
        fdesc_notify_events(&s->sock.f);
    }
    child->sock.f.flags |= bound(flags);
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
    unixsock_notify_writer(s);
out:
    socket_release(&s->sock);
    syscall_return(t, rv);
    closure_finish();
    return rv;
}

static sysreturn unixsock_accept4(struct sock *sock, struct sockaddr *addr,
        socklen_t *addrlen, int flags)
{
    unixsock s = (unixsock) sock;
    sysreturn rv;
    if (s->sock.type != SOCK_STREAM) {
        rv = -EOPNOTSUPP;
        goto out;
    }
    if (!s->conn_q || (flags & ~(SOCK_NONBLOCK|SOCK_CLOEXEC))) {
        rv = -EINVAL;
        goto out;
    }
    blockq_action ba = closure(sock->h, accept_bh, s, current, addr, addrlen,
            flags);
    return blockq_check(sock->rxbq, current, ba, false);
out:
    socket_release(sock);
    return rv;
}

sysreturn unixsock_sendto(struct sock *sock, void *buf, u64 len, int flags,
        struct sockaddr *dest_addr, socklen_t addrlen)
{
    unixsock s = (unixsock) sock;
    unixsock dest;
    sysreturn rv;
    if (dest_addr || addrlen) {
        if (sock->type == SOCK_STREAM) {
            if (s->peer)
                rv = -EISCONN;
            else
                rv = -EOPNOTSUPP;
            goto out;
        }
        if (!(dest_addr && addrlen)) {
            rv = -EFAULT;
            goto out;
        }
        if (addrlen < sizeof(struct sockaddr_un)) {
            rv = -EINVAL;
            goto out;
        }
        struct sockaddr_un daddr;
        runtime_memcpy(&daddr, dest_addr, sizeof(daddr));
        if (daddr.sun_family != AF_UNIX) {
            rv = -EINVAL;
            goto out;
        }
        daddr.sun_path[sizeof(daddr.sun_path)-1] = 0;
        rv = lookup_socket(&dest, daddr.sun_path);
        if (rv != 0)
            goto out;
    } else {
        unixsock_lock(s);
        dest = s->peer;
        if (dest)
            refcount_reserve(&dest->refcount);
        unixsock_unlock(s);
    }
    if (!dest) {
        rv = -ENOTCONN;
        goto out;
    }
    return unixsock_write_with_addr(s, buf, len, 0, current, false,
        (io_completion)&sock->f.io_complete, dest);
out:
    socket_release(sock);
    return rv;
}

sysreturn unixsock_recvfrom(struct sock *sock, void *buf, u64 len, int flags,
        struct sockaddr *src_addr, socklen_t *addrlen)
{
    if (src_addr || addrlen) {
        if (!(src_addr && addrlen)) {
            socket_release(sock);
            return -EFAULT;
        }
    }
    return unixsock_read_with_addr((unixsock)sock, buf, len, 0, current, false,
        (io_completion)&sock->f.io_complete, src_addr, addrlen);
}

closure_function(2, 2, void, sendmsg_complete,
                 struct sock *, sock, sg_list, sg,
                 thread, t, sysreturn, rv)
{
    sg_list sg = bound(sg);
    deallocate_sg_list(sg);
    socket_release(bound(sock));
    apply(syscall_io_complete, t, rv);
    closure_finish();
}

sysreturn unixsock_sendmsg(struct sock *sock, const struct msghdr *msg,
        int flags)
{
    sg_list sg = allocate_sg_list();
    sysreturn rv;
    if (sg == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    if (!iov_to_sg(sg, msg->msg_iov, msg->msg_iovlen))
        goto err_dealloc_sg;
    io_completion complete = closure(sock->h, sendmsg_complete, sock, sg);
    if (complete == INVALID_ADDRESS)
        goto err_dealloc_sg;
    return apply(sock->f.sg_write, sg, sg->count, 0, current, false, complete);
  err_dealloc_sg:
    deallocate_sg_list(sg);
    rv = -ENOMEM;
  out:
    socket_release(sock);
    return rv;
}

closure_function(4, 2, void, recvmsg_complete,
                 struct sock *, sock, sg_list, sg, struct iovec *, iov, int, iovlen,
                 thread, t, sysreturn, rv)
{
    thread_resume(t);
    sg_list sg = bound(sg);
    sg_to_iov(sg, bound(iov), bound(iovlen));
    deallocate_sg_list(sg);
    socket_release(bound(sock));
    apply(syscall_io_complete, t, rv);
    closure_finish();
}

sysreturn unixsock_recvmsg(struct sock *sock, struct msghdr *msg, int flags)
{
    sg_list sg = allocate_sg_list();
    sysreturn rv;
    if (sg == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    io_completion complete = closure(sock->h, recvmsg_complete, sock, sg,
        msg->msg_iov, msg->msg_iovlen);
    if (complete == INVALID_ADDRESS)
        goto err_dealloc_sg;

    /* Non-connected sockets are not supported, so source address is not set. */
    msg->msg_namelen = 0;

    return apply(sock->f.sg_read, sg,
        iov_total_len(msg->msg_iov, msg->msg_iovlen), 0, current, false,
        complete);
  err_dealloc_sg:
    deallocate_sg_list(sg);
    rv = -ENOMEM;
  out:
    socket_release(sock);
    return rv;
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
    if (socket_init(current->p, h, AF_UNIX, type, flags, &s->sock) < 0) {
        msg_err("failed to initialize socket\n");
        goto err_socket;
    }
    s->sock.f.read = closure(h, unixsock_read, s);
    s->sock.f.write = closure(h, unixsock_write, s);
    s->sock.f.sg_read = closure(h, unixsock_sg_read, s);
    s->sock.f.sg_write = closure(h, unixsock_sg_write, s);
    s->sock.f.events = closure(h, unixsock_events, s);
    s->sock.f.ioctl = closure(h, unixsock_ioctl, s);
    s->sock.f.close = closure(h, unixsock_close, s);
    s->sock.bind = unixsock_bind;
    s->sock.listen = unixsock_listen;
    s->sock.connect = unixsock_connect;
    s->sock.accept4 = unixsock_accept4;
    s->sock.sendto = unixsock_sendto;
    s->sock.recvfrom = unixsock_recvfrom;
    s->sock.sendmsg = unixsock_sendmsg;
    s->sock.recvmsg = unixsock_recvmsg;
    s->fs_entry = 0;
    s->local_addr.sun_family = AF_UNIX;
    s->local_addr.sun_path[0] = '\0';
    s->conn_q = 0;
    s->peer = 0;
    s->notify_handle = INVALID_ADDRESS;
    init_closure(&s->free, unixsock_free, s);
    init_refcount(&s->refcount, 1, (thunk)&s->free);
    s->sock.fd = allocate_fd(current->p, s);
    if (s->sock.fd == INVALID_PHYSICAL) {
        apply(s->sock.f.close, 0, io_completion_ignore);
        return 0;
    }
    return s;
err_socket:
    deallocate_queue(s->data);
err_queue:
    deallocate(h, s, sizeof(*s));
    return 0;
}

sysreturn unixsock_open(int type, int protocol) {
    unix_heaps uh = get_unix_heaps();
    heap h = heap_locked((kernel_heaps)uh);
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
    heap h = heap_locked((kernel_heaps)uh);
    unixsock s1, s2;

    if (domain != AF_UNIX) {
        return set_syscall_error(current, EAFNOSUPPORT);
    }
    if (((type & SOCK_TYPE_MASK) != SOCK_STREAM) &&
            ((type & SOCK_TYPE_MASK) != SOCK_DGRAM)) {
        return -ESOCKTNOSUPPORT;
    }
    if (!validate_user_memory(sv, 2 * sizeof(int), true)) {
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
    refcount_reserve(&s1->refcount);
    refcount_reserve(&s2->refcount);
    sv[0] = s1->sock.fd;
    sv[1] = s2->sock.fd;
    return 0;
}
