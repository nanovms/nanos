#include <unix_internal.h>
#include <filesystem.h>
#include <net_system_structs.h>
#include <socket.h>

typedef struct unixsock_msg {
    buffer b;
    struct sockaddr_un from_addr;
} *unixsock_msg;

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
    closure_struct(file_io, read);
    closure_struct(file_io, write);
    closure_struct(file_iov, readv);
    closure_struct(file_iov, writev);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_ioctl, ioctl);
    closure_struct(fdesc_close, close);
    closure_struct(event_handler, event_handler);
    closure_struct(thunk, free);
    struct refcount refcount;
} *unixsock;

#define unixsock_lock(s)    spin_lock(&(s)->sock.f.lock)
#define unixsock_unlock(s)  spin_unlock(&(s)->sock.f.lock)

static inline void unixsock_msg_dealloc(unixsock_msg shb)
{
    heap h = shb->b->h;
    deallocate_buffer(shb->b);
    deallocate(h, shb, sizeof(*shb));
}

static boolean unixsock_type_is_supported(int type)
{
    switch (type & SOCK_TYPE_MASK) {
    case SOCK_STREAM:
    case SOCK_DGRAM:
    case SOCK_SEQPACKET:
        return true;
    default:
        return false;
    }
}

static boolean unixsock_is_conn_oriented(unixsock s)
{
    return (s->sock.type != SOCK_DGRAM);
}

closure_func_basic(event_handler, u64, unixsock_event_handler,
                   u64 events, void *arg)
{
    unixsock s = struct_from_closure(unixsock, event_handler);
    if (events == NOTIFY_EVENTS_RELEASE)    /* the peer socket is being closed */
        s->notify_handle = INVALID_ADDRESS;
    fdesc_notify_events(&s->sock.f);
    return 0;
}

closure_func_basic(thunk, void, unixsock_free)
{
    unixsock s = struct_from_closure(unixsock, free);
    deallocate(s->sock.h, s, sizeof(*s));
}

static unixsock_msg unixsock_msg_alloc(heap h, u64 len)
{
    unixsock_msg shb = allocate(h, sizeof(*shb));
    if (shb == INVALID_ADDRESS)
        return shb;
    shb->b = allocate_buffer(h, len);
    if (shb->b == INVALID_ADDRESS) {
        deallocate(h, shb, sizeof(*shb));
        return INVALID_ADDRESS;
    }
    return shb;
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

static unixsock unixsock_alloc(heap h, int type, u32 flags, boolean alloc_fd);

/* Called with lock acquired, returns with lock released. */
static void unixsock_dealloc(unixsock s)
{
    deallocate_queue(s->data);
    s->data = 0;
    unixsock_unlock(s);
    unixsock peer = unixsock_is_conn_oriented(s) ? s->peer : 0;
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

static void unixsock_addr_copy(struct sockaddr_un *dest, struct sockaddr_un *src, socklen_t *len)
{
    sstring addr = sstring_from_cstring(src->sun_path, sizeof(src->sun_path));
    socklen_t actual_len = __builtin_offsetof(struct sockaddr_un, sun_path) + addr.len;
    if ((addr.len > 0) && (actual_len < sizeof(struct sockaddr_un)))
        actual_len++;   /* include the string terminator for the path name */
    runtime_memcpy(dest, src, MIN(*len, actual_len));
    *len = actual_len;
}

closure_function(7, 1, sysreturn, unixsock_read_bh,
                 unixsock, s, void *, dest, struct iovec *, iov, u64, length, io_completion, completion, struct sockaddr_un *, from_addr, socklen_t *, from_length,
                 u64 flags)
{
    unixsock s = bound(s);
    void *dest = bound(dest);
    struct iovec *iov = bound(iov);
    u64 length = bound(length);

    unixsock_msg shb;
    sysreturn rv;

    unixsock_lock(s);
    boolean disconnected = unixsock_is_conn_oriented(s) && !(s->peer && s->peer->data);
    boolean read_done = false;
    if ((flags & BLOCKQ_ACTION_NULLIFY) && !disconnected) {
        rv = -ERESTARTSYS;
        goto out;
    }
    context ctx = context_from_closure(closure_self());
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
        return blockq_block_required((unix_context)ctx, flags);
    }
    rv = 0;
    if (context_set_err(ctx)) {
        if (rv == 0)
            rv = -EFAULT;
        else
            read_done = true;
        goto out;
    }
    u64 buf_offset = 0;
    do {
        buffer b = shb->b;
        u64 xfer;
        if (dest) {
            xfer = MIN(buffer_length(b), length);
            buffer_read(b, dest + buf_offset, xfer);
            buf_offset += xfer;
            length -= xfer;
        } else {
            xfer = 0;
            do {
                u64 partial_xfer;
                do {
                    partial_xfer = MIN(buffer_length(b), iov->iov_len - buf_offset);
                    if (partial_xfer == 0) {
                        iov++;
                        length--;
                        buf_offset = 0;
                    }
                } while ((partial_xfer == 0) && length);
                if (!length)
                    break;
                buffer_read(b, iov->iov_base + buf_offset, partial_xfer);
                buf_offset += partial_xfer;
                xfer += partial_xfer;
            } while (buffer_length(b));
        }
        rv += xfer;
        s->sock.rx_len -= xfer;
        if (!buffer_length(b) || (s->sock.type != SOCK_STREAM)) {
            if (s->sock.type == SOCK_DGRAM) {
                struct sockaddr_un *from_addr = bound(from_addr);
                socklen_t *from_length = bound(from_length);
                if (from_addr && from_length) {
                    unixsock_addr_copy(from_addr, &shb->from_addr, from_length);
                }
            }
            assert(dequeue(s->data) == shb);
            s->sock.rx_len -= buffer_length(b);
            unixsock_msg_dealloc(shb);
            shb = queue_peek(s->data);
            if (shb == INVALID_ADDRESS) { /* no more data available to read */
                break;
            }
        }
    } while ((s->sock.type == SOCK_STREAM) && (length > 0));
    context_clear_err(ctx);
    read_done = true;
out:
    unixsock_unlock(s);
    if (read_done)
        unixsock_notify_writer(s);
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

static sysreturn unixsock_read_with_addr(unixsock s, void *dest, u64 length, u64 offset_arg,
                                         context ctx, boolean bh, io_completion completion,
                                         void *addr, socklen_t *addrlen)
{
    if ((s->sock.type == SOCK_STREAM) && (length == 0))
        return io_complete(completion, 0);

    blockq_action ba = closure_from_context(ctx, unixsock_read_bh, s, dest, 0, length,
                                            completion, addr, addrlen);
    return blockq_check(s->sock.rxbq, ba, bh);
}

closure_func_basic(file_io, sysreturn, unixsock_read,
                 void *dest, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, read);
    return unixsock_read_with_addr(s, dest, length, offset_arg, ctx, bh, completion, 0, 0);
}

static sysreturn unixsock_write_check(unixsock s, u64 len)
{
    if ((s->sock.type == SOCK_STREAM) && (len == 0))
        return 0;
    if ((s->sock.type != SOCK_STREAM) && (len > UNIXSOCK_BUF_MAX_SIZE))
        return -EMSGSIZE;
    return 1;   /* any value > 0 will do */
}

static sysreturn unixsock_write_to(void *src, struct iovec *iov, u64 length,
                                   unixsock dest, unixsock from)
{
    if ((dest->sock.rx_len >= so_rcvbuf) || queue_full(dest->data)) {
        return -EAGAIN;
    }

    context ctx = get_current_context(current_cpu());
    u64 buf_offset = 0;
    sysreturn rv = 0;
    do {
        u64 xfer = src ? length : iov_total_len(iov, length);
        xfer = MIN(UNIXSOCK_BUF_MAX_SIZE, xfer);
        if (from->sock.type == SOCK_STREAM)
            xfer = MIN(xfer, so_rcvbuf - dest->sock.rx_len);
        unixsock_msg shb = unixsock_msg_alloc(dest->sock.h, xfer);
        if (shb == INVALID_ADDRESS) {
            if (rv == 0) {
                rv = -ENOMEM;
            }
            break;
        }
        if (from && from->sock.type == SOCK_DGRAM)
            runtime_memcpy(&shb->from_addr, &from->local_addr, sizeof(struct sockaddr_un));
        if (context_set_err(ctx)) {
            unixsock_msg_dealloc(shb);
            if (rv == 0)
                rv = -EFAULT;
            break;
        }
        if (src) {
            assert(buffer_write(shb->b, src + buf_offset, xfer));
            buf_offset += xfer;
            length -= xfer;
        } else {
            u64 xfer_limit = xfer;
            do {
                u64 partial_xfer;
                do {
                    partial_xfer = MIN(xfer_limit, iov->iov_len - buf_offset);
                    if (partial_xfer == 0) {
                        iov++;
                        length--;
                        buf_offset = 0;
                    }
                } while (partial_xfer == 0);
                buffer_write(shb->b, iov->iov_base + buf_offset, partial_xfer);
                buf_offset += partial_xfer;
                xfer_limit -= partial_xfer;
            } while (xfer_limit);
            if (buf_offset == iov->iov_len) {
                iov++;
                length--;
                buf_offset = 0;
            }
        }
        context_clear_err(ctx);
        assert(enqueue(dest->data, shb));
        dest->sock.rx_len += xfer;
        rv += xfer;
    } while ((length > 0) && (dest->sock.rx_len < so_rcvbuf) && !queue_full(dest->data));
    return rv;
}

static sysreturn unixsock_get_path(sstring *path, struct sockaddr *addr, socklen_t addrlen)
{
    if (addrlen <= __builtin_offsetof(struct sockaddr_un, sun_path))
        return -EINVAL;
    if (!fault_in_user_memory(addr, addrlen, false))
        return -EFAULT;
    struct sockaddr_un *unix_addr = (struct sockaddr_un *)addr;
    if (unix_addr->sun_family != AF_UNIX)
        return -EINVAL;
    *path = sstring_from_cstring(unix_addr->sun_path,
                                 addrlen - __builtin_offsetof(struct sockaddr_un, sun_path));
    return 0;
}

static sysreturn lookup_socket(unixsock *s, struct sockaddr *addr, socklen_t addrlen)
{
    sstring path;
    sysreturn rv = unixsock_get_path(&path, addr, addrlen);
    if (rv)
        return rv;
    process p = current->p;
    filesystem fs = p->cwd_fs;
    tuple n;
    int fss = filesystem_get_socket(&fs, p->cwd, path, &n, (void **)s);
    if (fss == -EINVAL)
        return -ECONNREFUSED;
    if (fss == 0) {
        refcount_reserve(&(*s)->refcount);
        filesystem_put_node(fs, n);
    }
    return fss;
}

closure_function(6, 1, sysreturn, unixsock_write_bh,
                 unixsock, s, void *, src, struct iovec *, iov, u64, length, io_completion, completion, unixsock, dest,
                 u64 flags)
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
        rv = unixsock_is_conn_oriented(s) ? -EPIPE : -ECONNREFUSED;
        goto out;
    }

    rv = unixsock_write_to(src, bound(iov), length, dest, s);
    if ((rv == -EAGAIN) && !(s->sock.f.flags & SOCK_NONBLOCK)) {
        unixsock_unlock(dest);
        return blockq_block_required((unix_context)context_from_closure(closure_self()), flags);
    }
    full = (dest->sock.rx_len >= so_rcvbuf) || queue_full(dest->data);
out:
    unixsock_unlock(dest);
    if ((rv > 0) || ((rv == 0) && (dest->sock.type != SOCK_STREAM)))
        unixsock_notify_reader(dest);
    if (full)   /* no more space available to write */
        fdesc_notify_events(&s->sock.f);
    apply(bound(completion), rv);
    refcount_release(&dest->refcount);
    closure_finish();
    return rv;
}

static sysreturn unixsock_write_with_addr(unixsock s, void *src, u64 length, u64 offset, context ctx,
                                          boolean bh, io_completion completion, unixsock addr)
{
    sysreturn rv = unixsock_write_check(s, length);
    if (rv <= 0) {
        refcount_release(&addr->refcount);
        return io_complete(completion, rv);
    }

    blockq_action ba = closure_from_context(ctx, unixsock_write_bh, s, src, 0, length,
                                            completion, addr);
    return blockq_check(addr->sock.txbq, ba, bh);
}

closure_func_basic(file_io, sysreturn, unixsock_write,
                   void *src, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, write);
    unixsock_lock(s);
    unixsock dest = s->peer;
    if (dest)
        refcount_reserve(&dest->refcount);
    unixsock_unlock(s);
    if (!dest)
        return io_complete(completion, -ENOTCONN);
    return unixsock_write_with_addr(s, src, length, offset, ctx, bh, completion, dest);
}

closure_func_basic(file_iov, sysreturn, unixsock_readv,
                   struct iovec *iov, int count, u64 offset, context ctx, boolean bh, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, readv);
    blockq_action ba = closure_from_context(ctx, unixsock_read_bh, s, 0, iov, count,
                                            completion, 0, 0);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, -ENOMEM);
    return blockq_check(s->sock.rxbq, ba, bh);
}

closure_func_basic(file_iov, sysreturn, unixsock_writev,
                   struct iovec *iov, int count, u64 offset, context ctx, boolean bh, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, writev);
    sysreturn rv = unixsock_write_check(s, iov_total_len(iov, count));
    if (rv <= 0)
        return io_complete(completion, rv);
    unixsock_lock(s);
    unixsock dest = s->peer;
    if (dest)
        refcount_reserve(&dest->refcount);
    unixsock_unlock(s);
    if (!dest)
        return io_complete(completion, -ENOTCONN);
    blockq_action ba = closure_from_context(ctx, unixsock_write_bh, s,
                                            0, iov, count, completion, dest);
    if (ba == INVALID_ADDRESS) {
        refcount_release(&dest->refcount);
        return io_complete(completion, -ENOMEM);
    }
    return blockq_check(dest->sock.txbq, ba, bh);
}

closure_func_basic(fdesc_events, u32, unixsock_events,
                   thread t /* ignore */)
{
    unixsock s = struct_from_field(closure_self(), unixsock, events);
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
                events |= unixsock_is_conn_oriented(s) ?
                          (EPOLLIN | EPOLLOUT | EPOLLHUP) : EPOLLOUT;
            else if ((peer->sock.rx_len < so_rcvbuf) && !queue_full(peer->data))
                events |= EPOLLOUT;
            unixsock_unlock(peer);
            refcount_release(&peer->refcount);
            return events;
        } else {
            events |= EPOLLOUT;
            if (unixsock_is_conn_oriented(s))
                events |= EPOLLHUP;
        }
    }
    unixsock_unlock(s);
    return events;
}

closure_func_basic(fdesc_ioctl, sysreturn, unixsock_ioctl,
                   unsigned long request, vlist ap)
{
    unixsock s = struct_from_field(closure_self(), unixsock, ioctl);
    return socket_ioctl(&s->sock, request, ap);
}

closure_func_basic(fdesc_close, sysreturn, unixsock_close,
                   context ctx, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, close);
    unixsock_lock(s);
    if (s->conn_q) {
        /* Deallocate any sockets in the connection queue. */
        unixsock child;
        while ((child = dequeue(s->conn_q)) != INVALID_ADDRESS)
            apply(child->sock.f.close, 0, io_completion_ignore);

        deallocate_queue(s->conn_q);
        s->conn_q = 0;
    }
    if (s->fs_entry) {
        filesystem_clear_socket(s->fs, s->fs_entry);
    }
    unixsock_dealloc(s);
    return io_complete(completion, 0);
}

static sysreturn unixsock_bind(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    unixsock s = (unixsock) sock;
    unixsock_lock(s);
    sysreturn ret;
    if (s->fs_entry) {
        ret = -EADDRINUSE;
        goto out;
    }

    sstring path;
    ret = unixsock_get_path(&path, addr, addrlen);
    if (ret)
        goto out;

    process p = current->p;
    s->fs = p->cwd_fs;
    int fss = filesystem_mk_socket(&s->fs, p->cwd, path, s, &s->fs_entry);
    if (fss != 0) {
        ret = (fss == -EEXIST) ? -EADDRINUSE : fss;
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
    case SOCK_SEQPACKET:
        if (!s->conn_q) {
            s->conn_q = allocate_queue(sock->h, backlog);
            if (s->conn_q == INVALID_ADDRESS) {
                msg_err("%s: failed to allocate connection queue", func_ss);
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
                 u64 bqflags)
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
        return blockq_block_required(&t->syscall->uc, bqflags);
    }
    unixsock peer = unixsock_alloc(s->sock.h, s->sock.type, 0, false);
    if (!peer) {
        rv = -ENOMEM;
        goto out;
    }
    unixsock_conn_internal(s, peer);
    unixsock_conn_internal(peer, s);
    assert(enqueue(listener->conn_q, peer));
    rv = 0;
out:
    unixsock_unlock(s);
    if (rv == 0)
        unixsock_notify_reader(listener);
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

    unixsock listener = 0;
    rv = lookup_socket(&listener, addr, addrlen);
    if (rv != 0)
        goto out;
    if (listener->sock.type != s->sock.type) {
        rv = -EPROTOTYPE;
        goto out;
    }
    if (unixsock_is_conn_oriented(s)) {
        blockq_action ba = contextual_closure(connect_bh, s, current, listener);
        if (ba == INVALID_ADDRESS)
            rv = -ENOMEM;
        return blockq_check(listener->sock.txbq, ba, false);
    } else {
        if (s->notify_handle != INVALID_ADDRESS)
            notify_remove(s->peer->sock.f.ns, s->notify_handle, false);
        unixsock_lock(s);
        unixsock_disconnect(s);
        s->notify_handle = notify_add(listener->sock.f.ns, EPOLLOUT | EPOLLERR | EPOLLHUP,
                                      init_closure_func(&s->event_handler, event_handler,
                                                        unixsock_event_handler));
        if (s->notify_handle == INVALID_ADDRESS)
            rv = -ENOMEM;
        else
            unixsock_conn_internal(s, listener);
        unixsock_unlock(s);
    }
out:
    if (listener)
        refcount_release(&listener->refcount);
    socket_release(sock);
    return rv;
}

closure_function(5, 1, sysreturn, accept_bh,
                 unixsock, s, struct sockaddr *, addr, socklen_t *, addrlen, int, flags, io_completion, completion,
                 u64 bqflags)
{
    unixsock s = bound(s);
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
    context ctx = context_from_closure(closure_self());
    if (child == INVALID_ADDRESS) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return blockq_block_required((unix_context)ctx, bqflags);
    }

    process p = is_syscall_context(ctx) ? ((syscall_context)ctx)->t->p : ((process_context)ctx)->p;
    child->sock.fd = allocate_fd(p, child);
    if (child->sock.fd == INVALID_PHYSICAL) {
        apply(child->sock.f.close, 0, io_completion_ignore);
        rv = -ENFILE;
        goto out;
    }

    if (empty) {
        fdesc_notify_events(&s->sock.f);
    }
    child->sock.f.flags |= bound(flags);
    rv = child->sock.fd;
    if (addr) {
        if (context_set_err(ctx)) {
            rv = -EFAULT;
            goto out;
        }
        unixsock_addr_copy((struct sockaddr_un *)addr, &child->peer->local_addr, bound(addrlen));
        context_clear_err(ctx);
    }
    unixsock_notify_writer(s);
out:
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

static sysreturn unixsock_accept4(struct sock *sock, struct sockaddr *addr,
                                  socklen_t *addrlen, int flags, context ctx, boolean in_bh,
                                  io_completion completion)
{
    unixsock s = (unixsock) sock;
    sysreturn rv;
    if (!unixsock_is_conn_oriented(s)) {
        rv = -EOPNOTSUPP;
        goto out;
    }
    if (!s->conn_q || (flags & ~SOCK_FLAGS_MASK)) {
        rv = -EINVAL;
        goto out;
    }
    blockq_action ba = closure_from_context(ctx, accept_bh, s, addr, addrlen, flags, completion);
    if (ba == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    return blockq_check(sock->rxbq, ba, in_bh);
out:
    return io_complete(completion, rv);
}

static sysreturn unixsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    unixsock s = (unixsock)sock;
    unixsock_lock(s);
    unixsock_addr_copy((struct sockaddr_un *)addr, &s->local_addr, addrlen);
    unixsock_unlock(s);
    socket_release(sock);
    return 0;
}

static sysreturn unixsock_setsockopt(struct sock *sock, int level,
                                     int optname, void *optval, socklen_t optlen)
{
    sysreturn rv;
    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_REUSEADDR:
            rv = 0; /* to mimic Linux behavior, return 0 even if not actually implemented */
            break;
        default:
            rv = -EOPNOTSUPP;
        }
        break;
    default:
        rv = -EOPNOTSUPP;
    }
    socket_release(sock);
    return rv;
}

static sysreturn unixsock_getsockopt(struct sock *sock, int level,
                                     int optname, void *optval, socklen_t *optlen)
{
    sysreturn rv;
    union {
        int val;
        struct linger {
            int l_onoff;
            int l_linger;
        } linger;
    } ret_optval;
    int ret_optlen;

    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_TYPE:
            ret_optval.val = sock->type;
            ret_optlen = sizeof(ret_optval.val);
            break;
        default:
            goto unimplemented;
        }
        break;
    default:
        goto unimplemented;
    }
    rv = sockopt_copy_to_user(optval, optlen, &ret_optval, ret_optlen);
    goto out;
unimplemented:
    msg_err("getsockopt unimplemented: fd %d, level %d, optname %d",
            sock->fd, level, optname);
    rv = -ENOPROTOOPT;
out:
    socket_release(sock);
    return rv;
}

sysreturn unixsock_sendto(struct sock *sock, void *buf, u64 len, int flags,
                          struct sockaddr *dest_addr, socklen_t addrlen, context ctx,
                          boolean in_bh, io_completion completion)
{
    unixsock s = (unixsock) sock;
    unixsock dest;
    sysreturn rv;
    /* Linux ignores destination address in SEQPACKET sockets. */
    if ((sock->type != SOCK_SEQPACKET) && (dest_addr || addrlen)) {
        if (sock->type == SOCK_STREAM) {
            if (s->peer)
                rv = -EISCONN;
            else
                rv = -EOPNOTSUPP;
            goto out;
        }
        rv = lookup_socket(&dest, dest_addr, addrlen);
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
    return unixsock_write_with_addr(s, buf, len, 0, ctx, in_bh, completion, dest);
out:
    return io_complete(completion, rv);
}

sysreturn unixsock_recvfrom(struct sock *sock, void *buf, u64 len, int flags,
                            struct sockaddr *src_addr, socklen_t *addrlen, context ctx,
                            boolean in_bh, io_completion completion)
{
    if (src_addr || addrlen) {
        if (!(src_addr && addrlen)) {
            return io_complete(completion, -EFAULT);
        }
    }
    return unixsock_read_with_addr((unixsock)sock, buf, len, 0, ctx, in_bh, completion,
                                   src_addr, addrlen);
}

sysreturn unixsock_sendmsg(struct sock *sock, const struct msghdr *msg,
                           int flags, boolean in_bh, io_completion completion)
{
    context ctx = get_current_context(current_cpu());
    return apply(sock->f.writev, msg->msg_iov, msg->msg_iovlen, 0, ctx, in_bh, completion);
}

sysreturn unixsock_recvmsg(struct sock *sock, struct msghdr *msg, int flags, boolean in_bh,
                           io_completion completion)
{
    blockq_action ba = contextual_closure(unixsock_read_bh, (unixsock)sock,
                                          0, msg->msg_iov, msg->msg_iovlen,
                                          completion, msg->msg_name, &msg->msg_namelen);
    if (ba == INVALID_ADDRESS) {
        return io_complete(completion, -ENOMEM);
    }
    return blockq_check(sock->rxbq, ba, in_bh);
}

static unixsock unixsock_alloc(heap h, int type, u32 flags, boolean alloc_fd)
{
    unixsock s = allocate(h, sizeof(*s));
    if (s == INVALID_ADDRESS) {
        msg_err("unixsock: failed to allocate socket structure");
        return 0;
    }
    s->data = allocate_queue(h, UNIXSOCK_QUEUE_MAX_LEN);
    if (s->data == INVALID_ADDRESS) {
        msg_err("unixsock: failed to allocate data buffer");
        goto err_queue;
    }
    if (socket_init(h, AF_UNIX, type, flags, &s->sock) < 0) {
        msg_err("unixsock: failed to initialize socket");
        goto err_socket;
    }
    s->sock.f.read = init_closure_func(&s->read, file_io, unixsock_read);
    s->sock.f.write = init_closure_func(&s->write, file_io, unixsock_write);
    s->sock.f.readv = init_closure_func(&s->readv, file_iov, unixsock_readv);
    s->sock.f.writev = init_closure_func(&s->writev, file_iov, unixsock_writev);
    s->sock.f.events = init_closure_func(&s->events, fdesc_events, unixsock_events);
    s->sock.f.ioctl = init_closure_func(&s->ioctl, fdesc_ioctl, unixsock_ioctl);
    s->sock.f.close = init_closure_func(&s->close, fdesc_close, unixsock_close);
    s->sock.bind = unixsock_bind;
    s->sock.listen = unixsock_listen;
    s->sock.connect = unixsock_connect;
    s->sock.accept4 = unixsock_accept4;
    s->sock.getsockname = unixsock_getsockname;
    s->sock.setsockopt = unixsock_setsockopt;
    s->sock.getsockopt = unixsock_getsockopt;
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
    init_closure_func(&s->free, thunk, unixsock_free);
    init_refcount(&s->refcount, 1, (thunk)&s->free);
    if (alloc_fd) {
        s->sock.fd = allocate_fd(current->p, s);
        if (s->sock.fd == INVALID_PHYSICAL) {
            apply(s->sock.f.close, 0, io_completion_ignore);
            return 0;
        }
    } else {
        s->sock.fd = -1;
    }
    return s;
err_socket:
    deallocate_queue(s->data);
err_queue:
    deallocate(h, s, sizeof(*s));
    return 0;
}

sysreturn unixsock_open(int type, int protocol) {
    heap h = heap_locked(get_kernel_heaps());
    unixsock s;

    if (!unixsock_type_is_supported(type))
        return -ESOCKTNOSUPPORT;
    s = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK, true);
    if (!s) {
        return -ENOMEM;
    }
    return s->sock.fd;
}

sysreturn socketpair(int domain, int type, int protocol, int sv[2]) {
    heap h = heap_locked(get_kernel_heaps());
    unixsock s1, s2;

    if (domain != AF_UNIX) {
        return set_syscall_error(current, EAFNOSUPPORT);
    }
    if (!unixsock_type_is_supported(type))
        return -ESOCKTNOSUPPORT;
    if (!fault_in_user_memory(sv, 2 * sizeof(int), true))
        return -EFAULT;
    s1 = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK, true);
    if (!s1) {
        return -ENOMEM;
    }
    s2 = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK, true);
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
