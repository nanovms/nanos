#include <net_system_structs.h>
#include <unix_internal.h>
#include <socket.h>

#include "vsock.h"
#include <virtio/virtio_socket.h>

#define VSOCK_PORT_LAST_PRIVILEGED  1023

//#define VSOCK_DEBUG
#ifdef VSOCK_DEBUG
#define vsock_debug(x, ...) do {tprintf(sym(vsock), 0, ss(x "\n"), ##__VA_ARGS__);} while(0)
#else
#define vsock_debug(x, ...)
#endif

static struct {
    heap h;
    void *transport;
    table bound;
    table connections;
    struct spinlock lock;
} vsock_priv;

typedef struct vsock {
    struct sock sock;
    closure_struct(file_io, read);
    closure_struct(file_io, write);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_close, close);
    enum {
        VSOCK_STATE_INIT,
        VSOCK_STATE_BOUND,
        VSOCK_STATE_LISTEN,
        VSOCK_STATE_CONNECTING,
        VSOCK_STATE_CONNECTED,
    } state;
    struct vsock_bound *bound;
    vsock_connection conn;
    u32 local_port;
    int listen_backlog;
    int so_error;
    int flags;
    ringbuf incoming;
} *vsock;

declare_closure_struct(0, 0, void, vsock_bound_free);
typedef struct vsock_bound {
    vsock s;
    u32 cid;
    struct refcount refc;
    closure_struct(vsock_bound_free, free);
    struct spinlock lock;
} *vsock_bound;

typedef struct vsock_rxbuf {
    void *data;
    u64 len;
    u64 offset;
} *vsock_rxbuf;

#define vsock_lock(s)   spin_lock(&(s)->sock.f.lock)
#define vsock_unlock(s) spin_unlock(&(s)->sock.f.lock)

static sysreturn vsock_addr_check(struct sockaddr_vm *addr, socklen_t addrlen)
{
    if (!fault_in_memory(addr, addrlen))
        return -EFAULT;
    if ((addrlen != sizeof(*addr)) || (addr->svm_family != AF_VSOCK) || (addr->svm_rsvd != 0))
        return -EINVAL;
    return 0;
}

define_closure_function(0, 0, void, vsock_bound_free)
{
    vsock_bound bound = struct_from_field(closure_self(), vsock_bound, free);
    deallocate(vsock_priv.h, bound, sizeof(*bound));
}

static boolean vsock_add_bound(vsock_bound bound, u32 port)
{
    spin_lock(&vsock_priv.lock);
    boolean success = table_set_noreplace(vsock_priv.bound, pointer_from_u64((u64)port), bound);
    spin_unlock(&vsock_priv.lock);
    return success;
}

static sysreturn vsock_bind_internal(vsock s, u32 cid, u32 port)
{
    vsock_debug("bind to %d:%d", cid, port);
    if (cid != VMADDR_CID_ANY) {
        if (!vsock_priv.transport)
            return -EADDRNOTAVAIL;
        u32 guest_cid = virtio_sock_get_guest_cid(vsock_priv.transport);
        if (cid != guest_cid)
            return -EADDRNOTAVAIL;
    }
    vsock_bound bound = allocate(vsock_priv.h, sizeof(*bound));
    if (bound == INVALID_ADDRESS)
        return -ENOMEM;
    bound->s = s;
    bound->cid = cid;
    init_refcount(&bound->refc, 1, init_closure(&bound->free, vsock_bound_free));
    spin_lock_init(&bound->lock);
    if (port == VMADDR_PORT_ANY) {
        for (u32 p = VSOCK_PORT_LAST_PRIVILEGED + 1; p != 0; p++) {
            if (vsock_add_bound(bound, p)) {
                port = p;
                s->state = VSOCK_STATE_BOUND;
                break;
            }
        }
    } else if (vsock_add_bound(bound, port)) {
        s->state = VSOCK_STATE_BOUND;
    }
    if (s->state == VSOCK_STATE_BOUND) {
        vsock_debug("  bound to port %d", port);
        s->local_port = port;
        s->bound = bound;
        return 0;
    }
    refcount_release(&bound->refc);
    return (port == VMADDR_PORT_ANY) ? -EADDRNOTAVAIL : -EADDRINUSE;
}

static u64 vsock_conn_key(void *x)
{
    struct vsock_conn_id *id = x;
    u64 key = id->peer_cid;
    return (key << 32) | (id->local_port ^ id->peer_port);
}

static boolean vsock_conn_equals(void *x, void *y)
{
    struct vsock_conn_id *idx = x;
    struct vsock_conn_id *idy = y;
    return (idx->local_port == idy->local_port) &&
           (idx->peer_cid == idy->peer_cid) && (idx->peer_port == idy->peer_port);
}

static void vsock_add_connection(vsock_connection conn)
{
    spin_lock(&vsock_priv.lock);
    table_set(vsock_priv.connections, &conn->id, conn);
    refcount_reserve(&conn->refc);
    spin_unlock(&vsock_priv.lock);
}

/* Must be called with connection locked. */
static void vsock_remove_connection(vsock_connection conn)
{
    spin_lock(&vsock_priv.lock);
    table_set(vsock_priv.connections, &conn->id, 0);
    vsock_bound bound = conn->bound;
    if (bound) {
        table_set(vsock_priv.bound, pointer_from_u64((u64)conn->id.local_port), 0);
        refcount_release(&bound->refc);
        conn->bound = 0;
    }
    spin_unlock(&vsock_priv.lock);
    refcount_release(&conn->refc);
}

static vsock_connection vsock_get_connection(struct vsock_conn_id *id)
{
    spin_lock(&vsock_priv.lock);
    vsock_connection conn = table_find(vsock_priv.connections, id);
    if (conn)
        refcount_reserve(&conn->refc);
    spin_unlock(&vsock_priv.lock);
    return conn;
}

closure_function(4, 1, sysreturn, vsock_read_bh,
                 vsock, s, void *, dest, u64, length, io_completion, completion,
                 u64, bqflags)
{
    vsock s = bound(s);
    void *dest = bound(dest);
    u64 length = bound(length);
    boolean notify = false;
    sysreturn rv;
    vsock_lock(s);
    vsock_debug("reading (state %d incoming %ld)", s->state, ringbuf_length(s->incoming));
    if (s->state != VSOCK_STATE_CONNECTED) {
        rv = -ENOTCONN;
        goto out;
    }
    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }
    struct vsock_rxbuf rxbuf;
    context ctx = context_from_closure(closure_self());
    if (!ringbuf_peek(s->incoming, &rxbuf, sizeof(rxbuf))) {
        if (s->flags & VSOCK_SHUTDOWN_RX) {
            rv = 0;
            goto out;
        }
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        vsock_unlock(s);
        return blockq_block_required((unix_context)ctx, bqflags);
    }
    rv = 0;
    if (context_set_err(ctx)) {
        if (rv == 0)
            rv = -EFAULT;
        goto out;
    }
    do {
        u64 xfer = rxbuf.len - rxbuf.offset;
        if (length < xfer)
            xfer = length;
        runtime_memcpy(dest, rxbuf.data + rxbuf.offset, xfer);
        dest += xfer;
        length -= xfer;
        rv += xfer;
        rxbuf.offset += xfer;
        if (rxbuf.offset == rxbuf.len) {
            ringbuf_consume(s->incoming, sizeof(rxbuf));
            virtio_sock_free_rxbuf(vsock_priv.transport, rxbuf.data);
            if (!ringbuf_peek(s->incoming, &rxbuf, sizeof(rxbuf))) {
                notify = true;  /* reset EPOLLIN event */
                break;
            }
        } else {
            ringbuf_overwrite(s->incoming, offsetof(vsock_rxbuf, offset),
                              &rxbuf.offset, sizeof(rxbuf.offset));
        }
    } while (length > 0);
    context_clear_err(ctx);
  out:
    vsock_unlock(s);
    if (notify)
        fdesc_notify_events(&s->sock.f);
    apply(bound(completion), rv);
    closure_finish();
    if (rv > 0) {
        vsock_connection conn = s->conn;
        vsock_conn_lock(conn);
        virtio_sock_recved(conn, rv);
        vsock_conn_unlock(conn);
    }
    return rv;
}

closure_func_basic(file_io, sysreturn, vsock_read,
                   void *dest, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    if (length == 0)
        return io_complete(completion, 0);
    vsock s = struct_from_field(closure_self(), vsock, read);
    blockq_action ba = closure_from_context(ctx, vsock_read_bh, s, dest, length, completion);
    return blockq_check(s->sock.rxbq, ba, bh);
}

closure_function(4, 1, sysreturn, vsock_write_bh,
                 vsock, s, void *, src, u64, length, io_completion, completion,
                 u64, bqflags)
{
    vsock s = bound(s);
    void *src = bound(src);
    u64 length = bound(length);
    u64 buf_space;
    sysreturn rv;
    vsock_connection conn = s->conn;
    if (conn) {
        vsock_conn_lock(conn);
        buf_space = virtio_sock_get_buf_space(conn);
        vsock_conn_unlock(conn);
    } else {
        buf_space = 0;
    }
    vsock_lock(s);
    if (s->state != VSOCK_STATE_CONNECTED) {
        rv = -ENOTCONN;
        goto unlock_out;
    }
    if (s->flags & VSOCK_SHUTDOWN_TX) {
        rv = -EPIPE;
        goto unlock_out;
    }
    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto unlock_out;
    }
    context ctx = context_from_closure(closure_self());
    if (buf_space == 0) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto unlock_out;
        }
        vsock_unlock(s);
        return blockq_block_required((unix_context)ctx, bqflags);
    }
    if (buf_space < length)
        length = buf_space;
    void *txbuf = virtio_sock_alloc_txbuf(vsock_priv.transport, length);
    if (txbuf == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto unlock_out;
    }
    if (context_set_err(ctx)) {
        virtio_sock_free_txbuf(vsock_priv.transport, txbuf);
        rv = -EFAULT;
        goto unlock_out;
    }
    runtime_memcpy(txbuf, src, length);
    context_clear_err(ctx);
    vsock_unlock(s);
    vsock_conn_lock(conn);
    rv = virtio_sock_tx(conn, txbuf) ? length : -ENOMEM;
    vsock_conn_unlock(conn);
    goto out;
unlock_out:
    vsock_unlock(s);
out:
    if ((rv > 0) && (length == buf_space))
        fdesc_notify_events(&s->sock.f);    /* reset EPOLLOUT event */
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

closure_func_basic(file_io, sysreturn, vsock_write,
                   void *src, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    if (length == 0)
        return io_complete(completion, 0);
    vsock s = struct_from_field(closure_self(), vsock, write);
    blockq_action ba = closure_from_context(ctx, vsock_write_bh, s, src, length, completion);
    return blockq_check(s->sock.txbq, ba, bh);
}

static u32 vsock_events_internal(vsock s)
{
    u32 events;
    vsock_lock(s);
    switch (s->state) {
    case VSOCK_STATE_INIT:
    case VSOCK_STATE_BOUND:
        events = EPOLLIN | EPOLLOUT;
        break;
    case VSOCK_STATE_LISTEN:
    case VSOCK_STATE_CONNECTED:
        events = (ringbuf_length(s->incoming) > 0) ? EPOLLIN : 0;
        if (s->state == VSOCK_STATE_CONNECTED) {
            if ((virtio_sock_get_buf_space(s->conn) > 0) || (s->flags & VSOCK_SHUTDOWN_TX))
                events |= EPOLLOUT;
            if (s->flags & VSOCK_SHUTDOWN_RX)
                events |= EPOLLIN | EPOLLRDHUP;
        }
        break;
    default:
        events = 0;
    }
    if (s->so_error)
        events |= EPOLLERR;
    vsock_unlock(s);
    return events;
}

closure_func_basic(fdesc_events, u32, vsock_events,
                   thread t)
{
    vsock s = struct_from_field(closure_self(), vsock, events);
    u32 events = vsock_events_internal(s);
    return events;
}

closure_func_basic(fdesc_close, sysreturn, vsock_close,
                   context ctx, io_completion completion)
{
    vsock s = struct_from_field(closure_self(), vsock, close);
    if (s->state >= VSOCK_STATE_BOUND) {
        vsock_bound bound = s->bound;
        if (bound) {
            spin_lock(&bound->lock);
            bound->s = 0;
            spin_unlock(&bound->lock);
        }
        switch (s->state) {
        case VSOCK_STATE_LISTEN: {
            spin_lock(&vsock_priv.lock);
            table_set(vsock_priv.bound, pointer_from_u64((u64)s->local_port), 0);
            spin_unlock(&vsock_priv.lock);
            refcount_release(&bound->refc);
            vsock child;
            while (ringbuf_read(s->incoming, &child, sizeof(child)))
                apply(child->sock.f.close, 0, io_completion_ignore);
            break;
        }
        case VSOCK_STATE_CONNECTED: {
            vsock_connection conn = s->conn;
            vsock_conn_lock(conn);
            conn->vsock = 0;
            conn->bound = bound;
            int shutdown_flags = VSOCK_SHUTDOWN_TX | VSOCK_SHUTDOWN_RX;
            if ((s->flags & shutdown_flags) != shutdown_flags) {
                if (!virtio_sock_shutdown(conn, shutdown_flags))
                    vsock_remove_connection(conn);
            }
            vsock_conn_unlock(conn);
            vsock_conn_release(conn);
            struct vsock_rxbuf rxbuf;
            while (ringbuf_read(s->incoming, &rxbuf, sizeof(rxbuf)))
                virtio_sock_free_rxbuf(vsock_priv.transport, rxbuf.data);
            break;
        }
        default:
            break;
        }
    }
    socket_deinit(&s->sock);
    deallocate_ringbuf(s->incoming);
    deallocate(s->sock.h, s, sizeof(*s));
    return io_complete(completion, 0);
}

static sysreturn vsock_bind(struct sock *sock, struct sockaddr *addr, socklen_t addrlen)
{
    vsock s = (vsock)sock;
    struct sockaddr_vm *vsock_addr = (struct sockaddr_vm *)addr;
    vsock_lock(s);
    sysreturn rv = vsock_addr_check(vsock_addr, addrlen);
    if (rv < 0)
        goto out;
    if (s->state != VSOCK_STATE_INIT) {
        rv = -EINVAL;
        goto out;
    }
    rv = vsock_bind_internal(s, vsock_addr->svm_cid, vsock_addr->svm_port);
  out:
    vsock_unlock(s);
    socket_release(sock);
    return rv;
}

static sysreturn vsock_listen(struct sock *sock, int backlog)
{
    vsock s = (vsock)sock;
    sysreturn rv;
    vsock_lock(s);
    if (s->state == VSOCK_STATE_BOUND) {
        s->state = VSOCK_STATE_LISTEN;
    } else if (s->state != VSOCK_STATE_LISTEN) {
        rv = -EINVAL;
        goto out;
    }
    s->listen_backlog = MAX(backlog, 1);
    rv = 0;
  out:
    vsock_unlock(s);
    socket_release(sock);
    return rv;
}

closure_function(3, 1, sysreturn, vsock_connect_bh,
                 vsock, s, u32, peer_cid, u32, peer_port,
                 u64, bqflags)
{
    vsock s = bound(s);
    u32 peer_cid = bound(peer_cid);
    u32 peer_port = bound(peer_port);
    syscall_context ctx = (syscall_context)context_from_closure(closure_self());
    sysreturn rv;
    if (!(bqflags & BLOCKQ_ACTION_BLOCKED)) {
        vsock_connection conn = s->conn;
        if (!conn) {
            if (!vsock_priv.transport) {
                rv = -ENETUNREACH;
                goto out;
            }
            conn = virtio_sock_conn_new(vsock_priv.transport, s->local_port, peer_cid, peer_port,
                                        so_rcvbuf);
            if (conn == INVALID_ADDRESS) {
                rv = -ENOMEM;
                goto out;
            }
            conn->vsock = s;
            s->conn = conn;
        }
        if (!virtio_sock_connect(conn)) {
            rv = -ENOMEM;
            goto out;
        }
        vsock_add_connection(conn);
        s->state = VSOCK_STATE_CONNECTING;
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EINPROGRESS;
            goto out;
        }
        vsock_unlock(s);
        return blockq_block_required(&ctx->uc, bqflags);
    } else {
        if (bqflags & BLOCKQ_ACTION_NULLIFY) {
            vsock_connection conn = s->conn;
            vsock_conn_lock(conn);
            virtio_sock_connect_abort(conn);
            vsock_remove_connection(conn);
            vsock_conn_unlock(conn);
        }
        vsock_lock(s);
        if (bqflags & BLOCKQ_ACTION_NULLIFY) {
            s->state = VSOCK_STATE_BOUND;
            rv = -ERESTARTSYS;
        } else if (s->state != VSOCK_STATE_CONNECTING) {
            rv = -s->so_error;
            s->so_error = 0;
        } else {
            vsock_unlock(s);
            return blockq_block_required(&ctx->uc, bqflags);
        }
    }
  out:
    vsock_unlock(s);
    closure_finish();
    socket_release(&s->sock);
    syscall_return(ctx->t, rv);
    return rv;
}

static sysreturn vsock_connect(struct sock *sock, struct sockaddr *addr, socklen_t addrlen)
{
    vsock s = (vsock)sock;
    struct sockaddr_vm *vsock_addr = (struct sockaddr_vm *)addr;
    sysreturn rv = vsock_addr_check(vsock_addr, addrlen);
    if (rv < 0)
        goto out;
    vsock_lock(s);
    switch (s->state) {
    case VSOCK_STATE_INIT:
        rv = vsock_bind_internal(s, VMADDR_CID_ANY, VMADDR_PORT_ANY);
        if (rv < 0)
            goto unlock_out;
        /* no break */
    case VSOCK_STATE_BOUND:
        break;
    case VSOCK_STATE_CONNECTING:
        rv = -EALREADY;
        goto unlock_out;
    case VSOCK_STATE_CONNECTED:
        rv = -EISCONN;
        goto unlock_out;
    default:
        rv = -EINVAL;
        goto unlock_out;
    }
    blockq_action ba = contextual_closure(vsock_connect_bh, s,
                                          vsock_addr->svm_cid, vsock_addr->svm_port);
    if (ba == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto unlock_out;
    }
    return blockq_check(s->sock.txbq, ba, false);
  unlock_out:
    vsock_unlock(s);
  out:
    socket_release(sock);
    return rv;
}

closure_function(4, 1, sysreturn, vsock_accept_bh,
                 vsock, s, struct sockaddr *, addr, socklen_t *, addrlen, int, flags,
                 u64, bqflags)
{
    vsock s = bound(s);
    sysreturn rv;
    context ctx = context_from_closure(closure_self());
    thread t = ((syscall_context)ctx)->t;
    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }
    vsock_lock(s);
    vsock child;
    boolean dequeued = ringbuf_read(s->incoming, &child, sizeof(child));
    boolean empty = (ringbuf_length(s->incoming) == 0);
    vsock_unlock(s);
    vsock_debug("accept_bh: dequeued %d", dequeued);
    if (!dequeued) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return blockq_block_required(&((syscall_context)ctx)->uc, bqflags);
    }
    child->sock.fd = allocate_fd(t->p, child);
    if (child->sock.fd == INVALID_PHYSICAL) {
        apply(child->sock.f.close, 0, io_completion_ignore);
        rv = -ENFILE;
        goto out;
    }
    child->sock.f.flags |= bound(flags);
    rv = child->sock.fd;
    struct sockaddr *addr = bound(addr);
    if (addr) {
        struct sockaddr_vm peer_addr = {
            .svm_family = AF_VSOCK,
            .svm_rsvd = 0,
            .svm_port = child->conn->id.peer_port,
            .svm_cid = child->conn->id.peer_cid,
        };
        zero(peer_addr.svm_zero, sizeof(peer_addr.svm_zero));
        if (context_set_err(ctx)) {
            apply(child->sock.f.close, 0, io_completion_ignore);
            rv = -EFAULT;
            goto out;
        }
        socklen_t *addrlen = bound(addrlen);
        socklen_t min_len = MIN(*addrlen, sizeof(peer_addr));
        runtime_memcpy(addr, &peer_addr, min_len);
        *addrlen = sizeof(peer_addr);
        context_clear_err(ctx);
    }
    if (empty)
        fdesc_notify_events(&s->sock.f);    /* reset EPOLLIN event */
  out:
    closure_finish();
    socket_release(&s->sock);
    syscall_return(t, rv);
    return rv;
}

static sysreturn vsock_accept4(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen,
                               int flags)
{
    vsock s = (vsock)sock;
    sysreturn rv;
    if ((s->state != VSOCK_STATE_LISTEN) || (flags & ~SOCK_FLAGS_MASK)) {
        rv = -EINVAL;
        goto out;
    }
    blockq_action ba = contextual_closure(vsock_accept_bh, s, addr, addrlen, flags);
    if (ba == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    return blockq_check(sock->rxbq, ba, false);
out:
    socket_release(sock);
    return rv;
}

static sysreturn vsock_sendto(struct sock *sock, void *buf, u64 len, int flags,
                              struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (dest_addr || addrlen) {
        vsock s = (vsock)sock;
        sysreturn rv = (s->state == VSOCK_STATE_CONNECTED) ? -EISCONN : -EOPNOTSUPP;
        socket_release(sock);
        return rv;
    }
    return apply(sock->f.write, buf, len, infinity, get_current_context(current_cpu()), false,
                 (io_completion)&sock->f.io_complete);
}

static sysreturn vsock_recvfrom(struct sock *sock, void *buf, u64 len, int flags,
                                struct sockaddr *src_addr, socklen_t *addrlen)
{
    return apply(sock->f.read, buf, len, infinity, get_current_context(current_cpu()), false,
                 (io_completion)&sock->f.io_complete);
}

static sysreturn vsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    vsock s = (vsock)sock;
    struct sockaddr_vm local_addr = {
        .svm_family = AF_VSOCK,
        .svm_rsvd = 0,
        .svm_zero = {0},
    };
    socklen_t len = sizeof(local_addr);
    vsock_lock(s);
    local_addr.svm_cid = s->bound ? s->bound->cid : VMADDR_CID_ANY;
    local_addr.svm_port = s->local_port;
    vsock_unlock(s);
    runtime_memcpy(addr, &local_addr, MIN(len, *addrlen));
    *addrlen = len;
    socket_release(sock);
    return 0;
}

static sysreturn vsock_getsockopt(struct sock *sock, int level, int optname, void *optval,
                                  socklen_t *optlen)
{
    vsock s = (vsock)sock;
    sysreturn rv;
    int ret_optval;
    int ret_optlen = sizeof(ret_optval);
    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_TYPE:
            ret_optval = s->sock.type;
            break;
        case SO_ERROR:
            ret_optval = __atomic_exchange_n(&s->so_error, 0, __ATOMIC_RELAXED);
            break;
        case SO_SNDBUF:
            ret_optval = 0;
            break;
        case SO_RCVBUF:
            ret_optval = so_rcvbuf;
            break;
        case SO_ACCEPTCONN:
            ret_optval = (s->state == VSOCK_STATE_LISTEN);
            break;
        default:
            rv = -EOPNOTSUPP;
            goto out;
        }
        break;
    default:
        rv = -EOPNOTSUPP;
        goto out;
    }
    rv = sockopt_copy_to_user(optval, optlen, &ret_optval, ret_optlen);
  out:
    socket_release(sock);
    return rv;
}

static sysreturn vsock_alloc(heap h, int type, int flags, boolean alloc_fd, vsock *sp)
{
    vsock s = allocate(h, sizeof(*s));
    if (s == INVALID_ADDRESS)
        return -ENOMEM;
    sysreturn rv;
    s->incoming = allocate_ringbuf(h, 512);
    if (s->incoming == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto err_incoming;
    }
    rv = socket_init(h, AF_VSOCK, type, flags, &s->sock);
    if (rv < 0)
        goto err_socket;
    s->sock.f.read = init_closure_func(&s->read, file_io, vsock_read);
    s->sock.f.write = init_closure_func(&s->write, file_io, vsock_write);
    s->sock.f.events = init_closure_func(&s->events, fdesc_events, vsock_events);
    s->sock.f.close = init_closure_func(&s->close, fdesc_close, vsock_close);
    s->sock.bind = vsock_bind;
    s->sock.listen = vsock_listen;
    s->sock.connect = vsock_connect;
    s->sock.accept4 = vsock_accept4;
    s->sock.sendto = vsock_sendto;
    s->sock.recvfrom = vsock_recvfrom;
    s->sock.getsockname = vsock_getsockname;
    s->sock.getsockopt = vsock_getsockopt;
    s->bound = 0;
    s->conn = 0;
    s->flags = 0;
    s->state = VSOCK_STATE_INIT;
    if (alloc_fd) {
        s->sock.fd = allocate_fd(current->p, s);
        if (s->sock.fd == INVALID_PHYSICAL) {
            apply(s->sock.f.close, 0, io_completion_ignore);
            return -ENFILE;
        }
    } else {
        s->sock.fd = -1;
    }
    *sp = s;
    return alloc_fd ? s->sock.fd : 0;
err_socket:
    deallocate_ringbuf(s->incoming);
err_incoming:
    deallocate(h, s, sizeof(*s));
    return rv;
}

void vsock_init(void)
{
    vsock_priv.h = heap_locked(&get_unix_heaps()->kh);
    vsock_priv.bound = allocate_table(vsock_priv.h, identity_key, pointer_equal);
    assert(vsock_priv.bound != INVALID_ADDRESS);
    vsock_priv.connections = allocate_table(vsock_priv.h, vsock_conn_key, vsock_conn_equals);
    assert(vsock_priv.connections != INVALID_ADDRESS);
}

sysreturn vsock_open(int type, int protocol) {
    switch (type & SOCK_TYPE_MASK) {
    case SOCK_STREAM:
        break;
    default:
        return -ESOCKTNOSUPPORT;
    }
    int flags = type & ~SOCK_TYPE_MASK;
    if (flags & ~SOCK_FLAGS_MASK)
        return -EINVAL;
    vsock s;
    return vsock_alloc(vsock_priv.h, type & SOCK_TYPE_MASK, flags, true, &s);
}

void vsock_set_transport(void *transport)
{
    vsock_priv.transport = transport;
}

u32 vsock_get_buf_size(void)
{
    return so_rcvbuf;
}

boolean vsock_connect_request(vsock_connection conn)
{
    spin_lock(&vsock_priv.lock);
    vsock_bound bound = table_find(vsock_priv.bound, pointer_from_u64((u64)conn->id.local_port));
    if (bound)
        refcount_reserve(&bound->refc);
    spin_unlock(&vsock_priv.lock);
    if (!bound)
        return false;
    spin_lock(&bound->lock);
    vsock s = bound->s;
    boolean success;
    if (s && (s->state == VSOCK_STATE_LISTEN)) {
        vsock child;
        if (vsock_alloc(vsock_priv.h, s->sock.type, 0, false, &child) == 0) {
            vsock_lock(s);
            if (ringbuf_length(s->incoming) < s->listen_backlog * sizeof(child)) {
                vsock_debug("child socket :%d %d:%d", s->local_port,
                            conn->id.peer_cid, conn->id.peer_port);
                child->local_port = s->local_port;
                child->conn = conn;
                child->state = VSOCK_STATE_CONNECTED;
                conn->vsock = child;
                success = ringbuf_write(s->incoming, &child, sizeof(child));
                if (success)
                    vsock_add_connection(conn);
            } else {
                success = false;
            }
            vsock_unlock(s);
            if (!success)
                apply(child->sock.f.close, 0, io_completion_ignore);
        } else {
            success = false;
        }
        blockq_wake_one(s->sock.rxbq);
        fdesc_notify_events(&s->sock.f);
    } else {
        success = false;
    }
    spin_unlock(&bound->lock);
    refcount_release(&bound->refc);
    return success;
}

vsock_connection vsock_connect_complete(struct vsock_conn_id *conn_id, boolean success)
{
    vsock_connection conn = vsock_get_connection(conn_id);
    if (!conn)
        return conn;
    vsock_conn_lock(conn);
    vsock s = conn->vsock;
    if (s) {
        vsock_lock(s);
        if (success) {
            s->state = VSOCK_STATE_CONNECTED;
        } else {
            s->so_error = ECONNREFUSED;
            s->state = VSOCK_STATE_BOUND;
        }
        vsock_unlock(s);
        blockq_wake_one(s->sock.txbq);
        notify_dispatch(s->sock.f.ns, vsock_events_internal(s));
    }
    if (success)
        return conn;
    vsock_remove_connection(conn);
    vsock_conn_unlock(conn);
    vsock_conn_release(conn);
    return 0;
}

vsock_connection vsock_get_conn(struct vsock_conn_id *conn_id)
{
    vsock_connection conn = vsock_get_connection(conn_id);
    if (conn)
        vsock_conn_lock(conn);
    return conn;
}

vsock_connection vsock_rx(struct vsock_conn_id *conn_id, void *data, u64 len)
{
    vsock_connection conn = vsock_get_connection(conn_id);
    if (!conn)
        return conn;
    vsock_conn_lock(conn);
    vsock s = conn->vsock;
    if (s) {
        vsock_lock(s);
        if (s->flags & VSOCK_SHUTDOWN_RX)
            len = 0;
        boolean notify = (ringbuf_length(s->incoming) == 0) && (len > 0);
        if (len > 0) {
            struct vsock_rxbuf rxbuf = {
                .data = data,
                .offset = 0,
                .len = len,
            };
            if (!ringbuf_write(s->incoming, &rxbuf, sizeof(rxbuf))) {
                /* couldn't enqueue incoming data: disable data reception on this connection */
                virtio_sock_free_rxbuf(vsock_priv.transport, data);
                s->flags |= VSOCK_SHUTDOWN_RX;
                virtio_sock_shutdown(conn, VSOCK_SHUTDOWN_RX);
                notify = false;
            }
        } else {
            virtio_sock_free_rxbuf(vsock_priv.transport, data);
        }
        vsock_unlock(s);
        blockq_wake_one(s->sock.rxbq);
        if (notify)
            notify_dispatch(s->sock.f.ns, vsock_events_internal(s));
    }
    return conn;
}

void vsock_buf_space_notify(vsock_connection conn, u64 buf_space)
{
    vsock s = conn->vsock;
    if (s) {
        blockq_wake_one(s->sock.txbq);
        notify_dispatch(s->sock.f.ns, vsock_events_internal(s));
    }
}

vsock_connection vsock_shutdown_request(struct vsock_conn_id *conn_id, int flags,
                                        boolean *conn_close)
{
    vsock_connection conn = vsock_get_connection(conn_id);
    if (!conn)
        return conn;
    vsock_conn_lock(conn);
    vsock s = conn->vsock;
    if (s) {
        vsock_lock(s);
        s->flags |= flags;
        *conn_close = (s->flags & VSOCK_SHUTDOWN_TX) && (s->flags & VSOCK_SHUTDOWN_RX);
        vsock_unlock(s);
        blockq_wake_one(s->sock.txbq);
        blockq_wake_one(s->sock.rxbq);
        notify_dispatch(s->sock.f.ns, vsock_events_internal(s));
    } else {
        *conn_close = true;
    }
    if (*conn_close)
        vsock_remove_connection(conn);
    return conn;
}

void vsock_conn_reset(struct vsock_conn_id *conn_id)
{
    vsock_debug("connection (:%d %d:%d) reset", conn_id->local_port,
                conn_id->peer_cid, conn_id->peer_port);
    vsock_connection conn = vsock_get_connection(conn_id);
    if (!conn)
        return;
    boolean connect_failed;
    vsock_conn_lock(conn);
    vsock s = conn->vsock;
    if (s) {
        vsock_lock(s);
        vsock_debug("  socket state %d", s->state);
        if (s->state == VSOCK_STATE_CONNECTING) {
            connect_failed = true;
            s->so_error = ECONNRESET;
            s->state = VSOCK_STATE_BOUND;
        } else {
            connect_failed = false;
            s->flags |= VSOCK_SHUTDOWN_TX | VSOCK_SHUTDOWN_RX;
        }
        vsock_unlock(s);
        blockq_wake_one(s->sock.txbq);
        if (!connect_failed)
            blockq_wake_one(s->sock.rxbq);
        notify_dispatch(s->sock.f.ns, vsock_events_internal(s));
    }
    vsock_remove_connection(conn);
    vsock_conn_unlock(conn);
    vsock_conn_release(conn);
}
