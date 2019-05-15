#include <net_system_structs.h>
#include <unix_internal.h>
#include <buffer.h>

#define SOCKPAIR_BUF_MAX_SIZE   (16 * PAGESIZE)

#define SOCKPAIR_BLOCKQ_LEN 32

struct sockpair;

typedef struct sockpair_socket {
    struct fdesc f; /* must be first */
    int fd;
    struct sockpair *sockpair;
    struct sockpair_socket *peer;
    notify_set ns;
    blockq read_bq, write_bq;
} *sockpair_socket;

struct sockpair {
    struct sockpair_socket sockets[2];
    heap h;
    u64 ref_cnt;
    buffer data;
};

static inline void sockpair_notify_reader(sockpair_socket s, int events)
{
    if (s->fd != -1) {
        if (events & EPOLLHUP) {
            blockq_flush(s->read_bq);
        }
        else {
            blockq_wake_one(s->read_bq);
        }
        notify_dispatch(s->ns, events);
    }
}

static inline void sockpair_notify_writer(sockpair_socket s, int events)
{
    if (s->fd != -1) {
        if (events & EPOLLHUP) {
            blockq_flush(s->write_bq);
        }
        else {
            blockq_wake_one(s->write_bq);
        }
        notify_dispatch(s->ns, events);
    }
}

static CLOSURE_4_1(sockpair_read_bh, sysreturn, sockpair_socket, thread, void *,
        u64, boolean);
static sysreturn sockpair_read_bh(sockpair_socket s, thread t, void *dest,
        u64 length, boolean blocked)
{
    buffer b = s->sockpair->data;
    int real_length = MIN(buffer_length(b), length);

    if (real_length == 0) {
        if (s->peer->fd == -1) {
            goto out;
        }
        else if (s->f.flags & SOCK_NONBLOCK) {
            real_length = -EAGAIN;
            goto out;
        }
        return infinity;
    }
    buffer_read(b, dest, real_length);
    sockpair_notify_writer(s->peer, EPOLLOUT);
    if (buffer_length(b) == 0) {
        buffer_clear(b);
    }
out:
    if (blocked) {
        thread_wakeup(t);
    }
    return set_syscall_return(t, real_length);
}

static CLOSURE_1_3(sockpair_read, sysreturn, sockpair_socket, void *, u64, u64);
static sysreturn sockpair_read(sockpair_socket s, void *dest, u64 length,
        u64 offset_arg)
{
    if (length == 0) {
        return 0;
    }

    blockq_action ba = closure(s->sockpair->h, sockpair_read_bh, s, current,
            dest, length);
    sysreturn rv = blockq_check(s->read_bq, current, ba);

    if (rv != infinity) {
        return rv;
    }
    msg_err("thread %ld unable to block; queue full\n", current->tid);
    return set_syscall_error(current, EAGAIN);
}

static CLOSURE_4_1(sockpair_write_bh, sysreturn, sockpair_socket, thread,
        void *, u64, boolean);
static sysreturn sockpair_write_bh(sockpair_socket s, thread t, void *dest,
        u64 length, boolean blocked)
{
    sysreturn rv = 0;
    buffer b = s->sockpair->data;

    if (s->peer->fd == -1) {
        rv = -EPIPE;
        goto out;
    }

    u64 avail = SOCKPAIR_BUF_MAX_SIZE - buffer_length(b);
    if (avail == 0) {
        if (s->f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return infinity;
    }

    u64 real_length = MIN(length, avail);
    buffer_write(b, dest, real_length);
    sockpair_notify_reader(s->peer, EPOLLIN);
    rv = real_length;
out:
    if (blocked) {
        thread_wakeup(t);
    }
    return set_syscall_return(t, rv);
}

static CLOSURE_1_3(sockpair_write, sysreturn, sockpair_socket, void *, u64,
        u64);
static sysreturn sockpair_write(sockpair_socket s, void * dest, u64 length,
        u64 offset)
{
    if (length == 0) {
        return 0;
    }

    blockq_action ba = closure(s->sockpair->h, sockpair_write_bh, s, current,
            dest, length);
    sysreturn rv = blockq_check(s->write_bq, current, ba);

    if (rv != infinity) {
        return rv;
    }
    msg_err("thread %ld unable to block; queue full\n", current->tid);
    return set_syscall_error(current, EAGAIN);
}

static CLOSURE_1_3(sockpair_check, boolean, sockpair_socket, u32, u32 *,
        event_handler);
static boolean sockpair_check(sockpair_socket s, u32 eventmask, u32 *last,
        event_handler eh)
{
    u32 events = 0;
    if (buffer_length(s->sockpair->data) != 0) {
        events |= EPOLLIN;
    }
    if (buffer_length(s->sockpair->data) != SOCKPAIR_BUF_MAX_SIZE) {
        events |= EPOLLOUT;
    }
    if (s->peer->fd == -1) {
        events |= EPOLLHUP;
    }

    u32 report = edge_events(events, eventmask, last);
    if (report) {
        if (apply(eh, report)) {
            if (last) {
                *last = events & eventmask;
            }
            return true;
        }
        else {
            return false;
        }
    }
    else {
        if (!notify_add(s->ns, eventmask, last, eh)) {
            msg_err("notify enqueue fail: out of memory\n");
        }
    }
    return true;
}

static void sockpair_dealloc_sock(sockpair_socket s)
{
    if (s->fd != -1) {
        if (s->peer) {
            sockpair_notify_reader(s->peer, EPOLLIN | EPOLLHUP);
            sockpair_notify_writer(s->peer, EPOLLHUP);
        }
        s->fd = -1;
    }
    if ((s->ns != 0) && (s->ns != INVALID_ADDRESS)) {
        deallocate_notify_set(s->ns);
    }
    if ((s->read_bq != 0) && (s->read_bq != INVALID_ADDRESS)) {
        deallocate_blockq(s->read_bq);
    }
    if ((s->write_bq != 0) && (s->write_bq != INVALID_ADDRESS)) {
        deallocate_blockq(s->write_bq);
    }
}

static void sockpair_release(struct sockpair *sockpair)
{
    if (!sockpair->ref_cnt || (fetch_and_add(&sockpair->ref_cnt, -1) == 1)) {
        if (sockpair->data != INVALID_ADDRESS) {
            deallocate_buffer(sockpair->data);
        }
        deallocate(sockpair->h, sockpair, sizeof(*sockpair));
    }
}

static CLOSURE_1_0(sockpair_close, sysreturn, sockpair_socket);
static sysreturn sockpair_close(sockpair_socket s)
{
    sockpair_dealloc_sock(s);
    sockpair_release(s->sockpair);
    return 0;
}

sysreturn socketpair(int domain, int type, int protocol, int sv[2]) {
    unix_heaps uh = get_unix_heaps();
    heap h = heap_general((kernel_heaps)uh);
    struct sockpair *sockpair;
    int i;

    if (domain != AF_UNIX) {
        return set_syscall_error(current, EAFNOSUPPORT);
    }
    if ((type & SOCK_TYPE_MASK) != SOCK_STREAM) {
        return set_syscall_error(current, ESOCKTNOSUPPORT);
    }
    sockpair = allocate(h, sizeof(*sockpair));
    if (sockpair == INVALID_ADDRESS) {
        msg_err("failed to allocate socketpair structure\n");
        return set_syscall_error(current, ENOMEM);
    }
    sockpair->h = heap_general((kernel_heaps) uh);
    sockpair->data = allocate_buffer(sockpair->h, 128);
    if (sockpair->data == INVALID_ADDRESS) {
        msg_err("failed to allocate socketpair data buffer\n");
        sockpair_release(sockpair);
        return set_syscall_error(current, ENOMEM);
    }
    sockpair->ref_cnt = 0;
    for (i = 0; i < 2; i++) {
        sockpair_socket s = &sockpair->sockets[i];

        runtime_memset((u8 *)s, 0, sizeof(*s));
        s->sockpair = sockpair;
        s->fd = sv[i] = allocate_fd(current->p, s);
        if (s->fd == -1) {
            msg_err("failed to allocate socketpair file descriptor\n");
            break;
        }
        s->ns = allocate_notify_set(sockpair->h);
        if (s->ns == INVALID_ADDRESS) {
            msg_err("failed to allocate socketpair notify set\n");
            break;
        }
        s->read_bq = allocate_blockq(sockpair->h, "socketpair read",
                SOCKPAIR_BLOCKQ_LEN, 0);
        if (s->read_bq == INVALID_ADDRESS) {
            msg_err("failed to allocate socketpair read block queue\n");
            break;
        }
        s->write_bq = allocate_blockq(sockpair->h, "socketpair write",
                SOCKPAIR_BLOCKQ_LEN, 0);
        if (s->write_bq == INVALID_ADDRESS) {
            msg_err("failed to allocate socketpair write block queue\n");
            break;
        }
        fdesc_init(&s->f, FDESC_TYPE_SOCKET);
        s->f.flags = type & ~SOCK_TYPE_MASK;
        s->f.read = closure(sockpair->h, sockpair_read, s);
        s->f.write = closure(sockpair->h, sockpair_write, s);
        s->f.check = closure(sockpair->h, sockpair_check, s);
        s->f.close = closure(sockpair->h, sockpair_close, s);
    }
    if (i != 2) {
        if (i == 1) {
            sockpair_dealloc_sock(&sockpair->sockets[1]);
            if (sockpair->sockets[1].fd != -1) {
                deallocate_fd(current->p, sockpair->sockets[1].fd);
            }
        }
        sockpair_dealloc_sock(&sockpair->sockets[0]);
        if (sockpair->sockets[0].fd != -1) {
            deallocate_fd(current->p, sockpair->sockets[0].fd);
        }
        sockpair_release(sockpair);
        return set_syscall_error(current, ENOMEM);
    }
    sockpair->sockets[0].peer = &sockpair->sockets[1];
    sockpair->sockets[1].peer = &sockpair->sockets[0];
    sockpair->ref_cnt = 2;
    return 0;
}
