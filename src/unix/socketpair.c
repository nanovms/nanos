#include <net_system_structs.h>
#include <unix_internal.h>
#include <buffer.h>

#define SOCKPAIR_BUF_MAX_SIZE   (16 * PAGESIZE)

#define SOCKPAIR_DGRAM_MAX_COUNT    64

#define SOCKPAIR_BLOCKQ_LEN 32

struct sockpair;

typedef struct sockpair_socket {
    struct fdesc f; /* must be first */
    int fd;
    struct sockpair *sockpair;
    struct sockpair_socket *peer;
    blockq read_bq, write_bq;
} *sockpair_socket;

struct sockpair {
    struct sockpair_socket sockets[2];
    heap h;
    u64 ref_cnt;
    int type;
    buffer data;
    unsigned int dgram_len[SOCKPAIR_DGRAM_MAX_COUNT];
};

static void sockpair_dgram_set_len(struct sockpair *sp, u64 len)
{
    int last_dgram;

    for (last_dgram = SOCKPAIR_DGRAM_MAX_COUNT - 1; last_dgram >= 0;
            last_dgram--) {
        if (sp->dgram_len[last_dgram] != 0) {
            break;
        }
    }
    if (last_dgram < SOCKPAIR_DGRAM_MAX_COUNT - 1) {
        sp->dgram_len[last_dgram + 1] = len;
    }
}

static u64 sockpair_dgram_get_len(struct sockpair *sp)
{
    int first_dgram;

    for (first_dgram = 0; first_dgram < SOCKPAIR_DGRAM_MAX_COUNT; first_dgram++)
    {
        if (sp->dgram_len[first_dgram] != 0) {
            return sp->dgram_len[first_dgram];
        }
    }
    return 0;   /* no datagrams were found */
}

static void sockpair_dgram_consume(struct sockpair *sp)
{
    int first_dgram;

    for (first_dgram = 0; first_dgram < SOCKPAIR_DGRAM_MAX_COUNT; first_dgram++)
    {
        if (sp->dgram_len[first_dgram] != 0) {
            sp->dgram_len[first_dgram] = 0;
            break;
        }
    }
}

static unsigned int sockpair_dgram_get_free(struct sockpair *sp)
{
    int last_dgram;

    for (last_dgram = SOCKPAIR_DGRAM_MAX_COUNT - 1; last_dgram >= 0;
            last_dgram--) {
        if (sp->dgram_len[last_dgram] != 0) {
            break;
        }
    }
    return (SOCKPAIR_DGRAM_MAX_COUNT - 1 - last_dgram);
}

static void sockpair_dgram_clear(struct sockpair *sp)
{
    runtime_memset((u8 *)sp->dgram_len, 0, sizeof(sp->dgram_len));
}

static inline void sockpair_notify_reader(sockpair_socket s, int events)
{
    if (s->fd != -1) {
        if (events & EPOLLHUP) {
            blockq_flush(s->read_bq);
        }
        else {
            blockq_wake_one(s->read_bq);
        }
        notify_dispatch(s->f.ns, events);
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
        notify_dispatch(s->f.ns, events);
    }
}

static CLOSURE_5_2(sockpair_read_bh, sysreturn,
                   sockpair_socket, thread, void *, u64, io_completion,
                   boolean, boolean);
static sysreturn sockpair_read_bh(sockpair_socket s, thread t, void *dest,
                                  u64 length, io_completion completion, boolean blocked, boolean nullify)
{
    buffer b = s->sockpair->data;
    int real_length;
    int dgram_length;

    if (nullify) {
        real_length = -EINTR;
        goto out;
    }

    if (s->sockpair->type == SOCK_STREAM) {
        real_length = MIN(buffer_length(b), length);
    }
    else {
        dgram_length = sockpair_dgram_get_len(s->sockpair);
        real_length = MIN(dgram_length, length);
    }
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
    if (s->sockpair->type == SOCK_STREAM) {
        buffer_read(b, dest, real_length);
    }
    else {
        runtime_memcpy(dest, buffer_ref(b, 0), real_length);
        buffer_consume(b, dgram_length);
        sockpair_dgram_consume(s->sockpair);
    }
    sockpair_notify_writer(s->peer, EPOLLOUT);
    if (buffer_length(b) == 0) {
        buffer_clear(b);
        if (s->sockpair->type == SOCK_DGRAM) {
            sockpair_dgram_clear(s->sockpair);
        }
    }
out:
    if (blocked) {
        blockq_set_completion(s->read_bq, completion, t, real_length);
    }
    return real_length;
}

static CLOSURE_1_6(sockpair_read, sysreturn,
        sockpair_socket,
        void *, u64, u64, thread, boolean, io_completion);
static sysreturn sockpair_read(sockpair_socket s, void *dest, u64 length,
        u64 offset_arg, thread t, boolean bh, io_completion completion)
{
    if (length == 0) {
        return 0;
    }

    blockq_action ba = closure(s->sockpair->h, sockpair_read_bh, s, t,
            dest, length, completion);
    return blockq_check(s->read_bq, t, ba, bh);
}

static CLOSURE_5_2(sockpair_write_bh, sysreturn,
        sockpair_socket, thread, void *, u64, io_completion,
                   boolean, boolean);
static sysreturn sockpair_write_bh(sockpair_socket s, thread t, void *dest,
                                   u64 length, io_completion completion, boolean blocked, boolean nullify)
{
    sysreturn rv = 0;
    buffer b = s->sockpair->data;

    if (nullify) {
        rv = -EINTR;
        goto out;
    }

    if (s->peer->fd == -1) {
        rv = -EPIPE;
        goto out;
    }

    u64 avail = SOCKPAIR_BUF_MAX_SIZE - buffer_length(b);
    if ((avail == 0) || ((s->sockpair->type == SOCK_DGRAM) &&
            ((avail < length) || (sockpair_dgram_get_free(s->sockpair) == 0))))
    {
        if (s->f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return infinity;
    }

    u64 real_length = MIN(length, avail);
    buffer_write(b, dest, real_length);
    if (s->sockpair->type == SOCK_DGRAM) {
        sockpair_dgram_set_len(s->sockpair, length);
    }
    sockpair_notify_reader(s->peer, EPOLLIN);
    rv = real_length;
out:
    if (blocked) {
        blockq_set_completion(s->write_bq, completion, t, rv);
    }
    return rv;
}

static CLOSURE_1_6(sockpair_write, sysreturn,
        sockpair_socket,
        void *, u64, u64, thread, boolean, io_completion);
static sysreturn sockpair_write(sockpair_socket s, void * dest, u64 length,
        u64 offset, thread t, boolean bh, io_completion completion)
{
    if (length == 0) {
        return 0;
    }

    blockq_action ba = closure(s->sockpair->h, sockpair_write_bh, s, t,
            dest, length, completion);
    return blockq_check(s->write_bq, t, ba, bh);
}

static CLOSURE_1_0(sockpair_events, u32, sockpair_socket);
static u32 sockpair_events(sockpair_socket s)
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
    return events;
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
    if ((s->read_bq != 0) && (s->read_bq != INVALID_ADDRESS)) {
        deallocate_blockq(s->read_bq);
    }
    if ((s->write_bq != 0) && (s->write_bq != INVALID_ADDRESS)) {
        deallocate_blockq(s->write_bq);
    }
    release_fdesc(&s->f);
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
    if (((type & SOCK_TYPE_MASK) != SOCK_STREAM) &&
            ((type & SOCK_TYPE_MASK) != SOCK_DGRAM)) {
        return set_syscall_error(current, ESOCKTNOSUPPORT);
    }
    sockpair = allocate(h, sizeof(*sockpair));
    if (sockpair == INVALID_ADDRESS) {
        msg_err("failed to allocate socketpair structure\n");
        return set_syscall_error(current, ENOMEM);
    }
    sockpair->h = h;
    sockpair->data = allocate_buffer(sockpair->h, 128);
    if (sockpair->data == INVALID_ADDRESS) {
        msg_err("failed to allocate socketpair data buffer\n");
        sockpair_release(sockpair);
        return set_syscall_error(current, ENOMEM);
    }
    sockpair->ref_cnt = 0;
    sockpair->type = type & SOCK_TYPE_MASK;
    if (sockpair->type == SOCK_DGRAM) {
        sockpair_dgram_clear(sockpair);
    }
    for (i = 0; i < 2; i++) {
        sockpair_socket s = &sockpair->sockets[i];

        runtime_memset((u8 *)s, 0, sizeof(*s));
        s->sockpair = sockpair;
        s->fd = sv[i] = allocate_fd(current->p, s);
        if (s->fd == -1) {
            msg_err("failed to allocate socketpair file descriptor\n");
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
        init_fdesc(h, &s->f, FDESC_TYPE_SOCKET);
        s->f.flags = type & ~SOCK_TYPE_MASK;
        s->f.read = closure(sockpair->h, sockpair_read, s);
        s->f.write = closure(sockpair->h, sockpair_write, s);
        s->f.events = closure(sockpair->h, sockpair_events, s);
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
