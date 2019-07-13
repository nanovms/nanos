#include <unix_internal.h>

#define EFD_COUNTER_MAX 0xFFFFFFFFFFFFFFFEULL

#define EFD_BLOCKQ_LEN  32

struct efd {
    struct fdesc f; /* must be first */
    int fd;
    heap h;
    blockq read_bq, write_bq;
    u64 counter;
};

static CLOSURE_5_2(efd_read_bh, sysreturn,
                   struct efd *, thread, void *, u64, io_completion,
                   boolean, boolean);
static sysreturn efd_read_bh(struct efd *efd, thread t, void *buf, u64 length,
                             io_completion completion, boolean blocked, boolean nullify)
{
    sysreturn rv = sizeof(efd->counter);

    if (nullify) {
        rv = -EINTR;
        goto out;
    }

    if (efd->counter == 0) {
        if (efd->f.flags & EFD_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return infinity;
    }
    if (efd->f.flags & EFD_SEMAPHORE) {
        u64 readVal = 1;

        runtime_memcpy(buf, &readVal, sizeof(readVal));
        efd->counter--;
    }
    else {
        runtime_memcpy(buf, &efd->counter, sizeof(efd->counter));
        efd->counter = 0;
    }
    blockq_wake_one(efd->write_bq);
    notify_dispatch(efd->f.ns, EPOLLOUT);
out:
    if (blocked)
        blockq_set_completion(efd->read_bq, completion, t, rv);
    return rv;
}

static CLOSURE_1_6(efd_read, sysreturn,
        struct efd *,
        void *, u64, u64, thread, boolean, io_completion);
static sysreturn efd_read(struct efd *efd, void *buf, u64 length,
        u64 offset_arg, thread t, boolean bh, io_completion completion)
{
    if (length < sizeof(u64)) {
        return -EINVAL;
    }

    blockq_action ba = closure(efd->h, efd_read_bh, efd, t, buf, length,
            completion);
    return blockq_check(efd->read_bq, t, ba, bh);
}

static CLOSURE_5_2(efd_write_bh, sysreturn,
                   struct efd *, thread, void *, u64, io_completion,
                   boolean, boolean);
static sysreturn efd_write_bh(struct efd *efd, thread t, void *buf, u64 length,
                              io_completion completion, boolean blocked, boolean nullify)
{
    sysreturn rv = sizeof(efd->counter);
    u64 counter;

    if (nullify) {
        rv = -EINTR;
        goto out;
    }

    runtime_memcpy(&counter, buf, sizeof(counter));
    if (counter > (EFD_COUNTER_MAX - efd->counter)) {
        if (efd->f.flags & EFD_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return infinity;
    }
    efd->counter += counter;
    blockq_wake_one(efd->read_bq);
    notify_dispatch(efd->f.ns, EPOLLIN);
out:
    if (blocked)
        blockq_set_completion(efd->write_bq, completion, t, rv);
    return rv;
}

static CLOSURE_1_6(efd_write, sysreturn,
        struct efd *,
        void *, u64, u64, thread, boolean, io_completion);
static sysreturn efd_write(struct efd *efd, void *buf, u64 length,
        u64 offset, thread t, boolean bh, io_completion completion)
{
    if (length < sizeof(u64)) {
        return -EINVAL;
    }

    blockq_action ba = closure(efd->h, efd_write_bh, efd, t, buf, length,
            completion);
    return blockq_check(efd->write_bq, t, ba, bh);
}

static CLOSURE_1_0(efd_events, u32, struct efd *);
static u32 efd_events(struct efd *efd)
{
    u32 events = 0;
    if (efd->counter != 0) {
        events |= EPOLLIN;
    }
    if (efd->counter != EFD_COUNTER_MAX) {
        events |= EPOLLOUT;
    }
    return events;
}

static CLOSURE_1_0(efd_close, sysreturn, struct efd *);
static sysreturn efd_close(struct efd *efd)
{
    deallocate_blockq(efd->read_bq);
    deallocate_blockq(efd->write_bq);
    release_fdesc(&efd->f);
    deallocate(efd->h, efd, sizeof(*efd));
    return 0;
}

int do_eventfd2(unsigned int count, int flags)
{
    unix_heaps uh = get_unix_heaps();
    heap h = heap_general((kernel_heaps)uh);
    struct efd *efd;

    if (flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE)) {
        return set_syscall_error(current, EINVAL);
    }
    efd = allocate(h, sizeof(*efd));
    if (efd == INVALID_ADDRESS) {
        msg_err("failed to allocate eventfd structure\n");
        return -ENOMEM;
    }
    efd->fd = allocate_fd(current->p, efd);
    init_fdesc(h, &efd->f, 0);
    efd->f.flags = flags;
    efd->f.read = closure(h, efd_read, efd);
    efd->f.write = closure(h, efd_write, efd);
    efd->f.events = closure(h, efd_events, efd);
    efd->f.close = closure(h, efd_close, efd);
    efd->h = h;
    efd->read_bq = allocate_blockq(h, "eventfd read", EFD_BLOCKQ_LEN, 0);
    efd->write_bq = allocate_blockq(h, "eventfd write", EFD_BLOCKQ_LEN, 0);
    efd->counter = count;
    return efd->fd;
}
