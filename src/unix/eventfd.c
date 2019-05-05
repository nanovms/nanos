#include <unix_internal.h>

#define EFD_COUNTER_MAX 0xFFFFFFFFFFFFFFFEULL

#define EFD_BLOCKQ_LEN  32

struct efd {
    struct fdesc f; /* must be first */
    int fd;
    heap h;
    notify_set ns;
    blockq read_bq, write_bq;
    u64 counter;
};

static CLOSURE_4_1(efd_read_bh, sysreturn, struct efd *, thread, void *, u64,
        boolean);
static sysreturn efd_read_bh(struct efd *efd, thread t, void *buf, u64 length,
        boolean blocked)
{
    sysreturn rv = sizeof(efd->counter);

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
    notify_dispatch(efd->ns, EPOLLOUT);
out:
    if (blocked)
        thread_wakeup(t);
    return set_syscall_return(t, rv);
}

static CLOSURE_1_3(efd_read, sysreturn, struct efd *, void *, u64, u64);
static sysreturn efd_read(struct efd *efd, void *buf, u64 length,
        u64 offset_arg)
{
    if (length < sizeof(u64)) {
        return set_syscall_error(current, EINVAL);
    }

    blockq_action ba = closure(efd->h, efd_read_bh, efd, current, buf, length);
    sysreturn rv = blockq_check(efd->read_bq, current, ba);

    if (rv != infinity)
        return rv;

    msg_err("thread %ld unable to block; queue full\n", current->tid);
    return set_syscall_error(current, EAGAIN);
}

static CLOSURE_4_1(efd_write_bh, sysreturn, struct efd *, thread, void *, u64,
        boolean);
static sysreturn efd_write_bh(struct efd *efd, thread t, void *buf, u64 length,
        boolean blocked)
{
    sysreturn rv = sizeof(efd->counter);
    u64 counter;

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
    notify_dispatch(efd->ns, EPOLLIN);
out:
    if (blocked)
        thread_wakeup(t);
    return set_syscall_return(t, rv);
}

static CLOSURE_1_3(efd_write, sysreturn, struct efd *, void *, u64, u64);
static sysreturn efd_write(struct efd *efd, void *buf, u64 length,
        u64 offset)
{
    if (length < sizeof(u64)) {
        return set_syscall_error(current, EINVAL);
    }

    blockq_action ba = closure(efd->h, efd_write_bh, efd, current, buf, length);
    sysreturn rv = blockq_check(efd->write_bq, current, ba);

    if (rv != infinity)
        return rv;

    msg_err("thread %ld unable to block; queue full\n", current->tid);
    return set_syscall_error(current, EAGAIN);
}

static CLOSURE_1_3(efd_check, boolean, struct efd *, u32, u32 *, event_handler);
static boolean efd_check(struct efd *efd, u32 eventmask, u32 * last,
        event_handler eh)
{
    u32 events = 0;
    if (efd->counter != 0) {
        events |= EPOLLIN;
    }
    if (efd->counter != EFD_COUNTER_MAX) {
        events |= EPOLLOUT;
    }

    u32 report = edge_events(events, eventmask, last);
    if (report) {
        if (apply(eh, report)) {
            if (last)
                *last = events & eventmask;
            return true;
        } else {
            return false;
        }
    } else {
        if (!notify_add(efd->ns, eventmask, last, eh))
            msg_err("notify enqueue fail: out of memory\n");
    }
    return true;
}

static CLOSURE_1_0(efd_close, sysreturn, struct efd *);
static sysreturn efd_close(struct efd *efd)
{
    deallocate_notify_set(efd->ns);
    deallocate_blockq(efd->read_bq);
    deallocate_blockq(efd->write_bq);
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
    fdesc_init(&efd->f, 0);
    efd->f.flags = flags;
    efd->f.read = closure(h, efd_read, efd);
    efd->f.write = closure(h, efd_write, efd);
    efd->f.check = closure(h, efd_check, efd);
    efd->f.close = closure(h, efd_close, efd);
    efd->h = h;
    efd->ns = allocate_notify_set(h);
    efd->read_bq = allocate_blockq(h, "eventfd read", EFD_BLOCKQ_LEN, 0);
    efd->write_bq = allocate_blockq(h, "eventfd write", EFD_BLOCKQ_LEN, 0);
    efd->counter = count;
    return efd->fd;
}
