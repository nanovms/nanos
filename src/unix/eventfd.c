#include <unix_internal.h>

#define EFD_COUNTER_MAX 0xFFFFFFFFFFFFFFFEULL

struct efd {
    struct fdesc f; /* must be first */
    int fd;
    heap h;
    blockq read_bq, write_bq;
    u64 counter;
};

closure_function(5, 1, sysreturn, efd_read_bh,
                 struct efd *, efd, thread, t, void *, buf, u64, length, io_completion, completion,
                 u64, flags)
{
    struct efd *efd = bound(efd);
    sysreturn rv = sizeof(efd->counter);

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }

    if (efd->counter == 0) {
        if (efd->f.flags & EFD_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    if (efd->f.flags & EFD_SEMAPHORE) {
        u64 readVal = 1;

        runtime_memcpy(bound(buf), &readVal, sizeof(readVal));
        efd->counter--;
    }
    else {
        runtime_memcpy(bound(buf), &efd->counter, sizeof(efd->counter));
        efd->counter = 0;
    }
    blockq_wake_one(efd->write_bq);
    notify_dispatch(efd->f.ns, EPOLLOUT);
out:
    blockq_handle_completion(efd->read_bq, flags, bound(completion), bound(t), rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, efd_read,
                 struct efd *, efd,
                 void *, buf, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    if (length < sizeof(u64)) {
        return io_complete(completion, t, -EINVAL);
    }

    blockq_action ba = closure(bound(efd)->h, efd_read_bh, bound(efd), t, buf, length,
            completion);
    return blockq_check(bound(efd)->read_bq, t, ba, bh);
}

closure_function(5, 1, sysreturn, efd_write_bh,
                 struct efd *, efd, thread, t, void *, buf, u64, length, io_completion, completion,
                 u64, flags)
{
    struct efd *efd = bound(efd);
    sysreturn rv = sizeof(efd->counter);
    u64 counter;

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }

    runtime_memcpy(&counter, bound(buf), sizeof(counter));
    if (counter > (EFD_COUNTER_MAX - efd->counter)) {
        if (efd->f.flags & EFD_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    efd->counter += counter;
    blockq_wake_one(efd->read_bq);
    notify_dispatch(efd->f.ns, EPOLLIN);
out:
    blockq_handle_completion(efd->write_bq, flags, bound(completion), bound(t), rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, efd_write,
                 struct efd *, efd,
                 void *, buf, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    if (length < sizeof(u64)) {
        return io_complete(completion, t, -EINVAL);
    }

    blockq_action ba = closure(bound(efd)->h, efd_write_bh, bound(efd), t, buf, length,
            completion);
    return blockq_check(bound(efd)->write_bq, t, ba, bh);
}

closure_function(1, 1, u32, efd_events,
                 struct efd *, efd,
                 thread, t /* ignore */)
{
    u32 events = 0;
    if (bound(efd)->counter != 0) {
        events |= EPOLLIN;
    }
    if (bound(efd)->counter != EFD_COUNTER_MAX) {
        events |= EPOLLOUT;
    }
    return events;
}

closure_function(1, 2, sysreturn, efd_close,
                 struct efd *, efd,
                 thread, t, io_completion, completion)
{
    struct efd *efd = bound(efd);
    deallocate_blockq(efd->read_bq);
    deallocate_blockq(efd->write_bq);
    deallocate_closure(efd->f.read);
    deallocate_closure(efd->f.write);
    deallocate_closure(efd->f.events);
    deallocate_closure(efd->f.close);
    release_fdesc(&efd->f);
    deallocate(efd->h, efd, sizeof(*efd));
    return io_complete(completion, t, 0);
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
        goto err_efd;
    }

    efd->fd = allocate_fd(current->p, efd);
    if (efd->fd == INVALID_PHYSICAL) {
        msg_err("failed to allocate fd\n");
        goto err_fd;
    }

    init_fdesc(h, &efd->f, FDESC_TYPE_EVENTFD);
    efd->f.flags = flags;
    efd->f.read = closure(h, efd_read, efd);
    efd->f.write = closure(h, efd_write, efd);
    efd->f.events = closure(h, efd_events, efd);
    efd->f.close = closure(h, efd_close, efd);
    efd->h = h;

    efd->read_bq = allocate_blockq(h, "eventfd read");
    if (efd->read_bq == INVALID_ADDRESS) {
        msg_err("failed to allocated blockq\n");
        goto err_read_bq;
    }

    efd->write_bq = allocate_blockq(h, "eventfd write");
    if (efd->write_bq == INVALID_ADDRESS) {
        msg_err("failed to allocate blockq\n");
        goto err_write_bq;
    }

    efd->counter = count;
    return efd->fd;

err_write_bq:
    deallocate_blockq(efd->read_bq);
err_read_bq:
    deallocate_fd(current->p, efd->fd);
err_fd:
    deallocate(h, efd, sizeof(*efd));
err_efd:
    return set_syscall_error(current, ENOMEM);
}
