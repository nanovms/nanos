#include <unix_internal.h>

#define EFD_COUNTER_MAX 0xFFFFFFFFFFFFFFFEULL

struct efd {
    struct fdesc f; /* must be first */
    int fd;
    heap h;
    int flags;
    blockq read_bq, write_bq;
    u64 counter;
    boolean io_event;
    closure_struct(file_io, read);
    closure_struct(file_io, write);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_close, close);
    closure_struct(fdesc_et_handler, et_handler);
};

#define efd_lock(efd)   spin_lock(&(efd)->f.lock)
#define efd_unlock(efd) spin_unlock(&(efd)->f.lock)

closure_func_basic(fdesc_et_handler, u64, efd_edge_handler,
                   u64 events, u64 lastevents)
{
    struct efd *efd = struct_from_field(closure_self(), struct efd *, et_handler);
    efd_lock(efd);

    /* A read or a write acts as an edge */
    if (efd->io_event) {
        lastevents &= ~(EPOLLIN | EPOLLOUT);
        efd->io_event = false;
    }
    efd_unlock(efd);
    return lastevents;
}

closure_function(4, 1, sysreturn, efd_read_bh,
                 struct efd *, efd, void *, buf, u64, length, io_completion, completion,
                 u64 flags)
{
    struct efd *efd = bound(efd);
    sysreturn rv = sizeof(efd->counter);

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }

    context ctx = get_current_context(current_cpu());
    efd_lock(efd);
    if (efd->counter == 0) {
        efd_unlock(efd);
        if (efd->flags & EFD_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return blockq_block_required((unix_context)ctx, flags);
    }
    if (context_set_err(ctx)) {
        efd_unlock(efd);
        rv = -EFAULT;
        goto out;
    }
    if (efd->flags & EFD_SEMAPHORE) {
        u64 readVal = 1;

        runtime_memcpy(bound(buf), &readVal, sizeof(readVal));
        efd->counter--;
    }
    else {
        runtime_memcpy(bound(buf), &efd->counter, sizeof(efd->counter));
        efd->counter = 0;
    }
    context_clear_err(ctx);
    efd->io_event = true;
    efd_unlock(efd);
    blockq_wake_one(efd->write_bq);
    fdesc_notify_events(&efd->f);
out:
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

closure_func_basic(file_io, sysreturn, efd_read,
                   void *buf, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    if (length < sizeof(u64)) {
        return io_complete(completion, -EINVAL);
    }

    struct efd *efd = struct_from_field(closure_self(), struct efd *, read);
    blockq_action ba = closure_from_context(ctx, efd_read_bh, efd, buf, length, completion);
    return blockq_check(efd->read_bq, ba, bh);
}

closure_function(4, 1, sysreturn, efd_write_bh,
                 struct efd *, efd, void *, buf, u64, length, io_completion, completion,
                 u64 flags)
{
    struct efd *efd = bound(efd);
    sysreturn rv = sizeof(efd->counter);
    u64 counter;

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }

    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        rv = -EFAULT;
        goto out;
    }
    runtime_memcpy(&counter, bound(buf), sizeof(counter));
    context_clear_err(ctx);
    efd_lock(efd);
    if (counter > (EFD_COUNTER_MAX - efd->counter)) {
        efd_unlock(efd);
        if (efd->flags & EFD_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return blockq_block_required((unix_context)ctx, flags);
    }
    efd->counter += counter;
    efd->io_event = true;
    efd_unlock(efd);
    blockq_wake_one(efd->read_bq);
    fdesc_notify_events(&efd->f);
out:
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

closure_func_basic(file_io, sysreturn, efd_write,
                 void *buf, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    if (length < sizeof(u64)) {
        return io_complete(completion, -EINVAL);
    }

    struct efd *efd = struct_from_field(closure_self(), struct efd *, write);
    blockq_action ba = closure_from_context(ctx, efd_write_bh, efd, buf, length, completion);
    return blockq_check(efd->write_bq, ba, bh);
}

closure_func_basic(fdesc_events, u32, efd_events,
                   thread t /* ignore */)
{
    struct efd *efd = struct_from_field(closure_self(), struct efd *, events);
    u64 counter = efd->counter;
    u32 events = 0;
    if (counter != 0) {
        events |= EPOLLIN;
    }
    if (counter != EFD_COUNTER_MAX) {
        events |= EPOLLOUT;
    }
    return events;
}

closure_func_basic(fdesc_close, sysreturn, efd_close,
                   context ctx, io_completion completion)
{
    struct efd *efd = struct_from_field(closure_self(), struct efd *, close);
    deallocate_blockq(efd->read_bq);
    deallocate_blockq(efd->write_bq);
    release_fdesc(&efd->f);
    deallocate(efd->h, efd, sizeof(*efd));
    return io_complete(completion, 0);
}

int do_eventfd2(unsigned int count, int flags)
{
    unix_heaps uh = get_unix_heaps();
    heap h = heap_locked((kernel_heaps)uh);
    struct efd *efd;

    if (flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE)) {
        return set_syscall_error(current, EINVAL);
    }
    efd = allocate(h, sizeof(*efd));
    if (efd == INVALID_ADDRESS) {
        msg_err("failed to allocate eventfd structure\n");
        goto err_efd;
    }

    init_fdesc(h, &efd->f, FDESC_TYPE_EVENTFD);
    efd->f.flags = O_RDWR;
    efd->f.read = init_closure_func(&efd->read, file_io, efd_read);
    efd->f.write = init_closure_func(&efd->write, file_io, efd_write);
    efd->f.events = init_closure_func(&efd->events, fdesc_events, efd_events);
    efd->f.close = init_closure_func(&efd->close, fdesc_close, efd_close);
    efd->f.edge_trigger_handler = init_closure_func(&efd->et_handler, fdesc_et_handler, efd_edge_handler);
    efd->h = h;
    efd->flags = flags;

    efd->read_bq = allocate_blockq(h, ss("eventfd read"));
    if (efd->read_bq == INVALID_ADDRESS) {
        msg_err("failed to allocated blockq\n");
        goto err_read_bq;
    }

    efd->write_bq = allocate_blockq(h, ss("eventfd write"));
    if (efd->write_bq == INVALID_ADDRESS) {
        msg_err("failed to allocate blockq\n");
        goto err_write_bq;
    }

    efd->counter = count;
    efd->io_event = false;
    efd->fd = allocate_fd(current->p, efd);
    if (efd->fd == INVALID_PHYSICAL) {
        msg_err("failed to allocate fd\n");
        apply(efd->f.close, 0, io_completion_ignore);
        return -EMFILE;
    }
    return efd->fd;

err_write_bq:
    deallocate_blockq(efd->read_bq);
err_read_bq:
    deallocate(h, efd, sizeof(*efd));
err_efd:
    return set_syscall_error(current, ENOMEM);
}
