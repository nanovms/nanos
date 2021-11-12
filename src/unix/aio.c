#include "unix_internal.h"

#define AIO_RING_MAGIC  0xa10a10a1

#define AIO_KNOWN_FLAGS IOCB_FLAG_RESFD

#define AIO_RESFD_INVALID   -1U

#define aio_lock(aio)   spin_lock(&(aio)->lock)
#define aio_unlock(aio) spin_unlock(&(aio)->lock)

typedef struct aio_ring {
    unsigned int id;
    unsigned int nr;
    unsigned int head;
    unsigned int tail;
    unsigned int magic;
    unsigned int compat_features;
    unsigned int incompat_features;
    unsigned int header_length;
    struct io_event events[0];
} *aio_ring;

declare_closure_struct(1, 0, void, aio_free,
                       struct aio *, aio);

struct aio {
    struct list elem;  /* must be first */
    heap vh;
    kernel_heaps kh;
    aio_ring ring;
    struct spinlock lock;
    blockq bq;
    unsigned int nr;
    unsigned int ongoing_ops;
    unsigned int copied_evts;
    struct refcount refcount;
    closure_struct(aio_free, free);
};

static struct aio *aio_alloc(process p, kernel_heaps kh, unsigned int *id)
{
    struct aio *aio = allocate(heap_locked(get_kernel_heaps()),
            sizeof(*aio));
    if (aio == INVALID_ADDRESS) {
        return 0;
    }
    process_lock(p);
    u64 aio_id = allocate_u64((heap)p->aio_ids, 1);
    if ((aio_id != INVALID_PHYSICAL) && !vector_set(p->aio, aio_id, aio)) {
        deallocate_u64((heap)p->aio_ids, aio_id, 1);
        aio_id = INVALID_PHYSICAL;
    }
    process_unlock(p);
    if (aio_id == INVALID_PHYSICAL) {
        deallocate(heap_locked(kh), aio, sizeof(*aio));
        return 0;
    }
    *id = (unsigned int) aio_id;
    aio->kh = kh;
    return aio;
}

static inline struct aio *aio_from_ring(process p, aio_ring ring)
{
    process_lock(p);
    struct aio *aio = vector_get(p->aio, ring->id);
    refcount_reserve(&aio->refcount);
    process_unlock(p);
    return aio;
}

define_closure_function(1, 0, void, aio_free,
                        struct aio *, aio)
{
    struct aio *aio = bound(aio);
    aio_ring ring = aio->ring;
    u64 phys = physical_from_virtual(ring);
    u64 alloc_size = pad(sizeof(*ring) + aio->nr * sizeof(struct io_event), PAGESIZE);
    unmap(u64_from_pointer(ring), alloc_size);
    deallocate_u64((heap) heap_physical(aio->kh), phys, alloc_size);
    deallocate(aio->vh, ring, alloc_size);
    deallocate(heap_locked(aio->kh), aio, sizeof(*aio));
}

sysreturn io_setup(unsigned int nr_events, aio_context_t *ctx_idp)
{
    if (!validate_user_memory(ctx_idp, sizeof(aio_context_t), true)) {
        return -EFAULT;
    }
    if (nr_events == 0) {
        return -EINVAL;
    }

    /* Allocate AIO ring structure and add it to process memory map.*/
    kernel_heaps kh = get_kernel_heaps();
    aio_ring ctx;
    nr_events += 1; /* needed because of head/tail management in ring buffer */
    u64 alloc_size = pad(sizeof(*ctx) + nr_events * sizeof(struct io_event),
            PAGESIZE);
    u64 phys = allocate_u64((heap) heap_physical(kh), alloc_size);
    if (phys == INVALID_PHYSICAL) {
        return -ENOMEM;
    }
    ctx = (aio_ring)process_map_physical(current->p, phys, alloc_size,
        VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE);
    if (ctx == INVALID_ADDRESS) {
        deallocate_u64((heap)heap_physical(kh), phys, alloc_size);
        return -ENOMEM;
    }

    struct aio *aio = aio_alloc(current->p, kh, &ctx->id);
    assert(aio);
    aio->vh = current->p->virtual;
    aio->ring = ctx;
    spin_lock_init(&aio->lock);
    aio->bq = 0;
    aio->nr = nr_events;
    aio->ongoing_ops = 0;
    init_refcount(&aio->refcount, 1, init_closure(&aio->free, aio_free, aio));

    ctx->nr = nr_events;
    ctx->head = ctx->tail = 0;
    ctx->magic = AIO_RING_MAGIC;
    ctx->compat_features = 1;   /* same as Linux kernel */
    ctx->incompat_features = 0; /* same as Linux kernel */
    ctx->header_length = sizeof(*ctx);
    *ctx_idp = ctx;
    return 0;
}

closure_function(3, 2, void, aio_eventfd_complete,
                 heap, h, fdesc, f, u64 *, efd_val,
                 thread, t, sysreturn, rv)
{
    u64 *efd_val = bound(efd_val);
    deallocate(bound(h), efd_val, sizeof(*efd_val));
    fdesc_put(bound(f));
    closure_finish();
}

closure_function(5, 2, void, aio_complete,
                 struct aio *, aio, fdesc, f, u64, data, u64, obj, int, res_fd,
                 thread, t, sysreturn, rv)
{
    struct aio *aio = bound(aio);
    int res_fd = bound(res_fd);
    aio_ring ring = aio->ring;
    aio_lock(aio);
    aio->ongoing_ops--;
    unsigned int tail = ring->tail;
    if (tail >= aio->nr) {
        tail = 0;
    }
    ring->events[tail].data = bound(data);
    ring->events[tail].obj = bound(obj);
    ring->events[tail].res = rv;
    if (++tail == aio->nr) {
        tail = 0;
    }
    ring->tail = tail;
    blockq bq = aio->bq;
    if (bq)
        blockq_reserve(bq);
    aio_unlock(aio);
    fdesc_put(bound(f));
    if (res_fd != AIO_RESFD_INVALID) {
        fdesc res = fdesc_get(t->p, res_fd);
        if (res) {
            if (res->write && fdesc_is_writable(res)) {
                heap h = heap_locked(aio->kh);
                u64 *efd_val = allocate(h, sizeof(*efd_val));
                assert(efd_val != INVALID_ADDRESS);
                *efd_val = 1;
                io_completion completion = closure(h, aio_eventfd_complete, h, res, efd_val);
                apply(res->write, efd_val, sizeof(*efd_val), 0, t, true, completion);
            } else {
                fdesc_put(res);
            }
        }
    }
    if (bq) {
        blockq_wake_one(bq);
        blockq_release(bq);
    }
    closure_finish();
    refcount_release(&aio->refcount);
}

static unsigned int aio_avail_events(struct aio *aio)
{
    int avail = aio->ring->head - aio->ring->tail;
    if (avail <= 0) {
        avail += aio->nr;
    }
    return avail;
}

static sysreturn iocb_enqueue(struct aio *aio, struct iocb *iocb)
{
    if (!validate_user_memory(iocb, sizeof(struct iocb), false)) {
        return -EFAULT;
    }
    thread_log(current, "%s: fd %d, op %d", __func__, iocb->aio_fildes,
            iocb->aio_lio_opcode);

    if (iocb->aio_reserved1 || iocb->aio_reserved2 || !iocb->aio_buf ||
            (iocb->aio_flags & ~AIO_KNOWN_FLAGS)) {
        return -EINVAL;
    }

    fdesc f = resolve_fd(current->p, iocb->aio_fildes);
    aio_lock(aio);
    if (aio->ongoing_ops >= aio_avail_events(aio) - 1) {
        aio_unlock(aio);
        fdesc_put(f);
        return -EAGAIN;
    }
    aio->ongoing_ops++;
    aio_unlock(aio);
    int res_fd;
    if (iocb->aio_flags & IOCB_FLAG_RESFD) {
        res_fd = iocb->aio_resfd;
    } else {
        res_fd = AIO_RESFD_INVALID;
    }
    io_completion completion = closure(heap_locked(aio->kh), aio_complete, aio, f,
            iocb->aio_data, (u64) iocb, res_fd);
    refcount_reserve(&aio->refcount);
    sysreturn rv;
    switch (iocb->aio_lio_opcode) {
    case IOCB_CMD_PREAD:
        if (!f->read) {
            rv = -EINVAL;
            goto error;
        } else if (!fdesc_is_readable(f)) {
            rv = -EBADF;
            goto error;
        }
        apply(f->read, (void *) iocb->aio_buf, iocb->aio_nbytes,
                iocb->aio_offset, current, true, completion);
        break;
    case IOCB_CMD_PWRITE:
        if (!f->write) {
            rv = -EINVAL;
            goto error;
        } else if (!fdesc_is_writable(f)) {
            rv = -EBADF;
            goto error;
        }
        apply(f->write, (void *) iocb->aio_buf, iocb->aio_nbytes,
                iocb->aio_offset, current, true, completion);
        break;
    default:
        rv = -EINVAL;
        goto error;
    }
    return 0;
error:
    aio_lock(aio);
    aio->ongoing_ops--;
    aio_unlock(aio);
    refcount_release(&aio->refcount);
    deallocate_closure(completion);
    fdesc_put(f);
    return rv;
}

sysreturn io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp)
{
    struct aio *aio;
    if (!validate_user_memory(ctx_id, sizeof(struct aio_ring), false) ||
        !validate_user_memory(iocbpp, sizeof(struct iocb *) * nr, false)) {
        return -EFAULT;
    }
    if (!(aio = aio_from_ring(current->p, ctx_id))) {
        return -EINVAL;
    }
    int io_ops;
    for (io_ops = 0; io_ops < nr; io_ops++) {
        sysreturn rv = iocb_enqueue(aio, iocbpp[io_ops]);
        if (rv) {
            if (io_ops == 0) {
                io_ops = rv;
            }
            break;
        }
    }
    refcount_release(&aio->refcount);
    return io_ops;
}

/* Called with aio lock held (unless BLOCKQ_ACTION_BLOCKED is set in flags);
 * returns with aio lock released. */
closure_function(7, 1, sysreturn, io_getevents_bh,
                 struct aio *, aio, long, min_nr, long, nr, struct io_event *, events, thread, t, timestamp, timeout, io_completion, completion,
                 u64, flags)
{
    struct aio *aio = bound(aio);
    struct io_event *events = bound(events);
    thread t = bound(t);
    timestamp timeout = bound(timeout);
    aio_ring ring = aio->ring;
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_BLOCKED)
        aio_lock(aio);
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = (timeout == infinity) ? -ERESTARTSYS : -EINTR;
        goto out;
    }

    unsigned int head = ring->head;
    unsigned int tail = ring->tail;
    if (head >= aio->nr) {
        head = 0;
    }
    if (tail >= aio->nr) {
        tail = 0;
    }
    while (head != tail) {
        if (events) {
            runtime_memcpy(&events[aio->copied_evts], &ring->events[head],
                    sizeof(struct io_event));
        }
        if (++head == aio->nr) {
            head = 0;
        }
        if (++aio->copied_evts == bound(nr)) {
            break;
        }
    }
    ring->head = head;
    ring->tail = tail;
    if ((aio->copied_evts < bound(min_nr)) && (timeout != 0) &&
            !(flags & BLOCKQ_ACTION_TIMEDOUT)) {
        aio_unlock(aio);
        return blockq_block_required(t, flags);;
    }
    rv = aio->copied_evts;
out:
    aio->bq = 0;
    aio_unlock(aio);
    apply(bound(completion), t, rv);
    closure_finish();
    refcount_release(&aio->refcount);
    return rv;
}

sysreturn io_getevents(aio_context_t ctx_id, long min_nr, long nr,
        struct io_event *events, struct timespec *timeout)
{
    if (!validate_user_memory(ctx_id, sizeof(struct aio_ring), false) ||
        !validate_user_memory(events, sizeof(struct io_event) * nr, true) ||
        (timeout && !validate_user_memory(timeout, sizeof(struct timespec), false))) {
        return -EFAULT;
    }
    struct aio *aio;
    if ((nr <= 0) || (nr < min_nr) ||
            !(aio = aio_from_ring(current->p, ctx_id))) {
        return -EINVAL;
    }
    timestamp ts = timeout ? time_from_timespec(timeout) : infinity;
    aio_lock(aio);
    aio->copied_evts = 0;
    aio->bq = current->thread_bq;
    return blockq_check_timeout(aio->bq, current,
            closure(heap_locked(aio->kh), io_getevents_bh, aio, min_nr, nr,
                    events, current, ts, syscall_io_complete), false,
            CLOCK_ID_MONOTONIC, (ts == infinity) ? 0 : ts, false);
}

static sysreturn io_destroy_internal(struct aio *aio, thread t, boolean in_bh);

closure_function(1, 2, void, io_destroy_complete,
                 struct aio *, aio,
                 thread, t, sysreturn, rv)
{
    struct aio *aio = bound(aio);
    if (aio->ongoing_ops) {
        /* This can happen if io_getevents has been interrupted by a signal: try
         * again. */
        io_destroy_internal(aio, t, true);
    } else {
        refcount_release(&aio->refcount);
        apply(syscall_io_complete, t, 0);
    }
    closure_finish();
}

static sysreturn io_destroy_internal(struct aio *aio, thread t, boolean in_bh)
{
    io_completion completion = closure(heap_locked(aio->kh),
            io_destroy_complete, aio);
    assert(completion != INVALID_ADDRESS);
    aio_lock(aio);
    unsigned int ongoing_ops = aio->ongoing_ops;
    if (ongoing_ops) {
        aio->copied_evts = 0;
        aio->bq = t->thread_bq;
        refcount_reserve(&aio->refcount);
        return blockq_check(aio->bq, t,
                closure(heap_locked(aio->kh), io_getevents_bh, aio,
                        ongoing_ops, ongoing_ops, 0, t, infinity, completion), in_bh);
    } else {
        aio_unlock(aio);
        apply(completion, t, 0);
        return 0;
    }
}

sysreturn io_destroy(aio_context_t ctx_id)
{
    if (!validate_user_memory(ctx_id, sizeof(struct aio_ring), false)) {
        return -EFAULT;
    }
    unsigned int id = ctx_id->id;
    process p = current->p;
    process_lock(p);
    struct aio *aio = vector_get(p->aio, id);
    if (aio) {
        assert(vector_set(p->aio, id, 0));
        deallocate_u64((heap) p->aio_ids, id, 1);
    }
    process_unlock(p);
    if (!aio)
        return -EINVAL;
    return io_destroy_internal(aio, current, false);
}
