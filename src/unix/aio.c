#include "unix_internal.h"
#include <page.h>

#define AIO_RING_MAGIC  0xa10a10a1

#define AIO_KNOWN_FLAGS IOCB_FLAG_RESFD

#define AIO_RESFD_INVALID   -1U

#define aio_lock(aio)   u64 _irqflags = spin_lock_irq(&(aio)->lock)
#define aio_unlock(aio) spin_unlock_irq(&(aio)->lock, _irqflags)

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
};

static struct aio *aio_alloc(process p, kernel_heaps kh, unsigned int *id)
{
    struct aio *aio = allocate(heap_general(get_kernel_heaps()),
            sizeof(*aio));
    if (aio == INVALID_ADDRESS) {
        return 0;
    }
    u64 aio_id = allocate_u64((heap)p->aio_ids, 1);
    if (aio_id == INVALID_PHYSICAL) {
        deallocate(heap_general(kh), aio, sizeof(*aio));
        return 0;
    }
    vector_set(p->aio, aio_id, aio);
    *id = (unsigned int) aio_id;
    aio->kh = kh;
    return aio;
}

static void aio_dealloc(process p, struct aio *aio, unsigned int id)
{
    vector_set(p->aio, id, 0);
    deallocate_u64((heap) p->aio_ids, id, 1);
    deallocate(heap_general(aio->kh), aio, sizeof(*aio));
}

static inline struct aio *aio_from_ring(process p, aio_ring ring)
{
    return (struct aio *) vector_get(p->aio, ring->id);
}

sysreturn io_setup(unsigned int nr_events, aio_context_t *ctx_idp)
{
    if (!ctx_idp) {
        return -EFAULT;
    }
    if (nr_events == 0) {
        return -EINVAL;
    }

    /* Allocate AIO ring structure and add it to process memory map.*/
    kernel_heaps kh = get_kernel_heaps();
    heap vh = (heap) current->p->virtual_page;
    aio_ring ctx;
    nr_events += 1; /* needed because of head/tail management in ring buffer */
    u64 alloc_size = pad(sizeof(*ctx) + nr_events * sizeof(struct io_event),
            PAGESIZE);
    ctx = (aio_ring) allocate_u64(vh, alloc_size);
    if (ctx == INVALID_ADDRESS) {
        return -ENOMEM;
    }
    u64 phys = allocate_u64((heap) heap_physical(kh), alloc_size);
    if (phys == INVALID_PHYSICAL) {
        deallocate(vh, ctx, alloc_size);
        return -ENOMEM;
    }
    map(u64_from_pointer(ctx), phys, alloc_size,
            PAGE_WRITABLE | PAGE_NO_EXEC | PAGE_USER, heap_pages(kh));

    struct aio *aio = aio_alloc(current->p, kh, &ctx->id);
    assert(aio);
    aio->vh = vh;
    aio->ring = ctx;
    spin_lock_init(&aio->lock);
    aio->bq = 0;
    aio->nr = nr_events;
    aio->ongoing_ops = 0;

    ctx->nr = nr_events;
    ctx->head = ctx->tail = 0;
    ctx->magic = AIO_RING_MAGIC;
    ctx->compat_features = 1;   /* same as Linux kernel */
    ctx->incompat_features = 0; /* same as Linux kernel */
    ctx->header_length = sizeof(*ctx);
    *ctx_idp = ctx;
    return 0;
}

closure_function(2, 2, void, aio_eventfd_complete,
                 heap, h, u64 *, efd_val,
                 thread, t, sysreturn, rv)
{
    u64 *efd_val = bound(efd_val);
    deallocate(bound(h), efd_val, sizeof(*efd_val));
    closure_finish();
}

closure_function(4, 2, void, aio_complete,
                 struct aio *, aio, u64, data, u64, obj, int, res_fd,
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
    aio_unlock(aio);
    if (res_fd != AIO_RESFD_INVALID) {
        fdesc res = resolve_fd_noret(t->p, res_fd);
        if (res && res->write) {
            heap h = heap_general(aio->kh);
            u64 *efd_val = allocate(h, sizeof(*efd_val));
            *efd_val = 1;
            io_completion completion = closure(h, aio_eventfd_complete, h,
                    efd_val);
            apply(res->write, efd_val, sizeof(*efd_val), 0, t, true,
                completion);
        }
    }
    if (aio->bq) {
        blockq_wake_one(aio->bq);
    }
    closure_finish();
}

static unsigned int aio_avail_events(struct aio *aio)
{
    aio_lock(aio);
    int avail = aio->ring->head - aio->ring->tail;
    aio_unlock(aio);
    if (avail <= 0) {
        avail += aio->nr;
    }
    return avail;
}

static sysreturn iocb_enqueue(struct aio *aio, struct iocb *iocb)
{
    if (!iocb) {
        return -EFAULT;
    }
    thread_log(current, "%s: fd %d, op %d", __func__, iocb->aio_fildes,
            iocb->aio_lio_opcode);

    fdesc f = resolve_fd(current->p, iocb->aio_fildes);
    if (aio->ongoing_ops >= aio_avail_events(aio) - 1) {
        return -EAGAIN;
    }
    if (iocb->aio_reserved1 || iocb->aio_reserved2 || !iocb->aio_buf ||
            (iocb->aio_flags & ~AIO_KNOWN_FLAGS)) {
        return -EINVAL;
    }

    int res_fd;
    if (iocb->aio_flags & IOCB_FLAG_RESFD) {
        res_fd = iocb->aio_resfd;
    } else {
        res_fd = AIO_RESFD_INVALID;
    }
    io_completion completion = closure(heap_general(aio->kh), aio_complete, aio,
            iocb->aio_data, (u64) iocb, res_fd);
    switch (iocb->aio_lio_opcode) {
    case IOCB_CMD_PREAD:
        if (!f->read) {
            goto inval;
        }
        apply(f->read, (void *) iocb->aio_buf, iocb->aio_nbytes,
                iocb->aio_offset, current, true, completion);
        break;
    case IOCB_CMD_PWRITE:
        if (!f->write) {
            goto inval;
        }
        apply(f->write, (void *) iocb->aio_buf, iocb->aio_nbytes,
                iocb->aio_offset, current, true, completion);
        break;
    default:
        goto inval;
    }
    aio_lock(aio);
    aio->ongoing_ops++;
    aio_unlock(aio);
    return 0;
inval:
    deallocate_closure(completion);
    return -EINVAL;
}

sysreturn io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp)
{
    struct aio *aio;
    if (!ctx_id) {
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
                return rv;
            } else {
                break;
            }
        }
    }
    return io_ops;
}

closure_function(6, 1, sysreturn, io_getevents_bh,
                 struct aio *, aio, long, min_nr, long, nr, struct io_event *, events, thread, t, io_completion, completion,
                 u64, flags)
{
    struct aio *aio = bound(aio);
    struct io_event *events = bound(events);
    thread t = bound(t);
    aio_ring ring = aio->ring;
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }

    aio_lock(aio);
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
    aio_unlock(aio);
    if ((aio->copied_evts < bound(min_nr)) &&
            !(flags & BLOCKQ_ACTION_TIMEDOUT)) {
        return BLOCKQ_BLOCK_REQUIRED;
    }
    rv = aio->copied_evts;
out:
    blockq_handle_completion(aio->bq, flags, bound(completion), t, rv);
    aio->bq = 0;
    closure_finish();
    return rv;
}

sysreturn io_getevents(aio_context_t ctx_id, long min_nr, long nr,
        struct io_event *events, struct timespec *timeout)
{
    if (!ctx_id || !events) {
        return -EFAULT;
    }
    struct aio *aio;
    if ((nr <= 0) || (nr < min_nr) ||
            !(aio = aio_from_ring(current->p, ctx_id))) {
        return -EINVAL;
    }
    aio->copied_evts = 0;
    aio->bq = current->thread_bq;
    return blockq_check_timeout(aio->bq, current,
            closure(heap_general(aio->kh), io_getevents_bh, aio, min_nr, nr,
                    events, current, syscall_io_complete), false,
            CLOCK_ID_MONOTONIC, timeout ? time_from_timespec(timeout) : 0,
            false);
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
        aio_ring ring = aio->ring;
        unsigned int aio_id = ring->id;
        u64 phys = physical_from_virtual(ring);
        u64 alloc_size = pad(sizeof(*ring) + aio->nr * sizeof(struct io_event),
                PAGESIZE);
        unmap(u64_from_pointer(ring), alloc_size, heap_pages(aio->kh));
        deallocate_u64((heap) heap_physical(aio->kh), phys, alloc_size);
        deallocate(aio->vh, ring, alloc_size);
        aio_dealloc(current->p, aio, aio_id);
        apply(syscall_io_complete, t, 0);
    }
    closure_finish();
}

static sysreturn io_destroy_internal(struct aio *aio, thread t, boolean in_bh)
{
    io_completion completion = closure(heap_general(aio->kh),
            io_destroy_complete, aio);
    assert(completion != INVALID_ADDRESS);
    unsigned int ongoing_ops = aio->ongoing_ops;
    if (ongoing_ops) {
        aio->copied_evts = 0;
        aio->bq = t->thread_bq;
        return blockq_check(aio->bq, t,
                closure(heap_general(aio->kh), io_getevents_bh, aio,
                        ongoing_ops, ongoing_ops, 0, t, completion), in_bh);
    } else {
        apply(completion, t, 0);
        return 0;
    }
}

sysreturn io_destroy(aio_context_t ctx_id)
{
    if (!ctx_id) {
        return -EFAULT;
    }
    struct aio *aio;
    if (!(aio = aio_from_ring(current->p, ctx_id))) {
        return -EINVAL;
    }
    return io_destroy_internal(aio, current, false);
}
