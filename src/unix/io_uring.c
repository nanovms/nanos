#include <unix_internal.h>

#define IORING_SETUP_CQSIZE     (1 << 3)

#define IORING_FEAT_SINGLE_MMAP     (1 << 0)
#define IORING_FEAT_RW_CUR_POS      (1 << 3)

#define IORING_OFF_SQ_RING  0ULL
#define IORING_OFF_CQ_RING  0x8000000ULL
#define IORING_OFF_SQES     0x10000000ULL

#define IORING_TIMEOUT_ABS  (1 << 0)

#define IORING_ENTER_GETEVENTS  (1 << 0)

#define IO_URING_OP_SUPPORTED   (1 << 0)

#define IOUR_SQ_ENTRIES_MAX 0x40000000UL
#define IOUR_CQ_ENTRIES_MAX (2 * IOUR_SQ_ENTRIES_MAX)
#define IOUR_FILES_MAX      0x8000

#define IOSQE_FIXED_FILE    (1 << 0)
#define IOSQE_ASYNC         (1 << 4)

//#define IOUR_DEBUG
#ifdef IOUR_DEBUG
#define iour_debug(x, ...) do { \
        tprintf(sym(iour), 0, "%s: " x "\n", __func__, ##__VA_ARGS__);   \
} while(0)
#else
#define iour_debug(x, ...)
#endif

struct io_uring_sqe {
    u8 opcode;
    u8 flags;
    u16 ioprio;
    s32 fd;
    u64 off;
    u64 addr;
    u32 len;
    union {
        u32 rw_flags;
        u32 fsync_flags;
        u16 poll_events;
        u32 sync_range_flags;
        u32 msg_flags;
        u32 timeout_flags;
    };
    u64 user_data;
    union{
        u16 buf_index;
        u64 __pad2[3];
    };
};

struct io_uring_cqe {
    u64 user_data;
    s32 res;
    u32 flags;
};

enum iour_enter_opcode {
    IORING_OP_NOP,
    IORING_OP_READV,
    IORING_OP_WRITEV,
    IORING_OP_FSYNC,
    IORING_OP_READ_FIXED,
    IORING_OP_WRITE_FIXED,
    IORING_OP_POLL_ADD,
    IORING_OP_POLL_REMOVE,
    IORING_OP_SYNC_FILE_RANGE,
    IORING_OP_SENDMSG,
    IORING_OP_RECVMSG,
    IORING_OP_TIMEOUT,
    IORING_OP_TIMEOUT_REMOVE,
    IORING_OP_ACCEPT,
    IORING_OP_ASYNC_CANCEL,
    IORING_OP_LINK_TIMEOUT,
    IORING_OP_CONNECT,
    IORING_OP_FALLOCATE,
    IORING_OP_OPENAT,
    IORING_OP_CLOSE,
    IORING_OP_FILES_UPDATE,
    IORING_OP_STATX,
    IORING_OP_READ,
    IORING_OP_WRITE,
    IORING_OP_LAST,
};

enum iour_register_opcode {
    IORING_REGISTER_BUFFERS,
    IORING_UNREGISTER_BUFFERS,
    IORING_REGISTER_FILES,
    IORING_UNREGISTER_FILES,
    IORING_REGISTER_EVENTFD,
    IORING_UNREGISTER_EVENTFD,
    IORING_REGISTER_FILES_UPDATE,
    IORING_REGISTER_EVENTFD_ASYNC,
    IORING_REGISTER_PROBE,
};

struct io_uring_files_update {
    u32 offset;
    u32 resv;
    s32 *fds;
};

struct io_uring_probe_op {
    u8 op;
    u8 resv;
    u16 flags;
    u32 resv2;
};

struct io_uring_probe {
    u8 last_op;
    u8 ops_len;
    u16 resv;
    u32 resv2[3];
    struct io_uring_probe_op ops[0];
};

typedef struct io_rings {
    u32 sq_head, sq_tail;
    u32 sq_mask, sq_entries;
    u32 sq_flags;
    u32 sq_dropped;
    u32 cq_head, cq_tail;
    u32 cq_mask, cq_entries;
    u32 cq_overflow;
    u32 pad;    /* for 8-byte alignment */
} *io_rings;

typedef struct io_uring {
    struct fdesc f;    /* must be first */
    heap h;
    u32 sq_mask, sq_entries;
    u32 cq_mask, cq_entries;
    io_rings rings;
    u32 *sq_array;
    struct io_uring_cqe *cqes;
    struct io_uring_sqe *sqes;
    u64 phys;
    closure_struct(fdesc_mmap, mmap);
    closure_struct(fdesc_close, close);
    struct iovec *bufs;
    u32 buf_count;
    fdesc *files;
    u32 file_count;
    blockq bq;
    u64 sigmask;
    fdesc eventfd;
    boolean eventfd_async;
    struct list pollers;
    struct list timers;
    u32 cq_timeouts;
    u64 noncancelable_ops;

    /* When true, the io_uring context is being shut down in the background,
     * i.e. no thread is blocked on close() and the context will be deallocated
     * when its last non-cancelable operation is completed. This can happen if
     * the file reference count is greater than 1 when close() is called, or if
     * an error occurs during close(). */
    boolean shutdown;

    io_completion shutdown_completion;
} *io_uring;

declare_closure_struct(2, 2, u64, iour_poll_notify,
                       io_uring, iour, struct iour_poll *, p,
                       u64, events, void *, arg);

typedef struct iour_poll {
    struct list l;
    u64 user_data;
    fdesc f;
    notify_entry ne;
    closure_struct(iour_poll_notify, handler);
    u64 events;
} *iour_poll;

declare_closure_struct(2, 2, void, iour_timeout,
                       io_uring, iour, struct iour_timer *, t,
                       u64, expiry, u64, overruns);

typedef struct iour_timer {
    struct list l;
    unsigned int target;
    u64 user_data;
    struct timer t;
    closure_struct(iour_timeout, handler);
} *iour_timer;

/* Mmapped region layout:
 * - Region 1
 *   - struct io_rings
 *   - array of sqe indices (sq_entries)
 *   - array of struct io_uring_cqe (cq_entries)
 * - Region 2
 *   - array of struct io_uring_sqe (sq_entries)
 */
#define IOUR_REGION1_SIZE(iour) \
        pad(sizeof(struct io_rings) + pad((iour)->sq_entries * sizeof(u32), 8) + \
        (iour)->cq_entries * sizeof(struct io_uring_cqe), PAGESIZE)
#define IOUR_REGION2_SIZE(iour) \
        pad((iour)->sq_entries * sizeof(struct io_uring_sqe), PAGESIZE)
#define IOUR_ALLOC_SIZE(iour) \
        (IOUR_REGION1_SIZE(iour) + IOUR_REGION2_SIZE(iour))

#define iour_from_fd(__p, __fd) ({fdesc f = fdesc_get(__p, __fd); \
    if (!f) return -EBADF; \
    if (f->type != FDESC_TYPE_IORING) {fdesc_put(f); return -EOPNOTSUPP;} \
    (io_uring)f;})

#define iour_lock(iour)     spin_lock(&(iour)->f.lock)
#define iour_unlock(iour)   spin_unlock(&(iour)->f.lock)

static void iour_release(io_uring iour)
{
    iour_debug("completion %p", iour->shutdown_completion);
    if (iour->file_count) {
        for (unsigned int i = 0; i < iour->file_count; i++)
            if (iour->files[i])
                fdesc_put(iour->files[i]);
        deallocate(iour->h, iour->files, sizeof(fdesc) * iour->file_count);
    }
    if (iour->buf_count)
        deallocate(iour->h, iour->bufs, sizeof(struct iovec) * iour->buf_count);
    u64 alloc_size = IOUR_ALLOC_SIZE(iour);
    release_fdesc(&iour->f);
    deallocate(iour->h, iour->rings, alloc_size);
    io_completion completion = iour->shutdown_completion;
    deallocate(iour->h, iour, sizeof(*iour));
    if (completion)
        apply(completion, 0);
}

static void iour_timer_remove(io_uring iour, iour_timer t)
{
    if (remove_timer(kernel_timers, &t->t, 0)) {
        deallocate(iour->h, t, sizeof(*t));
        fetch_and_add(&iour->noncancelable_ops, -1);
    }
}

closure_func_basic(fdesc_mmap, sysreturn, iour_mmap,
                   vmap vm, u64 offset)
{
    u64 len = range_span(vm->node.r);
    iour_debug("len %ld, flags 0x%x, offset 0x%x", len, vm->flags, offset);
    io_uring iour = struct_from_field(closure_self(), io_uring, mmap);
    u64 region_offset;
    switch (offset) {
    case IORING_OFF_SQ_RING:
    case IORING_OFF_CQ_RING:
        if (len > IOUR_REGION1_SIZE(iour))
            return -EINVAL;
        region_offset = 0;
        break;
    case IORING_OFF_SQES:
        if (len > IOUR_REGION2_SIZE(iour))
            return -EINVAL;
        region_offset = IOUR_REGION1_SIZE(iour);
        break;
    default:
        return -EINVAL;
    }
    if (vm->flags & VMAP_FLAG_EXEC)
        return -EACCES;
    u64 virt = vm->node.r.start;
    remap(virt, physical_from_virtual(iour->rings) + region_offset, len,
          pageflags_from_vmflags(vm->flags));
    vm->allowed_flags |= VMAP_FLAG_WRITABLE | VMAP_FLAG_READABLE;

    return virt;
}

closure_function(2, 1, sysreturn, iour_close_bh,
                 io_uring, iour, io_completion, completion,
                 u64, flags)
{
    io_uring iour = bound(iour);
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        iour->bq = 0;
        goto out;
    }
    if (flags & BLOCKQ_ACTION_BLOCKED)
        iour_lock(iour);
    if (iour->noncancelable_ops != 0) {
        iour_debug("blocking");
        iour_unlock(iour);
        return blockq_block_required((unix_context)get_current_context(current_cpu()), flags);
    }
    iour_release(iour);
    rv = 0;
out:
    apply(bound(completion), rv);
    closure_finish();
    iour_debug("returning %d", rv);
    return rv;
}

closure_func_basic(fdesc_close, sysreturn, iour_close,
                   context ctx, io_completion completion)
{
    io_uring iour = struct_from_field(closure_self(), io_uring, close);
    iour_debug("iour %p", iour);

    iour_lock(iour);
    list_foreach(&iour->timers, l) {
        iour_timer iour_tim = struct_from_list(l, iour_timer, l);
        iour_timer_remove(iour, iour_tim);
    }

    /* Pollers should be unregistered without the lock, to avoid deadlock if a notify handler is
     * executing when notify_remove() is called. */
    struct list deleted_items;
    list_move(&deleted_items, &iour->pollers);
    iour_unlock(iour);
    list_foreach(&deleted_items, l) {
        iour_poll poller = struct_from_list(l, iour_poll, l);
        notify_remove(poller->f->ns, poller->ne, false);
        fdesc_put(poller->f);
        deallocate(iour->h, poller, sizeof(*poller));
    }

    iour_lock(iour);
    if (iour->eventfd) {
        fdesc_put(iour->eventfd);
        iour->eventfd = 0;
    }
    if (ctx && is_syscall_context(ctx)) {
        if (iour->noncancelable_ops) {
            blockq_action ba = closure_from_context(ctx, iour_close_bh, iour, completion);
            if (ba != INVALID_ADDRESS) {
                iour->bq = ((syscall_context)ctx)->t->thread_bq;
                return blockq_check(iour->bq, ba, false);
            } else {
                iour->shutdown = true;
                iour_unlock(iour);
                return io_complete(completion, -ENOMEM);
            }
        } else {
            iour_release(iour);
            return io_complete(completion, 0);
        }
    }
    iour->shutdown_completion = completion;
    if (iour->noncancelable_ops) {
        iour->shutdown = true;
        iour_unlock(iour);
    } else
        iour_release(iour);
    return 0;
}

static void iour_rings_init(io_uring iour)
{
    io_rings rings = iour->rings;
    rings->sq_head = rings->sq_tail = 0;
    rings->sq_mask = iour->sq_mask;
    rings->sq_entries = iour->sq_entries;
    rings->sq_flags = 0;
    rings->sq_dropped = 0;
    rings->cq_head = rings->cq_tail = 0;
    rings->cq_mask = iour->cq_mask;
    rings->cq_entries = iour->cq_entries;
    rings->cq_overflow = 0;
}

sysreturn io_uring_setup(unsigned int entries, struct io_uring_params *params)
{
    if (!fault_in_user_memory(params, sizeof(*params), false))
        return -EFAULT;
    iour_debug("entries %d, flags 0x%x, CQ entries %d", entries, params->flags,
               params->cq_entries);
    if ((entries == 0) || (entries > IOUR_SQ_ENTRIES_MAX) ||
            (params->flags & ~IORING_SETUP_CQSIZE) || params->resv[0] ||
            params->resv[1] || params->resv[2] || params->resv[3])
        return -EINVAL;
    u32 sq_entries, cq_entries;
    sq_entries = U64_FROM_BIT(find_order(entries));
    if (params->flags & IORING_SETUP_CQSIZE) {
        if ((params->cq_entries < sq_entries) ||
                (params->cq_entries > IOUR_CQ_ENTRIES_MAX))
            return -EINVAL;
        cq_entries = U64_FROM_BIT(find_order(params->cq_entries));
    } else
        cq_entries = 2 * sq_entries;    /* Linux does that */

    sysreturn ret;
    kernel_heaps kh = get_kernel_heaps();
    heap h = heap_locked(kh);
    io_uring iour = allocate(h, sizeof(*iour));
    if (iour == INVALID_ADDRESS) {
        return -ENOMEM;
    }
    iour->h = h;
    iour->sq_entries = sq_entries;
    iour->sq_mask = iour->sq_entries - 1;
    iour->cq_entries = cq_entries;
    iour->cq_mask = iour->cq_entries - 1;

    u64 alloc_size = IOUR_ALLOC_SIZE(iour);
    iour_debug("allocating %ld bytes", alloc_size);
    iour->rings = (io_rings)allocate(h, alloc_size);
    if (iour->rings == INVALID_ADDRESS) {
        ret = -ENOMEM;
        goto err1;
    }
    iour->sq_array = (u32 *)((u8 *)iour->rings + sizeof(struct io_rings));
    iour->cqes = (struct io_uring_cqe *)((u8 *)iour->sq_array +
            pad(iour->sq_entries * sizeof(u32), 8));
    iour->sqes = (struct io_uring_sqe *)((u8 *)iour->rings +
            IOUR_REGION1_SIZE(iour));
    iour_debug("rings %p, SQ array %p, CQEs %p, SQEs %p", iour->rings,
               iour->sq_array, iour->cqes, iour->sqes);

    iour_rings_init(iour);
    iour->buf_count = iour->file_count = 0;
    iour->bq = 0;
    iour->eventfd = 0;
    list_init(&iour->pollers);
    list_init(&iour->timers);
    iour->cq_timeouts = 0;
    iour->noncancelable_ops = 0;
    iour->shutdown = false;
    iour->shutdown_completion = 0;
    init_fdesc(h, &iour->f, FDESC_TYPE_IORING);
    iour->f.mmap = init_closure_func(&iour->mmap, fdesc_mmap, iour_mmap);
    iour->f.close = init_closure_func(&iour->close, fdesc_close, iour_close);
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        ret = -EFAULT;
        goto err3;
    }
    params->features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_RW_CUR_POS;
    params->sq_entries = sq_entries;
    params->sq_off.head = offsetof(io_rings, sq_head);
    params->sq_off.tail = offsetof(io_rings, sq_tail);
    params->sq_off.ring_mask = offsetof(io_rings, sq_mask);
    params->sq_off.ring_entries = offsetof(io_rings, sq_entries);
    params->sq_off.flags = offsetof(io_rings, sq_flags);
    params->sq_off.dropped = offsetof(io_rings, sq_dropped);
    params->sq_off.array = (u8 *)iour->sq_array - (u8 *)iour->rings;
    runtime_memset((u8 *)params->sq_off.resv, 0, sizeof(params->sq_off.resv));
    params->cq_entries = cq_entries;
    params->cq_off.head = offsetof(io_rings, cq_head);
    params->cq_off.tail = offsetof(io_rings, cq_tail);
    params->cq_off.ring_mask = offsetof(io_rings, cq_mask);
    params->cq_off.ring_entries = offsetof(io_rings, cq_entries);
    params->cq_off.overflow = offsetof(io_rings, cq_overflow);
    params->cq_off.cqes = (u8 *)iour->cqes - (u8 *)iour->rings;
    runtime_memset((u8 *)params->cq_off.resv, 0, sizeof(params->cq_off.resv));
    context_clear_err(ctx);
    ret = allocate_fd(current->p, iour);
    if (ret == INVALID_PHYSICAL) {
        apply(iour->f.close, 0, io_completion_ignore);
        return -EMFILE;
    }
    iour_debug("fd %d", ret);
    return ret;
err3:
    deallocate(h, iour->rings, alloc_size);
err1:
    deallocate(h, iour, sizeof(*iour));
    return ret;
}

simple_closure_function(1, 1, void, iour_efd_complete,
                        u64, efd_val,
                        sysreturn, rv)
{
    closure_finish();
}

static void iour_complete_locked(io_uring iour, u64 user_data, s32 res,
                                 boolean async)
{
    io_rings rings = iour->rings;
    iour_debug("user_data %ld, res %d, CQ tail %d", user_data, res,
               rings->cq_tail);
    if (rings->cq_tail < rings->cq_head + iour->cq_entries) {
        struct io_uring_cqe *cqe = &iour->cqes[rings->cq_tail & iour->cq_mask];
        cqe->user_data = user_data;
        cqe->res = res;
        cqe->flags = 0;
        write_barrier();
        rings->cq_tail++;
    } else {
        iour_debug("overflow");
        rings->cq_overflow++;
    }
    if (iour->eventfd && (async || !iour->eventfd_async)) {
        closure_new(iour->h, iour_efd_complete, completion);
        if (completion != INVALID_ADDRESS) {
            completion->efd_val = 1;
            apply(iour->eventfd->write, &completion->efd_val,
                  sizeof(completion->efd_val), 0, get_current_context(current_cpu()), true,
                  closure_get(iour_efd_complete, completion));
        }
    }
}

static void iour_complete(io_uring iour, u64 user_data, s32 res,
                          boolean async, boolean noncancelable)
{
    iour_lock(iour);
    iour_complete_locked(iour, user_data, res, async);
    if (noncancelable) {
        if ((fetch_and_add(&iour->noncancelable_ops, -1) == 1) &&
                iour->shutdown) {
            iour_release(iour);
            return;
        }
    }
    struct list deleted_timers;
    list_init(&deleted_timers);
check_timers:
    list_foreach(&iour->timers, l) {
        iour_timer iour_tim = struct_from_list(l, iour_timer, l);
        if (iour_tim->target == iour->rings->cq_tail + iour->rings->cq_overflow) {
            list_delete(l);
            list_push_back(&deleted_timers, l);
            iour->cq_timeouts++;
            iour_complete_locked(iour, iour_tim->user_data, 0, async);

            /* Increment the target of any remaining timers, to compensate the
             * CQ tail increment due to the just completed timeout, then go
             * through the timer list again. */
            list_foreach(&iour->timers, l) {
                iour_timer iour_tim = struct_from_list(l, iour_timer, l);
                iour_tim->target++;
            }
            goto check_timers;
        }
    }
    blockq bq = iour->bq;
    if (bq)
        blockq_reserve(bq);
    iour_unlock(iour);
    list_foreach(&deleted_timers, l) {
        iour_timer iour_tim = struct_from_list(l, iour_timer, l);
        iour_timer_remove(iour, iour_tim);
    }
    if (bq) {
        blockq_wake_one(bq);
        blockq_release(bq);
    }
}

static void iour_complete_timeout(io_uring iour, u64 user_data)
{
    iour_lock(iour);
    iour->cq_timeouts++;
    iour_complete_locked(iour, user_data, -ETIME, true);
    blockq bq = iour->bq;
    if (bq)
        blockq_reserve(bq);
    iour_unlock(iour);
    if (bq) {
        blockq_wake_one(bq);
        blockq_release(bq);
    }
}

closure_function(3, 1, void, iour_rw_complete,
                 io_uring, iour, fdesc, f, u64, user_data,
                 sysreturn, rv)
{
    fdesc_put(bound(f));
    iour_complete(bound(iour), bound(user_data), rv, true, true);
    closure_finish();
}

static void iour_iov(io_uring iour, fdesc f, boolean write, struct iovec *iov,
                     u32 len, u64 off, u64 user_data)
{
    io_completion completion = closure(iour->h, iour_rw_complete, iour, f,
        user_data);
    process_context pc;
    if (completion != INVALID_ADDRESS) {
        pc = get_process_context();
        if (pc == INVALID_ADDRESS) {
            deallocate_closure(completion);
            completion = INVALID_ADDRESS;
        }
    }
    if (completion == INVALID_ADDRESS) {
        fdesc_put(f);
        iour_complete(iour, user_data, -ENOMEM, false, false);
    } else {
        fetch_and_add(&iour->noncancelable_ops, 1);
        iov_op(f, write, iov, len, off, &pc->uc.kc.context, false, completion);
    }
}

static void iour_rw(io_uring iour, fdesc f, boolean write, void *addr, u32 len,
                    u64 offset, u64 user_data)
{
    iour_debug("%s at %p, len %d, offset %ld", write ? "write" : "read", addr,
            len, offset);
    int err = 0;
    file_io op = write ? f->write : f->read;
    process_context pc;
    io_completion completion = 0;
    if (!op) {
        err = -EOPNOTSUPP;
    } else if ((write && !fdesc_is_writable(f)) ||
            (!write && !fdesc_is_readable(f))) {
        err = -EBADF;
    } else {
        completion = closure(iour->h, iour_rw_complete, iour, f, user_data);
        if (completion != INVALID_ADDRESS) {
            pc = get_process_context();
            if (pc == INVALID_ADDRESS) {
                deallocate_closure(completion);
                completion = INVALID_ADDRESS;
            }
        }
        if (completion == INVALID_ADDRESS)
            err = -ENOMEM;
    }
    if (err) {
        fdesc_put(f);
        iour_complete(iour, user_data, err, false, false);
    } else {
        fetch_and_add(&iour->noncancelable_ops, 1);
        apply(op, addr, len, offset, &pc->uc.kc.context, true, completion);
    }
}

define_closure_function(2, 2, u64, iour_poll_notify,
                        io_uring, iour, iour_poll, p,
                        u64, events, void *, arg)
{
    if (!events)
        return false;
    u64 rv = 0;
    io_uring iour = bound(iour);
    iour_poll p = bound(p);
    iour_lock(iour);
    boolean found = list_find(&iour->pollers, &p->l);
    if (found) {
        list_delete(&p->l);
    } else {
        p->events = events;
    }
    iour_unlock(iour);
    if (found) {
        iour_debug("user_data %ld, events %ld", p->user_data, events);
        iour_complete(iour, p->user_data, events, true, false);
        rv = NOTIFY_RESULT_RELEASE;
        fdesc_put(p->f);
        deallocate(iour->h, p, sizeof(*p));
    }
    return rv;
}

static void iour_poll_add(io_uring iour, fdesc f, u16 events, u64 user_data)
{
    s32 err = 0;
    iour_poll p = allocate(iour->h, sizeof(*p));
    if (p == INVALID_ADDRESS) {
        err = -ENOMEM;
        goto done;
    }
    p->user_data = user_data;
    p->f = f;
    p->events = 0;
    p->ne = notify_add(f->ns, events | EPOLLERR | EPOLLHUP,
        init_closure(&p->handler, iour_poll_notify, iour, p));
    if (p->ne == INVALID_ADDRESS) {
        err = -ENOMEM;
        deallocate(iour->h, p, sizeof(*p));
    }
    iour_lock(iour);
    if (!p->events)
        list_push_back(&iour->pollers, &p->l);
    else {
        /* Poll events have been notified already. */
        iour_unlock(iour);
        iour_complete(iour, p->user_data, p->events, false, false);
        notify_remove(p->f->ns, p->ne, false);
        fdesc_put(p->f);
        deallocate(iour->h, p, sizeof(*p));
        return;
    }
    iour_unlock(iour);
done:
    if (!err) {
        if (f->events)
            /* Check if poll events are already present. */
            notify_dispatch_for_thread(f->ns, apply(f->events, current),
                current);
    } else
        iour_complete(iour, user_data, err, false, false);
}

static void iour_poll_remove(io_uring iour, u64 addr, u64 user_data)
{
    iour_poll p = 0;
    s32 res;
    iour_lock(iour);
    list_foreach(&iour->pollers, l) {
        iour_poll elem = struct_from_list(l, iour_poll, l);
        if (elem->user_data == addr) {
            p = elem;
            list_delete(l);
            break;
        }
    }
    iour_unlock(iour);
    if (p) {
        iour_complete(iour, addr, -ECANCELED, false, false);
        res = 0;
        notify_remove(p->f->ns, p->ne, false);
        fdesc_put(p->f);
        deallocate(iour->h, p, sizeof(*p));
    } else
        res = -ENOENT;
    iour_complete(iour, user_data, res, false, false);
}

define_closure_function(2, 2, void, iour_timeout,
                        io_uring, iour, iour_timer, t,
                        u64, expiry, u64, overruns)
{
    if (overruns == timer_disabled)
        return;

    io_uring iour = bound(iour);
    iour_timer t = bound(t);
    iour_lock(iour);
    boolean found = list_find(&iour->timers, &t->l);
    if (found)
        list_delete(&t->l);
    iour_unlock(iour);
    if (found) {
        iour_debug("user_data %ld", t->user_data);
        iour_complete_timeout(iour, t->user_data);
    }
    deallocate(iour->h, t, sizeof(*t));
    if ((fetch_and_add(&iour->noncancelable_ops, -1) == 1) && iour->shutdown)
        iour_release(iour);
}

static void iour_timeout_add(io_uring iour, struct timespec *ts, u32 flags,
                             u64 off, u64 user_data)
{
    iour_debug("flags 0x%x, off %ld", flags, off);
    int err = 0;
    if (flags & ~IORING_TIMEOUT_ABS) {
        err = -EINVAL;
        goto done;
    }
    iour_timer iour_tim = allocate(iour->h, sizeof(*iour_tim));
    if (iour_tim == INVALID_ADDRESS) {
        err = -ENOMEM;
        goto done;
    }
    iour_tim->user_data = user_data;
    init_timer(&iour_tim->t);
    iour_lock(iour);

    /* off == 0 indicates a pure timeout request, i.e. one not linked to
     * completion of other requests; in this case, the target is set to the last
     * completion (i.e. a past completion), so that it won't match future
     * completions (until after UINT_MAX operations, at which point the timeout
     * will have elapsed already, hopefully). */
    iour_tim->target = iour->rings->cq_tail + off;
    iour_debug("target %ld", iour_tim->target);

    /* Timeouts are counted as non-cancelable_operations because the ability to remove a kernel
     * timer synchronously is not guaranteed in SMP machines. */
    fetch_and_add(&iour->noncancelable_ops, 1);

    list_push_back(&iour->timers, &iour_tim->l);
    register_timer(kernel_timers, &iour_tim->t, CLOCK_ID_MONOTONIC,
        time_from_timespec(ts), flags & IORING_TIMEOUT_ABS, 0,
        init_closure(&iour_tim->handler, iour_timeout, iour, iour_tim));
    iour_unlock(iour);
done:
    if (err)
        iour_complete(iour, user_data, err, false, false);
}

static void iour_timeout_remove(io_uring iour, u64 addr, u64 user_data)
{
    iour_timer t = 0;
    s32 res;
    iour_lock(iour);
    list_foreach(&iour->timers, l) {
        iour_timer elem = struct_from_list(l, iour_timer, l);
        if (elem->user_data == addr) {
            t = elem;
            list_delete(l);
            break;
        }
    }
    iour_unlock(iour);
    if (t) {
        iour_timer_remove(iour, t);
        iour_complete(iour, addr, -ECANCELED, false, false);
        res = 0;
    } else
        res = -ENOENT;
    iour_complete(iour, user_data, res, false, false);
}

closure_function(2, 1, void, iour_close_complete,
                 io_uring, iour, u64, user_data,
                 sysreturn, rv)
{
    iour_complete(bound(iour), bound(user_data), rv, true, true);
    closure_finish();
}

static int iour_register_files_update(io_uring iour, int *fds,
                                      unsigned int count, unsigned int offset)
{
    iour_debug("count %d, offset %d", count, offset);
    if ((count == 0) || (count > IOUR_FILES_MAX) || (offset >= IOUR_FILES_MAX))
        return -EINVAL;
    if (!fault_in_user_memory(fds, sizeof(fds[0]) * count, false))
        return -EFAULT;
    sysreturn ret;
    iour_lock(iour);
    if (offset + count > iour->file_count)
        ret = -EINVAL;
    else {
        ret = 0;
        for (unsigned int i = 0; i < count; i++) {
            fdesc f;
            if (fds[i] == -1)
                f = 0;
            else {
                f = fdesc_get(current->p, fds[i]);
                if (!f) {
                    iour_debug("invalid fd %d", fds[i]);
                    ret = -EBADF;
                }
            }
            if (!ret) {
                fdesc old = iour->files[offset + i];
                if (old)
                    fdesc_put(old);
                iour->files[offset + i] = f;
            } else {
                if (i > 0)
                    ret = i;
                break;
            }
        }
    }
    iour_unlock(iour);
    if (!ret)
        ret = count;
    return ret;
}

static boolean iour_submit(io_uring iour, struct io_uring_sqe *sqe)
{
    iour_debug("opcode %d, flags 0x%x, user_data %ld", sqe->opcode, sqe->flags,
        sqe->user_data);
    fdesc f = 0;
    s32 res;
    if (sqe->flags & ~(IOSQE_FIXED_FILE | IOSQE_ASYNC)) {
        /* non-supported flags */
        res = -EINVAL;
        goto complete;
    }
    switch(sqe->opcode) {
    case IORING_OP_READV:
    case IORING_OP_WRITEV:
    case IORING_OP_READ_FIXED:
    case IORING_OP_WRITE_FIXED:
    case IORING_OP_POLL_ADD:
    case IORING_OP_READ:
    case IORING_OP_WRITE:
        if (sqe->flags & IOSQE_FIXED_FILE) {
            iour_lock(iour);
            int fd = sqe->fd;
            if ((fd >= 0) && (fd < iour->file_count)) {
                f = iour->files[fd];
                if (f)
                    f->refcnt++;
            }
            iour_unlock(iour);
        } else
            f = fdesc_get(current->p, sqe->fd);
        if (!f) {
            res = -EBADF;
            goto complete;
        }
        break;
    default:
        break;
    }
    switch (sqe->opcode) {
    case IORING_OP_NOP:
        res = 0;
        goto complete;
    case IORING_OP_READV:
    case IORING_OP_WRITEV: {
        if (sqe->buf_index) {
            res = -EINVAL;
            goto complete;
        }
        struct iovec *iov = pointer_from_u64(sqe->addr);
        u32 len = sqe->len;
        boolean write = (sqe->opcode == IORING_OP_WRITEV);
        if (!validate_iovec(iov, len, !write)) {
            res = -EFAULT;
            goto complete;
        }
        iour_iov(iour, f, write, iov, len, sqe->off, sqe->user_data);
        break;
    }
    case IORING_OP_READ_FIXED:
    case IORING_OP_WRITE_FIXED:
        res = 0;
        iour_lock(iour);
        u16 buf_index = sqe->buf_index;
        if (buf_index >= iour->buf_count) {
            if (iour->buf_count != 0)
                res = -EINVAL;
            else
                res = -EFAULT;
        } else {
            struct iovec *iov = &iour->bufs[buf_index];
            void *buf = pointer_from_u64(sqe->addr);
            u32 len = sqe->len;
            boolean write = sqe->opcode == IORING_OP_WRITE_FIXED;
            if ((buf < iov->iov_base) || (u64_from_pointer(buf) + len >
                    u64_from_pointer(iov->iov_base) + iov->iov_len)) {
                res = -EFAULT;
            } else {
                iour_unlock(iour);
                iour_rw(iour, f, write, buf, len, sqe->off, sqe->user_data);
                return true;
            }
        }
        iour_unlock(iour);
        goto complete;
    case IORING_OP_POLL_ADD:
        if (sqe->ioprio || sqe->off || sqe->addr || sqe->len ||
                sqe->buf_index) {
            res = -EINVAL;
            goto complete;
        }
        iour_poll_add(iour, f, sqe->poll_events, sqe->user_data);
        break;
    case IORING_OP_POLL_REMOVE:
        if (sqe->ioprio || sqe->off || sqe->len || sqe->poll_events ||
                sqe->buf_index) {
            res = -EINVAL;
            goto complete;
        }
        iour_poll_remove(iour, sqe->addr, sqe->user_data);
        break;
    case IORING_OP_TIMEOUT: {
        struct timespec *ts = (struct timespec *)sqe->addr;
        if (sqe->ioprio || (sqe->len != 1) || sqe->buf_index) {
            res = -EINVAL;
            goto complete;
        }
        if (!validate_user_memory(ts, sizeof(*ts), false)) {
            res = -EFAULT;
            goto complete;
        }
        iour_timeout_add(iour, ts, sqe->timeout_flags, sqe->off,
                         sqe->user_data);
        break;
    }
    case IORING_OP_TIMEOUT_REMOVE:
        if (sqe->ioprio || sqe->len || sqe->buf_index || sqe->timeout_flags) {
            res = -EINVAL;
            goto complete;
        }
        iour_timeout_remove(iour, sqe->addr, sqe->user_data);
        break;
    case IORING_OP_CLOSE:
        if (sqe->ioprio || sqe->addr || sqe->len || sqe->off || sqe->buf_index
                || sqe->rw_flags) {
            res = -EINVAL;
            goto complete;
        }
        int fd = sqe->fd;
        if ((sqe->flags & IOSQE_FIXED_FILE) ||
                !(f = fdesc_get(current->p, fd)) || (f == &iour->f)) {
            res = -EBADF;
            goto complete;
        }
        iour_debug("closing fd %d", fd);
        deallocate_fd(current->p, fd);
        if (fetch_and_add(&f->refcnt, -2) == 2) {
            process_context pc;
            io_completion completion = closure(iour->h, iour_close_complete,
                iour, sqe->user_data);
            if (completion != INVALID_ADDRESS) {
                pc = get_process_context();
                if (pc == INVALID_ADDRESS) {
                    deallocate_closure(completion);
                    completion = INVALID_ADDRESS;
                }
            }
            if (completion == INVALID_ADDRESS) {
                iour_complete(iour, sqe->user_data, -ENOMEM, false, false);
                pc = 0;
                completion = io_completion_ignore;
            } else
                fetch_and_add(&iour->noncancelable_ops, 1);
            apply(f->close, (context)pc, completion);
        } else
            iour_complete(iour, sqe->user_data, 0, false, false);
        return true;
    case IORING_OP_FILES_UPDATE:
        if (sqe->flags || sqe->ioprio || sqe->rw_flags) {
            res = -EINVAL;
            goto complete;
        }
        res = iour_register_files_update(iour, (int *)sqe->addr, sqe->len,
            sqe->off);
        goto complete;
    case IORING_OP_READ:
    case IORING_OP_WRITE:
        if (sqe->buf_index) {
            res = -EINVAL;
            goto complete;
        } else {
            void *buf = pointer_from_u64(sqe->addr);
            u32 len = sqe->len;
            boolean write = sqe->opcode == IORING_OP_WRITE;

            if (!validate_user_memory(buf, len, !write)) {
                res = -EFAULT;
                goto complete;
            }
            iour_rw(iour, f, write, buf, len, sqe->off, sqe->user_data);
        }
        break;
    default:
        iour_complete(iour, sqe->user_data, -EINVAL, false, false);
        return false;
    }
    return true;
complete:
    iour_complete(iour, sqe->user_data, res, false, false);
    if (f)
        fdesc_put(f);
    return true;
}

simple_closure_function(7, 1, sysreturn, iour_getevents_bh,
                        io_uring, iour, sysreturn, submitted, unsigned int, min_complete, unsigned int, timeouts, boolean, sig_set, thread, t, io_completion, completion,
                        u64, flags)
{
    io_uring iour = bound(iour);
    if (flags & BLOCKQ_ACTION_BLOCKED)
        iour_lock(iour);
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        if (bound(submitted))
            rv = bound(submitted);
        else
            rv = -ERESTARTSYS;
        iour->bq = 0;
        goto out;
    }
    iour_debug("CQ head %d, CQ tail %d",iour->rings->cq_head,
               iour->rings->cq_tail);
    if ((iour->rings->cq_tail - iour->rings->cq_head < bound(min_complete)) &&
            (iour->cq_timeouts == bound(timeouts)))
        rv = BLOCKQ_BLOCK_REQUIRED;
    else {
        rv = bound(submitted);
        iour->bq = 0;
    }
out:
    iour_unlock(iour);
    if (rv == BLOCKQ_BLOCK_REQUIRED) {
        iour_debug("blocking");
        return blockq_block_required((unix_context)get_current_context(current_cpu()), flags);
    }
    thread t = bound(t);
    if (bound(sig_set))
        t->signal_mask = iour->sigmask;
    apply(bound(completion), rv);
    closure_finish();
    iour_debug("returning %d", rv);
    fdesc_put(&iour->f);
    return rv;
}

sysreturn io_uring_enter(int fd, unsigned int to_submit,
                         unsigned int min_complete, unsigned int flags,
                         sigset_t *sig)
{
    iour_debug("fd %d, to_submit %d, min_complete %d, flags 0x%x, sig %p", fd,
        to_submit, min_complete, flags, sig);
    io_uring iour = iour_from_fd(current->p, fd);
    sysreturn rv;
    if (flags & ~IORING_ENTER_GETEVENTS) {
        rv = -EINVAL;
        goto out;
    }
    u64 sigmask;
    if (sig && !get_user_value(sig, &sigmask)) {
        rv = -EFAULT;
        goto out;
    }
    closure_ref(iour_getevents_bh, bh) = 0;
    if (flags & IORING_ENTER_GETEVENTS) {
        contextual_closure_alloc(iour_getevents_bh, bh);
        if (bh == INVALID_ADDRESS) {
            rv = -ENOMEM;
            goto out;
        }
    }
    io_rings rings = iour->rings;
    read_barrier();
    iour_debug("SQ head %d, SQ tail %d", rings->sq_head, rings->sq_tail);
    unsigned int submitted;
    for (submitted = 0; submitted < to_submit;) {
        iour_lock(iour);
        if (rings->sq_head >= rings->sq_tail) {
            iour_unlock(iour);
            break;
        }
        u32 sqe_index = iour->sq_array[rings->sq_head & iour->sq_mask];
        rings->sq_head++;
        iour_unlock(iour);
        if (sqe_index < iour->sq_entries) {
            submitted++;
            if (!iour_submit(iour, &iour->sqes[sqe_index]))
                break;
        } else {
            iour_debug("sqe dropped: index %d, entries %d", sqe_index,
                iour->sq_entries);
            iour_lock(iour);
            iour->rings->sq_dropped++;
            iour_unlock(iour);
            break;
        }
    }
    cpuinfo ci = current_cpu();
    syscall_context sc = (syscall_context)get_current_context(ci);
    assert(is_syscall_context(&sc->uc.kc.context));
    rv = submitted;
    if (flags & IORING_ENTER_GETEVENTS) {
        iour_lock(iour);
        if (iour->bq) {
            /* Another thread is waiting on this instance, and waiting in parallel from multiple
             * threads is not supported. */
            iour_unlock(iour);
            goto out;
        }
        if (sig) {
            iour->sigmask = current->signal_mask;
            current->signal_mask = sigmask;
            bh->sig_set = true;
        } else
            bh->sig_set = false;
        iour->bq = current->thread_bq;
        bh->iour = iour;
        bh->submitted = submitted;
        bh->min_complete = min_complete;
        bh->timeouts = iour->cq_timeouts;
        bh->t = current;
        bh->completion = syscall_io_complete;
        return blockq_check(iour->bq,
            closure_get(iour_getevents_bh, bh), false);
    }
out:
    fdesc_put(&iour->f);
    return rv;
}

static sysreturn iour_register_buffers(io_uring iour, struct iovec *bufs,
                                       unsigned int count)
{
    if ((count == 0) || (count > IOV_MAX))
        return -EINVAL;
    sysreturn ret;
    iour_lock(iour);
    if (iour->buf_count)
        ret = -EBUSY;
    else {
        iour->bufs = allocate(iour->h, sizeof(struct iovec) * count);
        if (iour->bufs == INVALID_ADDRESS) {
            ret = -ENOMEM;
        } else {
            runtime_memcpy(iour->bufs, bufs, sizeof(struct iovec) * count);
            iour->buf_count = count;
            ret = 0;
        }
    }
    iour_unlock(iour);
    return ret;
}

static sysreturn iour_unregister_buffers(io_uring iour)
{
    sysreturn ret;
    iour_lock(iour);
    if (iour->buf_count == 0)
        ret = -ENXIO;
    else {
        deallocate(iour->h, iour->bufs, sizeof(struct iovec) * iour->buf_count);
        iour->buf_count = 0;
        ret = 0;
    }
    iour_unlock(iour);
    return ret;
}

static sysreturn iour_register_files(io_uring iour, s32 *fds,
                                     unsigned int count)
{
    if ((count == 0) || (count > IOUR_FILES_MAX))
        return -EINVAL;
    sysreturn ret;
    iour_lock(iour);
    if (iour->file_count)
        ret = -EBUSY;
    else {
        iour->files = allocate(iour->h, sizeof(fdesc) * count);
        if (iour->files == INVALID_ADDRESS) {
            ret = -ENOMEM;
        } else {
            ret = 0;
            for (int i = 0; i < count; i++) {
                if (fds[i] == -1)
                    iour->files[i] = 0;
                else {
                    iour_debug("registering fd %d", fds[i]);
                    iour->files[i] = fdesc_get(current->p, fds[i]);
                    if (!iour->files[i]) {
                        while (--i >= 0)
                            if (iour->files[i])
                                fdesc_put(iour->files[i]);
                        deallocate(iour->h, iour->files, sizeof(fdesc) * count);
                        ret = -EBADF;
                        break;
                    }
                }
            }
            if (ret == 0)
                iour->file_count = count;
        }
    }
    iour_unlock(iour);
    return ret;
}

static sysreturn iour_unregister_files(io_uring iour)
{
    iour_lock(iour);
    if (iour->file_count == 0) {
        iour_unlock(iour);
        return -ENXIO;
    }
    for (unsigned int i = 0; i < iour->file_count; i++)
        if (iour->files[i])
            fdesc_put(iour->files[i]);
    deallocate(iour->h, iour->files, sizeof(fdesc) * iour->file_count);
    iour->file_count = 0;
    iour_unlock(iour);
    return 0;
}

static sysreturn iour_register_eventfd(io_uring iour, int fd, boolean async)
{
    sysreturn ret;
    iour_lock(iour);
    if (iour->eventfd)
        ret = -EBUSY;
    else {
        iour->eventfd = fdesc_get(current->p, fd);
        if (iour->eventfd) {
            if (iour->eventfd->type == FDESC_TYPE_EVENTFD) {
                iour->eventfd_async = async;
                ret = 0;
            } else {
                fdesc_put(iour->eventfd);
                iour->eventfd = 0;
                ret = -EINVAL;
            }
        } else
            ret = -EBADF;
    }
    iour_unlock(iour);
    return ret;
}

static sysreturn iour_unregister_eventfd(io_uring iour)
{
    sysreturn ret;
    iour_lock(iour);
    if (!iour->eventfd)
        ret = -ENXIO;
    else {
        fdesc_put(iour->eventfd);
        iour->eventfd = 0;
        ret = 0;
    }
    iour_unlock(iour);
    return ret;
}

static sysreturn iour_register_probe(struct io_uring_probe *probe,
                                     unsigned int op_count)
{
    iour_debug("op_count %d", op_count);
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return -EFAULT;
    probe->last_op = IORING_OP_LAST - 1;
    if (op_count > IORING_OP_LAST)
        op_count = IORING_OP_LAST;
    zero(probe->ops, sizeof(probe->ops[0]) * op_count);
    for (unsigned int i = 0; i < op_count; i++)
        probe->ops[i].op = i;
    probe->ops_len = op_count;
    probe->ops[IORING_OP_NOP].flags = probe->ops[IORING_OP_READV].flags =
            probe->ops[IORING_OP_WRITEV].flags =
            probe->ops[IORING_OP_READ_FIXED].flags =
            probe->ops[IORING_OP_WRITE_FIXED].flags =
            probe->ops[IORING_OP_POLL_ADD].flags =
            probe->ops[IORING_OP_POLL_REMOVE].flags =
            probe->ops[IORING_OP_TIMEOUT].flags =
            probe->ops[IORING_OP_TIMEOUT_REMOVE].flags =
            probe->ops[IORING_OP_CLOSE].flags =
            probe->ops[IORING_OP_FILES_UPDATE].flags =
            probe->ops[IORING_OP_READ].flags =
            probe->ops[IORING_OP_WRITE].flags = IO_URING_OP_SUPPORTED;
    context_clear_err(ctx);
    return 0;
}

sysreturn io_uring_register(int fd, unsigned int opcode, void *arg,
                            unsigned int nr_args)
{
    iour_debug("fd %d, opcode %d", fd, opcode);
    io_uring iour = iour_from_fd(current->p, fd);
    sysreturn rv;
    switch (opcode) {
    case IORING_REGISTER_BUFFERS:
        if (!validate_iovec((struct iovec *)arg, nr_args, true))
            rv = -EFAULT;
        else
            rv = iour_register_buffers(iour, (struct iovec *)arg, nr_args);
        break;
    case IORING_UNREGISTER_BUFFERS:
        if (arg || nr_args)
            rv = -EINVAL;
        else
            rv = iour_unregister_buffers(iour);
        break;
    case IORING_REGISTER_FILES:
        if (!fault_in_user_memory(arg, sizeof(s32) * nr_args, false))
            rv = -EFAULT;
        else
            rv = iour_register_files(iour, (s32 *)arg, nr_args);
        break;
    case IORING_REGISTER_FILES_UPDATE: {
        struct io_uring_files_update *fu = (struct io_uring_files_update *)arg;
        if (!fault_in_user_memory(fu, sizeof(*fu), false))
            rv = -EFAULT;
        else if (fu->resv)
            rv = -EINVAL;
        else
            rv = iour_register_files_update(iour, fu->fds, nr_args, fu->offset);
        break;
    }
    case IORING_UNREGISTER_FILES:
        if (arg || nr_args)
            rv = -EINVAL;
        else
            rv = iour_unregister_files(iour);
        break;
    case IORING_REGISTER_EVENTFD:
    case IORING_REGISTER_EVENTFD_ASYNC: {
        int efd;
        if (!get_user_value(arg, &efd))
            rv = -EFAULT;
        else if (nr_args != 1)
            rv = -EINVAL;
        else
            rv = iour_register_eventfd(iour, efd,
                opcode == IORING_REGISTER_EVENTFD_ASYNC);
        break;
    }
    case IORING_UNREGISTER_EVENTFD:
        if (arg || nr_args)
            rv = -EINVAL;
        else
            rv = iour_unregister_eventfd(iour);
        break;
    case IORING_REGISTER_PROBE: {
        struct io_uring_probe *probe = (struct io_uring_probe *)arg;
        if (!validate_user_memory(probe,
                sizeof(*probe) + sizeof(probe->ops[0]) * nr_args, true))
            rv = -EFAULT;
        else
            rv = iour_register_probe(probe, nr_args);
        break;
    }
    default:
        rv = -EINVAL;
        break;
    }
    fdesc_put(&iour->f);
    return rv;
}
