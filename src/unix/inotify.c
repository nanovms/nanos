#include <unix_internal.h>
#include <filesystem.h>

#define INOTIFY_BUFLEN_MIN  PAGESIZE
#define INOTIFY_BUFLEN_MAX  (16384 * sizeof(struct inotify_event))
#define INOTIFY_WATCH_MAX   8192

struct inotify_event {
    int wd;
    u32 mask;
    u32 cookie;
    u32 len;
    char name[];
} __attribute__((packed));

typedef struct inotify {
    struct fdesc f; /* must be first */
    closure_struct(file_io, read);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_ioctl, ioctl);
    closure_struct(fdesc_close, close);
    heap h;
    struct list watches;
    int watch_count;
    int next_wd;
    ringbuf event_buf;
    blockq bq;
} *inotify;

typedef struct inotify_watch {
    struct list l;
    inotify in;
    int wd;
    inode n;
    notify_set ns;
    notify_entry ne;
    closure_struct(event_handler, eh);
} *inotify_watch;

#define inotify_lock(in)    spin_lock(&(in)->f.lock)
#define inotify_trylock(in) spin_try(&(in)->f.lock)
#define inotify_unlock(in)  spin_unlock(&(in)->f.lock)

static sysreturn inotify_resolve_fd(int fd, inotify *in)
{
    fdesc f = fdesc_get(current->p, fd);
    if (!f)
        return -EBADF;
    if (f->type != FDESC_TYPE_INOTIFY) {
        fdesc_put(f);
        return -EINVAL;
    }
    *in = (inotify)f;
    return 0;
}

closure_function(4, 1, sysreturn, inotify_read_bh,
                 inotify, in, void *, buf, u64, length, io_completion, completion,
                 u64 flags)
{
    inotify in = bound(in);
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }
    inotify_lock(in);
    ringbuf b = in->event_buf;
    bytes avail = ringbuf_length(b);
    if (avail == 0) {
        inotify_unlock(in);
        if (in->f.flags & O_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }
    context ctx = get_current_context(current_cpu());
    void *buf = bound(buf);
    u64 length = bound(length);
    boolean empty = false;
    rv = 0;
    while (true) {
        struct inotify_event event;
        if (!ringbuf_peek(b, &event, sizeof(event))) {
            empty = true;
            break;
        }
        bytes event_len = sizeof(event) + event.len;
        if (length < event_len)
            break;
        if (context_set_err(ctx)) {
            if (rv == 0)
                rv = -EFAULT;
            break;
        }
        runtime_memcpy(buf, &event, sizeof(event));
        context_clear_err(ctx);
        ringbuf_consume(b, sizeof(event));
        buf += sizeof(event);
        if (event.len) {
            if (context_set_err(ctx)) {
                ringbuf_unconsume(b, sizeof(event));
                if (rv == 0)
                    rv = -EFAULT;
                break;
            }
            ringbuf_read(b, buf, event.len);
            context_clear_err(ctx);
            buf += event.len;
        }
        length -= event_len;
        rv += event_len;
    }
    inotify_unlock(in);
    if (rv == 0)
        rv = -EINVAL;
    else if (empty)
        notify_dispatch(in->f.ns, 0);
out:
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

closure_func_basic(file_io, sysreturn, inotify_read,
                   void *buf, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    inotify in = struct_from_field(closure_self(), inotify, read);
    blockq_action ba = closure_from_context(ctx, inotify_read_bh, in, buf, length, completion);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, -ENOMEM);
    return blockq_check(in->bq, ba, bh);
}

closure_func_basic(fdesc_events, u32, inotify_events,
                   thread t)
{
    inotify in = struct_from_field(closure_self(), inotify, events);
    inotify_lock(in);
    boolean empty = (ringbuf_length(in->event_buf) == 0);
    inotify_unlock(in);
    return empty ? 0 : EPOLLIN;
}

closure_func_basic(fdesc_ioctl, sysreturn, inotify_ioctl,
                   unsigned long request, vlist ap)
{
    inotify in = struct_from_field(closure_self(), inotify, ioctl);
    switch (request) {
    case FIONREAD: {
        inotify_lock(in);
        int nbytes = ringbuf_length(in->event_buf);
        inotify_unlock(in);
        if (!set_user_value(varg(ap, int *), nbytes))
            return -EFAULT;
        return 0;
    }
    default:
        return ioctl_generic(&in->f, request, ap);
    }
}

closure_func_basic(fdesc_close, sysreturn, inotify_close,
                   context ctx, io_completion completion)
{
    inotify in = struct_from_field(closure_self(), inotify, close);
    inotify_lock(in);
    list_foreach(&in->watches, e) {
        inotify_watch watch = struct_from_field(e, inotify_watch, l);
        list_delete(e);
        notify_remove(watch->ns, watch->ne, false);
        deallocate(in->h, watch, sizeof(*watch));
    }
    release_fdesc(&in->f);
    deallocate_blockq(in->bq);
    deallocate_ringbuf(in->event_buf);
    deallocate(in->h, in, sizeof(struct inotify));
    return 0;
}

static boolean inotify_queue_event(inotify in, inotify_watch watch, u32 eventmask,
                                   inotify_evdata evdata)
{
    struct inotify_event event;
    int event_len = sizeof(event);
    int name_len = (evdata && evdata->name) ? buffer_length(evdata->name) : 0;
    if (name_len > 0) {
        event_len += name_len + 1;

        /* Ensure total length is multiple of struct inotify_event size. */
        int mod = (name_len + 1) % sizeof(event);
        if (mod)
            event_len += sizeof(event) - mod;
    }
    ringbuf b = in->event_buf;
    boolean empty = (ringbuf_length(b) == 0);

    /* Ensure there is always room for an overflow event. */
    if ((ringbuf_space(b) < event_len + sizeof(event)) && (b->length < INOTIFY_BUFLEN_MAX))
        ringbuf_extend(b, event_len + sizeof(event));
    bytes buf_space = ringbuf_space(b);
    if (buf_space < event_len + sizeof(event)) {
        if (buf_space >= sizeof(event)) {
            event.wd = -1;
            event.mask = IN_Q_OVERFLOW;
            event.cookie = 0;
            event.len = 0;
            ringbuf_write(b, &event, sizeof(event));
        }
        return false;
    }

    event.wd = watch->wd;
    event.mask = eventmask;
    event.cookie = evdata ? evdata->cookie : 0;
    event.len = name_len ? (event_len - sizeof(event)) : 0;
    ringbuf_write(b, &event, sizeof(event));
    if (name_len) {
        ringbuf_write(b, ringbuf_ref(evdata->name, 0), name_len);
        ringbuf_memset(b, '\0', event.len - name_len);
    }
    return empty;
}

static boolean inotify_rm_watch_locked(inotify in, inotify_watch watch, boolean delete_from_list)
{
    boolean notify_readers = inotify_queue_event(in, watch, IN_IGNORED, 0);
    if (delete_from_list)
        list_delete(&watch->l);
    deallocate(in->h, watch, sizeof(*watch));
    in->watch_count--;
    return notify_readers;
}

static void inotify_noti_readers(inotify in)
{
    notify_dispatch(in->f.ns, EPOLLIN);
    blockq_wake_one(in->bq);
}

closure_func_basic(event_handler, u64, inotify_event_handler,
                   u64 events, void *arg)
{
    u64 rv = 0;
    if (!(events & ~IN_ISDIR))
        return rv;
    inotify_watch watch = struct_from_field(closure_self(), inotify_watch, eh);
    inotify in = watch->in;

    /* Guard against potential deadlock if an event is notified while the watch is being removed
     * (the inotify and notify_set locks are acquired in different order). */
    while (!inotify_trylock(in)) {
        if (!list_inserted(&watch->l))
            return rv;
        kern_pause();
    }

    boolean notify_readers;
    if (events != NOTIFY_EVENTS_RELEASE) {
        notify_readers = inotify_queue_event(in, watch, events, arg);
        if (notify_entry_get_eventmask(watch->ne) & IN_ONESHOT) {
            notify_readers |= inotify_rm_watch_locked(in, watch, true);
            rv = NOTIFY_RESULT_RELEASE;
        }
    } else {
        notify_readers = inotify_rm_watch_locked(in, watch, true);
    }
    inotify_unlock(in);
    if (notify_readers)
        inotify_noti_readers(in);
    return rv;
}

sysreturn inotify_init(void)
{
    return inotify_init1(0);
}

sysreturn inotify_init1(int flags)
{
    if (flags & ~(O_NONBLOCK | O_CLOEXEC))
        return -EINVAL;
    heap h = heap_locked(get_kernel_heaps());
    inotify in = allocate(h, sizeof(struct inotify));
    if (in == INVALID_ADDRESS) {
        return -ENOMEM;
    }
    in->event_buf = allocate_ringbuf(h, INOTIFY_BUFLEN_MIN);
    if (in->event_buf == INVALID_ADDRESS) {
        goto nomem;
    }
    in->bq = allocate_blockq(h, ss("inotify"));
    if (in->bq == INVALID_ADDRESS) {
        deallocate_ringbuf(in->event_buf);
        goto nomem;
    }
    init_fdesc(h, &in->f, FDESC_TYPE_INOTIFY);
    in->f.read = init_closure_func(&in->read, file_io, inotify_read);
    in->f.events = init_closure_func(&in->events, fdesc_events, inotify_events);
    in->f.ioctl = init_closure_func(&in->ioctl, fdesc_ioctl, inotify_ioctl);
    in->f.close = init_closure_func(&in->close, fdesc_close, inotify_close);
    in->f.flags = flags & (O_NONBLOCK | O_CLOEXEC);
    in->h = h;
    list_init(&in->watches);
    in->watch_count = 0;
    in->next_wd = 0;
    sysreturn fd = allocate_fd(current->p, in);
    if (fd == INVALID_PHYSICAL) {
        apply(in->f.close, 0, io_completion_ignore);
        return -EMFILE;
    }
    return fd;
  nomem:
    deallocate(h, in, sizeof(struct inotify));
    return -ENOMEM;
}

sysreturn inotify_add_watch(int fd, const char *pathname, u32 mask)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    if (!mask)
        return -EINVAL;
    inotify in;
    sysreturn rv = inotify_resolve_fd(fd, &in);
    if (rv)
        return rv;
    filesystem fs;
    inode cwd;
    process_get_cwd(current->p, &fs, &cwd);
    filesystem cwd_fs = fs;
    tuple n;
    rv = filesystem_get_node(&fs, cwd, pathname_ss, (mask & IN_DONT_FOLLOW) ? 0 : FS_NODE_FOLLOW,
                             &n, 0, 0);
    if (rv != 0)
        goto out;
    if ((mask & IN_ONLYDIR) && !is_dir(n)) {
        rv = -ENOTDIR;
        filesystem_put_node(fs, n);
        goto out;
    }
    mask |= IN_IGNORED | IN_ISDIR | IN_Q_OVERFLOW | IN_UNMOUNT;
    inotify_watch watch = 0;
    inode ino = fs->get_inode(fs, n);
    inotify_lock(in);
    list_foreach(&in->watches, e) {
        inotify_watch w = struct_from_field(e, inotify_watch, l);
        if (w->n == ino) {
            notify_entry_update_eventmask(w->ne,
                (mask & IN_MASK_ADD) ? (notify_entry_get_eventmask(w->ne) | mask) : mask);
            watch = w;
            break;
        }
    }
    if (!watch) {
        if (in->watch_count >= INOTIFY_WATCH_MAX) {
            rv = -ENOSPC;
            goto unlock;
        }
        watch = allocate(in->h, sizeof(*watch));
        if (watch == INVALID_ADDRESS) {
            rv = -ENOMEM;
            goto unlock;
        }
        watch->ne = fs_watch(in->h, n, mask,
                             init_closure_func(&watch->eh, event_handler, inotify_event_handler),
                             &watch->ns);
        if (watch->ne) {
            watch->in = in;
            in->watch_count++;
            watch->wd = in->next_wd++;
            if (in->next_wd < 0)
                in->next_wd = 0;    /* negative watch descriptors are not allowed */
            watch->n = ino;
            list_push_back(&in->watches, &watch->l);
        } else {
            deallocate(in->h, watch, sizeof(*watch));
            watch = 0;
            rv = -ENOMEM;
        }
    }
    if (watch)
        rv = watch->wd;
  unlock:
    inotify_unlock(in);
    filesystem_put_node(fs, n);
  out:
    filesystem_release(cwd_fs);
    fdesc_put(&in->f);
    return rv;
}

sysreturn inotify_rm_watch(int fd, int wd)
{
    inotify in;
    sysreturn rv = inotify_resolve_fd(fd, &in);
    if (rv)
        return rv;
    rv = -EINVAL;
    boolean notify_readers = false;
    inotify_lock(in);
    list_foreach(&in->watches, e) {
        inotify_watch watch = struct_from_field(e, inotify_watch, l);
        if (watch->wd == wd) {
            /* Delete the watch from the inotify list before removing the notify entry, otherwise if
             * an event is triggered the event handler could access a deallocated watch structure.
             */
            list_delete(&watch->l);
            notify_remove(watch->ns, watch->ne, false);
            notify_readers = inotify_rm_watch_locked(in, watch, false);
            rv = 0;
            break;
        }
    }
    inotify_unlock(in);
    if (notify_readers)
        inotify_noti_readers(in);
    fdesc_put(&in->f);
    return rv;
}
