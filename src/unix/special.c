#include <unix_internal.h>
#include <filesystem.h>
#include <ftrace.h>
#include <storage.h>

typedef struct special_file {
    sstring path;
    sysreturn (*open)(file f);
    sysreturn (*close)(file f);
    sysreturn (*read)(file f, void *dest, u64 length, u64 offset);
    sysreturn (*write)(file f, void *dest, u64 length, u64 offset);
    u32 (*events)(file f);
    u64 alloc_size;
} special_file;

static sysreturn urandom_read(file f, void *dest, u64 length, u64 offset)
{
    buffer b = alloca_wrap_buffer(dest, length);
    random_buffer(b);
    return length;
}

static u32 urandom_events(file f)
{
    return EPOLLIN;
}

static sysreturn null_read(file f, void *dest, u64 length, u64 offset)
{
   return 0;
}

static sysreturn null_write(file f, void *dest, u64 length, u64 offset)
{
   return length;
}

static u32 null_events(file f)
{
    return EPOLLOUT;
}

static sysreturn meminfo_read(file f, void *dest, u64 length, u64 offset)
{
    heap h = (heap)heap_physical(get_kernel_heaps());
    u64 total = heap_total(h) / KB;
    u64 free = total - heap_allocated(h) / KB;
    u64 cached = pagecache_get_occupancy() / KB;
    buffer b = little_stack_buffer(256);
    bprintf(b, "MemTotal:     %9ld kB\n"
               "MemFree:      %9ld kB\n"
               "MemAvailable: %9ld kB\n"
               "Buffers:              0 kB\n"
               "SwapTotal:            0 kB\n"
               "SwapFree:             0 kB\n"
               "Cached:       %9ld kB\n",
            total, free, free + cached, cached);
    return buffer_read_at(b, offset, dest, length);
}

typedef struct mounts_notify_data *mounts_notify_data;

struct mounts_notify_data {
    struct special_file_wrapper w;
    closure_struct(mount_notification_handler, notify_handler);
    u64 last_generation;
};

static u32 mounts_events(file f)
{
    return EPOLLIN | EPOLLRDNORM;
}

closure_func_basic(mount_notification_handler, void, mounts_notify,
                   u64 generation)
{
    mounts_notify_data d = struct_from_closure(mounts_notify_data, notify_handler);

    u32 events = mounts_events(&d->w.f);
    if (d->last_generation != generation) {
        d->last_generation = generation;
        events |= EPOLLERR | EPOLLPRI;
    }
    notify_dispatch(d->w.f.f.ns, events);
}

sysreturn mounts_open(file f)
{
    mounts_notify_data d = (mounts_notify_data)f;
    d->last_generation = 0;
    storage_register_mount_notify(init_closure_func(&d->notify_handler, mount_notification_handler,
                                                    mounts_notify));
    return 0;
}

sysreturn mounts_close(file f)
{
    mounts_notify_data d = (mounts_notify_data)f;
    storage_unregister_mount_notify((mount_notification_handler)&d->notify_handler);
    return 0;
}

closure_function(1, 4, void, mounts_handler,
                 buffer, b,
                 u8 *uuid, sstring label, filesystem fs, inode mount_point)
{
    buffer b = bound(b);
    bytes saved_end = b->end;
    if (!sstring_is_empty(label))
        buffer_write_sstring(b, label);
    else
        print_uuid(b, uuid);
    push_u8(b, ' ');
    if (mount_point) {
        for (int count = 2; count > 0; count--) {
            int rv = file_get_path(get_root_fs(), mount_point, buffer_end(b), buffer_space(b));
            if (rv > 0) {
                buffer_produce(b, rv - 1);  /* drop the string terminator character */
                goto out;
            } else if (!buffer_extend(b, PATH_MAX)) {
                /* Couldn't write the mount point into the buffer: drop this filesystem */
                break;
            }
        }
        /* something has gone wrong looking up mount point */
        msg_err("error looking up mount point for volume '%s'\n", label);
        b->end = saved_end;
        return;
    } else {    /* root filesystem */
        push_u8(b, '/');
    }
out:
    bprintf(b, " tfs %s 0 0\n", filesystem_is_readonly(fs) ? ss("ro") : ss("rw"));
}

static sysreturn mounts_read(file f, void *dest, u64 length, u64 offset)
{
    heap h = heap_locked(get_kernel_heaps());
    buffer b = allocate_buffer(h, 64);
    if (b == INVALID_ADDRESS) {
        return -ENOMEM;
    }
    storage_iterate(stack_closure(mounts_handler, b));
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx))
        length = buffer_read_at(b, offset, dest, length);
    else
        length = -EFAULT;
    deallocate_buffer(b);
    return length;
}

closure_function(1, 1, boolean, maps_handler,
                 buffer, b,
                 vmap map)
{
    buffer b = bound(b);

    /* All mappings are assumed to be readable and private; offset, device and
     * inode are unknown. */
    bprintf(b, "%016lx-%016lx r%c%cp 00000000 00:00 0", map->node.r.start,
            map->node.r.end, (map->flags & VMAP_FLAG_WRITABLE) ? 'w' : '-',
            (map->flags & VMAP_FLAG_EXEC) ? 'x' : '-');

    /* File path is unknown; only stack and heap pseudo-paths are known. */
    if (map == current->p->stack_map) {
        buffer_write_cstring(b, "\t[stack]");
    } else if (map == current->p->heap_map) {
        buffer_write_cstring(b, "\t[heap]");
    }

    buffer_write_cstring(b, "\n");
    return true;
}

static sysreturn maps_read(file f, void *dest, u64 length, u64 offset)
{
    heap h = heap_locked(get_kernel_heaps());
    buffer b = allocate_buffer(h, 512);
    if (b == INVALID_ADDRESS) {
        return -ENOMEM;
    }
    vmap_iterator(current->p, stack_closure(maps_handler, b));
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx))
        length = buffer_read_at(b, offset, dest, length);
    else
        length = -EFAULT;
    deallocate_buffer(b);
    return length;
}

static u32 maps_events(file f)
{
    return EPOLLIN;
}

static sysreturn cpu_online_read(file f, void *dest, u64 length, u64 offset)
{
    buffer b = little_stack_buffer(16);
    bprintf(b, "0-%d\n", total_processors - 1);
    return buffer_read_at(b, offset, dest, length);
}

static u32 cpu_online_events(file f)
{
    return (EPOLLIN | EPOLLOUT);
}

static const special_file special_files[] = {
    { ss_static_init("/dev/urandom"), .read = urandom_read, .write = 0, .events = urandom_events },
    { ss_static_init("/dev/null"), .read = null_read, .write = null_write, .events = null_events },
    { ss_static_init("/proc/meminfo"), .read = meminfo_read},
    { ss_static_init("/proc/mounts"), .open = mounts_open, .close = mounts_close,
      .read = mounts_read, .events = mounts_events,
      .alloc_size = sizeof(struct mounts_notify_data)},
    { ss_static_init("/proc/self/maps"), .read = maps_read, .events = maps_events, },
    { ss_static_init("/sys/devices/system/cpu/online"), .read = cpu_online_read,
      .write = null_write, .events = cpu_online_events },
    FTRACE_SPECIAL_FILES
};

closure_function(2, 6, sysreturn, spec_read,
                 const special_file *, sf, file, f,
                 void *dest, u64 len, u64 offset, context ctx, boolean bh, io_completion completion)
{
    const special_file *sf = bound(sf);
    file f = bound(f);
    sysreturn nr;
    if (sf->read) {
        context ctx = get_current_context(current_cpu());
        boolean is_file_offset = (offset == infinity);
        if (!context_set_err(ctx)) {
            nr = sf->read(f, dest, len, is_file_offset ? f->offset : offset);
            context_clear_err(ctx);
        } else {
            nr = -EFAULT;
        }
        if ((nr > 0) && is_file_offset)
            f->offset += nr;
    } else {
        nr = 0;
    }
    return io_complete(completion, nr);
}

closure_function(2, 6, sysreturn, spec_write,
                 const special_file *, sf, file, f,
                 void *dest, u64 len, u64 offset, context ctx, boolean bh, io_completion completion)
{
    const special_file *sf = bound(sf);
    file f = bound(f);
    sysreturn nr;
    if (sf->write) {
        boolean is_file_offset = (offset == infinity);
        nr = sf->write(f, dest, len, is_file_offset ? f->offset : offset);
        if ((nr > 0) && is_file_offset)
            f->offset += nr;
    } else {
        nr = 0;
    }
    return io_complete(completion, nr);
}

closure_function(2, 1, u32, spec_events,
                 const special_file *, sf, file, f,
                 thread t)
{
    const special_file *sf = bound(sf);
    if (sf->events)
        return sf->events(bound(f));
    return 0;
}

closure_function(2, 2, sysreturn, spec_close,
                 const special_file *, sf, file, f,
                 context ctx, io_completion completion)
{
    const special_file *sf = bound(sf);
    file f = bound(f);
    sysreturn ret;
    if (sf->close)
        ret = sf->close(f);
    else
        ret = 0;
    deallocate_closure(f->f.read);
    deallocate_closure(f->f.write);
    deallocate_closure(f->f.events);
    deallocate_closure(f->f.close);
    file_release(f);
    return io_complete(completion, ret);
}

closure_function(1, 1, sysreturn, special_open,
                 const special_file *, sf,
                 file f)
{
    const special_file *sf = bound(sf);
    heap h = heap_locked(get_kernel_heaps());
    sysreturn ret;

    f->f.read = closure(h, spec_read, sf, f);
    if (f->f.read == INVALID_ADDRESS)
        goto no_mem;
    f->f.write = closure(h, spec_write, sf, f);
    if (f->f.write == INVALID_ADDRESS)
        goto no_mem;
    f->f.events = closure(h, spec_events, sf, f);
    if (f->f.events == INVALID_ADDRESS)
        goto no_mem;
    f->f.close = closure(h, spec_close, sf, f);
    if (f->f.close == INVALID_ADDRESS)
        goto no_mem;
    if (sf->open)
        ret = sf->open(f);
    else
        ret = 0;
    if (ret)
        goto err;
    return 0;
  no_mem:
    ret = -ENOMEM;
  err:
    if (f->f.read && (f->f.read != INVALID_ADDRESS))
        deallocate_closure(f->f.read);
    if (f->f.write && (f->f.write != INVALID_ADDRESS))
        deallocate_closure(f->f.write);
    if (f->f.events && (f->f.events != INVALID_ADDRESS))
        deallocate_closure(f->f.events);
    if (f->f.close && (f->f.close != INVALID_ADDRESS))
        deallocate_closure(f->f.close);
    return ret;
}

boolean create_special_file(sstring path, spec_file_open open, u64 size, u64 rdev)
{
    tuple entry = allocate_tuple();
    if (entry == INVALID_ADDRESS)
        return false;
    set(entry, sym(special), open);
    set(entry, sym(special_alloc_size), pointer_from_u64(size));
    filesystem fs = get_root_fs();
    if (rdev)
        filesystem_set_rdev(fs, entry, rdev);
    int s = filesystem_mkentry(fs, 0, path, entry, false, true);
    if (s == 0)
        return true;
    deallocate_value(entry);
    return false;
}

void register_special_files(process p)
{
    filesystem fs = p->root_fs;
    sstring self_exe_path = ss("/proc/self/exe");
    tuple self_exe;
    heap h = heap_locked(get_kernel_heaps());

    int fss = filesystem_get_node(&fs, p->cwd, self_exe_path, false, false, false, false,
        &self_exe, 0);
    if (fss == 0) {
        filesystem_put_node(fs, self_exe);
    } else {
        fss = filesystem_mkdirpath(p->root_fs, 0, ss("/proc/self"), true);
        if ((fss == 0) || (fss == -EEXIST)) {
            value program = get(p->process_root, sym(program));
            assert(program);
            buffer b = allocate_buffer(h, buffer_length(program) + 1);
            assert(b != INVALID_ADDRESS);
            /* glibc expects exe path to be absolute */
            if (peek_char(program) != '/')
                assert(buffer_write_byte(b, '/'));
            assert(push_buffer(b, program));
            filesystem_symlink(p->cwd_fs, p->cwd, self_exe_path, buffer_to_sstring(b));
            deallocate_buffer(b);
        }
    }

    for (int i = 0; i < sizeof(special_files) / sizeof(special_files[0]); i++) {
        const special_file *sf = special_files + i;

        /* create special file */
        spec_file_open open = closure(h, special_open, sf);
        assert(open != INVALID_ADDRESS);
        assert(create_special_file(sf->path, open, sf->alloc_size, 0));
    }

    filesystem_mkdirpath(p->root_fs, 0, ss("/sys/devices/system/cpu/cpu0"), false);
}

sysreturn
spec_open(file f, tuple t)
{
    spec_file_open open = get(t, sym(special));
    return apply(open, f);
}

file
spec_allocate(tuple t)
{
    u64 size = u64_from_pointer(get(t, sym(special_alloc_size)));
    if (size == 0)
        size = sizeof(struct special_file_wrapper);
    special_file_wrapper w = allocate(heap_locked(get_kernel_heaps()), size);
    if (w == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    w->alloc_size = size;
    return &w->f;
}

void
spec_deallocate(file f)
{
    special_file_wrapper w = (special_file_wrapper)f;
    deallocate(heap_locked(get_kernel_heaps()), w, w->alloc_size);
}
