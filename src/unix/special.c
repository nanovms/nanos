#include <unix_internal.h>
#include <filesystem.h>
#include <ftrace.h>

typedef struct special_file {
    const char *path;
    sysreturn (*open)(file f);
    sysreturn (*close)(file f);
    sysreturn (*read)(file f, void *dest, u64 length, u64 offset);
    sysreturn (*write)(file f, void *dest, u64 length, u64 offset);
    u32 (*events)(file f);
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

closure_function(1, 1, void, maps_handler,
                 buffer, b,
                 vmap, map)
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
}

static sysreturn maps_read(file f, void *dest, u64 length, u64 offset)
{
    heap h = heap_general(get_kernel_heaps());
    buffer b = allocate_buffer(h, 512);
    if (b == INVALID_ADDRESS) {
        return -ENOMEM;
    }
    vmap_iterator(current->p, stack_closure(maps_handler, b));
    if (offset >= buffer_length(b)) {
        return 0;
    }
    length = MIN(length, buffer_length(b) - offset);
    runtime_memcpy(dest, buffer_ref(b, offset), length);
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
    length = MIN(length, buffer_length(b) - offset);
    runtime_memcpy(dest, buffer_ref(b, offset), length);
    return length;
}

static u32 cpu_online_events(file f)
{
    return (EPOLLIN | EPOLLOUT);
}

static special_file special_files[] = {
    { "/dev/urandom", .read = urandom_read, .write = 0, .events = urandom_events },
    { "/dev/null", .read = null_read, .write = null_write, .events = null_events },
    { "/proc/self/maps", .read = maps_read, .events = maps_events, },
    { "/sys/devices/system/cpu/online", .read = cpu_online_read, .write = null_write, .events = cpu_online_events },
    FTRACE_SPECIAL_FILES
};

closure_function(2, 6, sysreturn, spec_read,
                 special_file *, sf, file, f,
                 void *, dest, u64, len, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    special_file *sf = bound(sf);
    thread_log(t, "spec_read: %s", sf->path);
    file f = bound(f);
    sysreturn nr;
    if (sf->read) {
        boolean is_file_offset = (offset == infinity);
        nr = sf->read(f, dest, len, is_file_offset ? f->offset : offset);
        if ((nr > 0) && is_file_offset)
            f->offset += nr;
    } else {
        nr = 0;
    }
    return io_complete(completion, t, nr);
}

closure_function(2, 6, sysreturn, spec_write,
                 special_file *, sf, file, f,
                 void *, dest, u64, len, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    special_file *sf = bound(sf);
    thread_log(t, "spec_write: %s", sf->path);
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
    return io_complete(completion, t, nr);
}

closure_function(2, 1, u32, spec_events,
                 special_file *, sf, file, f,
                 thread, t)
{
    special_file *sf = bound(sf);
    thread_log(current, "spec_events: %s", sf->path);
    if (sf->events)
        return sf->events(bound(f));
    return 0;
}

closure_function(2, 2, sysreturn, spec_close,
                 special_file *, sf, file, f,
                 thread, t, io_completion, completion)
{
    special_file *sf = bound(sf);
    thread_log(current, "spec_close: %s", sf->path);
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
    return io_complete(completion, t, ret);
}

closure_function(1, 1, sysreturn, special_open,
                 special_file *, sf,
                 file, f)
{
    special_file *sf = bound(sf);
    heap h = heap_general(get_kernel_heaps());
    sysreturn ret;

    thread_log(current, "spec_open: %s", sf->path);
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

boolean create_special_file(const char *path, spec_file_open open)
{
    tuple entry = allocate_tuple();
    if (entry == INVALID_ADDRESS)
        return false;
    set(entry, sym(special), open);
    fs_status s = filesystem_mkentry(get_root_fs(), 0, path, entry, false, true);
    if (s == FS_STATUS_OK)
        return true;
    deallocate_value(entry);
    return false;
}
KLIB_EXPORT(create_special_file);

void register_special_files(process p)
{
    heap h = heap_general((kernel_heaps)p->uh);

    tuple proc_self;
    int ret = resolve_cstring(0, p->cwd, "/proc/self/exe", 0, &proc_self);
    if (ret == -ENOENT) {
        if (!proc_self) {
            filesystem_mkdirpath(p->root_fs, 0, "/proc/self", true);
            assert(resolve_cstring(0, p->cwd, "/proc/self", &proc_self, 0) == 0);
        }
        assert(proc_self);
        value program = get(p->process_root, sym(program));
        assert(program);
        buffer b = allocate_buffer(h, buffer_length(program) + 2);
        assert(b != INVALID_ADDRESS);
        /* glibc expects exe path to be absolute */
        if (peek_char(program) != '/')
            assert(buffer_write_byte(b, '/'));
        assert(push_buffer(b, program));
        assert(buffer_write_byte(b, '\0')); /* append string terminator character */
        filesystem_symlink(p->root_fs, proc_self, "exe", buffer_ref(b, 0));
        deallocate_buffer(b);
    }

    for (int i = 0; i < sizeof(special_files) / sizeof(special_files[0]); i++) {
        special_file *sf = special_files + i;

        /* create special file */
        spec_file_open open = closure(h, special_open, sf);
        assert(open != INVALID_ADDRESS);
        assert(create_special_file(sf->path, open));
    }

    filesystem_mkdirpath(p->root_fs, 0, "/sys/devices/system/cpu/cpu0", false);
}

sysreturn
spec_open(file f)
{
    spec_file_open open = get(file_get_meta(f), sym(special));
    return apply(open, f);
}
