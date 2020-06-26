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
    bprintf(b, "%16lx-%16lx r%c%cp 00000000 00:00 0", map->node.r.start,
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

static sysreturn text_read(const char *text, bytes text_len, file f, void *dest, u64 length, u64 offset)
{
    if (text_len <= offset)
        return 0;

    u64 nr = MIN(text_len - offset, length);
    runtime_memcpy(dest, text + offset, nr);
    return nr;
}

static u32 text_events(const char *text, bytes text_len, file f)
{
    u32 events = EPOLLOUT;
    if (f->offset < text_len)
        events |= EPOLLIN;
    return events;
}

static const char cpu_online[] = "0-0\n";

static sysreturn cpu_online_read(file f, void *dest, u64 length, u64 offset)
{
    return text_read(cpu_online, sizeof(cpu_online) - 1, f, dest, length, offset);
}

static u32 cpu_online_events(file f)
{
    return text_events(cpu_online, sizeof(cpu_online) - 1, f);
}

static special_file special_files[] = {
    { "/dev/urandom", .read = urandom_read, .write = 0, .events = urandom_events },
    { "/dev/null", .read = null_read, .write = null_write, .events = null_events },
    { "/proc/self/maps", .read = maps_read, .events = maps_events, },
    { "/sys/devices/system/cpu/online", .read = cpu_online_read, .write = null_write, .events = cpu_online_events },
    FTRACE_SPECIAL_FILES
};

void register_special_files(process p)
{
    heap h = heap_general((kernel_heaps)p->uh);

    for (int i = 0; i < sizeof(special_files) / sizeof(special_files[0]); i++) {
        special_file *sf = special_files + i;

        /* create special file */
        tuple entry = allocate_tuple();
        buffer b = wrap_buffer(h, sf, sizeof(*sf));
        table_set(entry, sym(special), b);
        filesystem_mkentry(p->fs, 0, sf->path, entry, false, true);
    }

    filesystem_mkdirpath(p->fs, 0, "/sys/devices/system/cpu/cpu0", false);

    tuple proc_self, proc_self_exe;
    int ret = resolve_cstring(p->cwd, "/proc/self/exe", &proc_self_exe,
            &proc_self);
    if (ret == -ENOENT) {
        assert(proc_self);
        value program = table_find(p->process_root, sym(program));
        assert(program);
        buffer b = clone_buffer(h, program);
        assert(b != INVALID_ADDRESS);
        buffer_write_byte(b, '\0'); /* append string terminator character */
        filesystem_symlink(p->fs, proc_self, "exe", buffer_ref(b, 0));
        deallocate_buffer(b);
    }
}

static special_file *
get_special(file f)
{
    buffer b = table_find(file_get_meta(f), sym(special));
    assert(b);
    return (special_file *) buffer_ref(b, 0);
}

sysreturn
spec_open(file f)
{
    special_file *sf = get_special(f);
    assert(sf);

    thread_log(current, "spec_open: %s", sf->path);
    if (sf->open)
        return sf->open(f);

    return 0;
}

sysreturn
spec_close(file f)
{
    special_file *sf = get_special(f);
    assert(sf);

    thread_log(current, "spec_close: %s", sf->path);
    if (sf->close)
        return sf->close(f);

    return 0;
}

sysreturn
spec_read(file f, void *dest, u64 length, u64 offset, thread t, boolean bh,
        io_completion completion)
{
    special_file *sf = get_special(f);
    assert(sf);

    thread_log(t, "spec_read: %s", sf->path);
    if (sf->read) {
        sysreturn nr = sf->read(f, dest, length, offset);
        if (nr > 0)
            f->offset += nr;
        return nr;
    }

    return 0;
}

sysreturn
spec_write(file f, void *dest, u64 length, u64 offset, thread t, boolean bh,
        io_completion completion)
{
    special_file *sf = get_special(f);
    assert(sf);

    thread_log(t, "spec_write: %s", sf->path);
    if (sf->write)
        return sf->write(f, dest, length, offset);
    return 0;
}

u32
spec_events(file f)
{
    special_file *sf = get_special(f);
    assert(sf);

    thread_log(current, "spec_events: %s", sf->path);
    if (sf->events)
        return sf->events(f);

    return 0;
}
