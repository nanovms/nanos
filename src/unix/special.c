#include <unix_internal.h>
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
}

static special_file *
get_special(file f)
{
    buffer b = table_find(f->n, sym(special));
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
