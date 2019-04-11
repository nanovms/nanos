#include <unix_internal.h>

typedef struct special_file {
    const char *path;
    sysreturn (*read)(file f, void *dest, u64 length, u64 offset_arg);
    sysreturn (*write)(file f, void *dest, u64 length, u64 offset_arg);
    u32 (*events)(file f);
} special_file;

static sysreturn urandom_read(file f, void *dest, u64 length, u64 offset_arg)
{
    buffer b = alloca_wrap_buffer(dest, length);
    do_getrandom(b, 0);
    return length;
}

static sysreturn null_read(file f, void *dest, u64 length, u64 offset_arg)
{
   return 0;
}

static sysreturn null_write(file f, void *dest, u64 length, u64 offset_arg)
{
   return length;
}

static u32 urandom_events(file f)
{
    return EPOLLIN;
}

static u32 null_events(file f)
{
    return EPOLLOUT;
}

static special_file
special_files[] = {
    { "/dev/urandom", .read = urandom_read, .write = 0, .events = urandom_events },
    { "/dev/null", .read = null_read, .write = null_write, .events = null_events },
    { "/sys/devices/system/cpu/cpu0", .read = null_read, .write = null_write, .events = null_events },
};

void register_special_files(process p)
{
    heap h = heap_general((kernel_heaps)p->uh);

    /* TODO: create parent directories */
    filesystem_mkdir(p->fs, 0, "/dev", false);
    filesystem_mkdir(p->fs, 0, "/sys", false);
    filesystem_mkdir(p->fs, 0, "/sys/devices", false);
    filesystem_mkdir(p->fs, 0, "/sys/devices/system", false);
    filesystem_mkdir(p->fs, 0, "/sys/devices/system/cpu", false);

    for (int i = 0; i < sizeof(special_files) / sizeof(special_files[0]); i++) {
        special_file *sf = special_files + i;

        /* create special file */
        tuple entry = allocate_tuple();
        buffer b = wrap_buffer(h, sf, sizeof(*sf));
        table_set(entry, sym(special), b);
        filesystem_mkentry(p->fs, 0, sf->path, entry, false);
    }
}

static special_file *
get_special(file f)
{
    buffer b = table_find(f->n, sym(special));
    assert(b);
    return (special_file *) buffer_ref(b, 0);
}

sysreturn
spec_read(file f, void *dest, u64 length, u64 offset_arg)
{
    special_file *sf = get_special(f);
    assert(sf);

    thread_log(current, "spec_read: %s", sf->path);
    if (sf->read)
        return sf->read(f, dest, length, offset_arg);

    return 0;
}

sysreturn
spec_write(file f, void *dest, u64 length, u64 offset_arg)
{
    special_file *sf = get_special(f);
    assert(sf);

    thread_log(current, "spec_write: %s", sf->path);
    if (sf->write)
        return sf->write(f, dest, length, offset_arg);
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
