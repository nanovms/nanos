#include <unix_internal.h>
#include <path.h>

typedef struct special_file {
    const char *path;
    sysreturn (*read)(file f, void *dest, u64 length, u64 offset_arg);
    u32 (*events)(file f);
} special_file;

static sysreturn urandom_read(file f, void *dest, u64 length, u64 offset_arg)
{
    buffer b = alloca_wrap_buffer(dest, length);
    do_getrandom(b, 0);
    return length;
}

static u32 urandom_events(file f)
{
    return EPOLLIN;
}

static special_file
special_files[] = {
    { "/dev/urandom", .read = urandom_read, .events = urandom_events },
};

void register_special_files(process p)
{
    int res;
    heap h = heap_general((kernel_heaps)p->uh);

    static char ROOT[] = "/";
    buffer root = alloca_wrap_buffer(ROOT, sizeof(ROOT));

    /* TODO: create parent directories */
    res = filesystem_mkdir(p->fs, canonicalize_path(h, root, wrap_buffer_cstring(h, "/dev")));

    for (int i = 0; i < sizeof(special_files) / sizeof(special_files[0]); i++) {
        special_file *sf = special_files + i;

        /* create special file */
        tuple entry = allocate_tuple();
        buffer b = wrap_buffer(h, sf, sizeof(*sf));
        table_set(entry, sym(special), b);
        res = filesystem_mkentry(p->fs,
            canonicalize_path(h, root, wrap_buffer_cstring(h, (char *) sf->path)),
            entry);
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

    thread_log(current, "spec_read: %s\n", sf->path);
    if (sf->read)
        return sf->read(f, dest, length, offset_arg);

    return 0;
}

u32
spec_events(file f)
{
    special_file *sf = get_special(f);
    assert(sf);

    thread_log(current, "spec_events: %s\n", sf->path);
    if (sf->events)
        return sf->events(f);

    return 0;
}
