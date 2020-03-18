#include <unix_internal.h>
#include <filesystem.h>

#define SYMLINK_HOPS_MAX    8

// fused buffer wrap, split, and resolve
int resolve_cstring(tuple cwd, const char *f, tuple *entry, tuple *parent)
{
    if (!f)
        return -EFAULT;

    tuple t = *f == '/' ? filesystem_getroot(current->p->fs) : cwd;
    tuple p = t;
    buffer a = little_stack_buffer(NAME_MAX);
    char y;
    int nbytes;
    int err;

    while ((y = *f)) {
        if (y == '/') {
            if (buffer_length(a)) {
                p = t;
                t = lookup(t, intern(a));
                if (!t) {
                    err = -ENOENT;
                    goto done;
                }
                err = filesystem_follow_links(t, p, &t);
                if (err) {
                    t = false;
                    goto done;
                }
                if (!children(t))
                    return -ENOTDIR;
                buffer_clear(a);
            }
            f++;
        } else {
            nbytes = push_utf8_character(a, f);
            if (!nbytes) {
                thread_log(current, "Invalid UTF-8 sequence.\n");
                err = -ENOENT;
                p = false;
                goto done;
            }
            f += nbytes;
        }
    }

    if (buffer_length(a)) {
        p = t;
        t = lookup(t, intern(a));
    }
    err = -ENOENT;
done:
    if (!t && (*f == '/') && (*(f + 1)))
        /* The path being resolved contains entries under a non-existent
         * directory. */
        p = false;
    if (parent)
        *parent = p;
    if (entry)
        *entry = t;
    return (t ? 0 : err);
}

int resolve_cstring_follow(tuple cwd, const char *f, tuple *entry,
        tuple *parent)
{
    tuple t, p;
    int ret = resolve_cstring(cwd, f, &t, &p);
    if (!ret) {
        ret = filesystem_follow_links(t, p, &t);
    }
    if ((ret == 0) && entry) {
        *entry = t;
    }
    if (parent) {
        *parent = p;
    }
    return ret;
}

int filesystem_follow_links(tuple link, tuple parent, tuple *target)
{
    if (!is_symlink(link)) {
        return 0;
    }

    tuple target_t;
    buffer buf = little_stack_buffer(NAME_MAX + 1);
    int hop_count = 0;
    while (true) {
        buffer target_b = linktarget(link);
        if (!target_b) {
            *target = link;
            return 0;
        }
        int ret = resolve_cstring(parent, cstring(target_b, buf), &target_t,
                &parent);
        if (ret) {
            return ret;
        }
        if (is_symlink(target_t)) {
            if (hop_count++ == SYMLINK_HOPS_MAX) {
                return -ELOOP;
            }
        }
        link = target_t;
    }
}

closure_function(1, 1, void, symlink_complete,
                 thread, t,
                 status, s)
{
    thread t = bound(t);
    thread_log(current, "%s: status %v (%s)", __func__, s,
            is_ok(s) ? "OK" : "NOTOK");
    set_syscall_return(t, is_ok(s) ? 0 : -EIO);
    file_op_maybe_wake(t);
    closure_finish();
}

static sysreturn symlink_internal(tuple cwd, const char *path,
        const char *target)
{
    if (!target) {
        set_syscall_error(current, EFAULT);
    }
    tuple parent;
    int ret = resolve_cstring(cwd, path, 0, &parent);
    if ((ret != -ENOENT) || !parent) {
        return set_syscall_return(current, ret);
    }
    file_op_begin(current);
    filesystem_symlink(current->p->fs, parent, filename_from_path(path), target,
            closure(heap_general(get_kernel_heaps()), symlink_complete,
            current));
    return file_op_maybe_sleep(current);
}

sysreturn symlink(const char *target, const char *linkpath)
{
    thread_log(current, "symlink %s -> %s", linkpath, target);
    return symlink_internal(current->p->cwd, linkpath, target);
}

sysreturn symlinkat(const char *target, int dirfd, const char *linkpath)
{
    thread_log(current, "symlinkat %d %s -> %s", dirfd, linkpath, target);
    tuple cwd = resolve_dir(dirfd, linkpath);
    return symlink_internal(cwd, linkpath, target);
}
