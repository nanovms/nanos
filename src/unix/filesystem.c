#include <unix_internal.h>
#include <filesystem.h>

#define SYMLINK_HOPS_MAX    8

static sysreturn sysreturn_from_fs_status(fs_status s)
{
    switch (s) {
    case FS_STATUS_NOSPACE:
        return -ENOSPC;
    case FS_STATUS_IOERR:
        return -EIO;
    case FS_STATUS_NOENT:
        return -ENOENT;
    case FS_STATUS_EXIST:
        return -EEXIST;
    case FS_STATUS_NOTDIR:
        return -ENOTDIR;
    default:
        return 0;
    }
}

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

int filesystem_add_tuple(const char *path, tuple t)
{
    tuple parent;
    int ret = resolve_cstring(current->p->cwd, path, 0, &parent);
    if (ret == 0) {
        return -EEXIST;
    }
    if ((ret != -ENOENT) || !parent) {
        return ret;
    }
    do_mkentry(current->p->fs, parent, filename_from_path(path), t, true);
    return 0;
}

closure_function(2, 2, void, fs_op_complete,
                 thread, t, file, f,
                 fsfile, fsf, fs_status, s)
{
    thread t = bound(t);
    sysreturn ret = sysreturn_from_fs_status(s);
    thread_log(current, "%s: %d", __func__, ret);

    bound(f)->length = fsfile_get_length(fsf);
    set_syscall_return(t, ret);
    file_op_maybe_wake(t);
    closure_finish();
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
    if (!validate_user_string(path) || !validate_user_string(target)) {
        return set_syscall_error(current, EFAULT);
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

static sysreturn utime_internal(const char *filename, timestamp actime,
        timestamp modtime)
{
    tuple t;
    int ret = resolve_cstring(current->p->cwd, filename, &t, 0);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    filesystem_set_atime(current->p->fs, t, actime);
    filesystem_set_mtime(current->p->fs, t, modtime);
    return set_syscall_return(current, 0);
}

sysreturn utime(const char *filename, const struct utimbuf *times)
{
    if (!validate_user_string(filename) ||
        !validate_user_memory(times, sizeof(struct utimbuf), false))
        return set_syscall_error(current, EFAULT);
    timestamp atime = times ? seconds(times->actime) : now(CLOCK_ID_REALTIME);
    timestamp mtime = times ? seconds(times->modtime) : now(CLOCK_ID_REALTIME);
    return utime_internal(filename, atime, mtime);
}

sysreturn utimes(const char *filename, const struct timeval times[2])
{
    if (!validate_user_string(filename) ||
        !validate_user_memory(times, 2 * sizeof(struct timeval), false))
        return set_syscall_error(current, EFAULT);
    /* Sub-second precision is not supported. */
    timestamp atime =
            times ? time_from_timeval(&times[0]) : now(CLOCK_ID_REALTIME);
    timestamp mtime =
            times ? time_from_timeval(&times[1]) : now(CLOCK_ID_REALTIME);
    return utime_internal(filename, atime, mtime);
}

static sysreturn statfs_internal(tuple t, struct statfs *buf)
{
    if (!buf) {
        return set_syscall_error(current, EFAULT);
    }
    runtime_memset((u8 *) buf, 0, sizeof(*buf));
    if (t) {
        filesystem fs = current->p->fs;
        buf->f_bsize = fs_blocksize(fs);
        buf->f_blocks = fs_totalblocks(fs);
        buf->f_bfree = buf->f_bavail = fs_freeblocks(fs);
    } else {
        buf->f_bsize = PAGESIZE;
    }
    buf->f_frsize = buf->f_bsize;
    u64 id = u64_from_pointer(t);
    buf->f_fsid.val[0] = (int) id;
    buf->f_fsid.val[1] = (int) (id >> 32);
    buf->f_namelen = NAME_MAX;
    return set_syscall_return(current, 0);
}

sysreturn statfs(const char *path, struct statfs *buf)
{
    if (!validate_user_string(path) ||
        !validate_user_memory(buf, sizeof(struct statfs), true))
        return set_syscall_error(current, EFAULT);
    tuple t;
    int ret = resolve_cstring(current->p->cwd, path, &t, 0);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    return statfs_internal(t, buf);
}

sysreturn fstatfs(int fd, struct statfs *buf)
{
    fdesc desc = resolve_fd(current->p, fd);
    file f;
    switch (desc->type) {
    case FDESC_TYPE_REGULAR:
    case FDESC_TYPE_DIRECTORY:
    case FDESC_TYPE_SYMLINK:
        f = (file) desc;
        break;
    default:
        f = 0;
        break;
    }
    return statfs_internal(f ? f->n : 0, buf);
}

sysreturn fallocate(int fd, int mode, long offset, long len)
{
    fdesc desc = resolve_fd(current->p, fd);
    if (desc->type != FDESC_TYPE_REGULAR) {
        switch (desc->type) {
        case FDESC_TYPE_PIPE:
        case FDESC_TYPE_STDIO:
            return -ESPIPE;
        default:
            return -ENODEV;
        }
    }

    heap h = heap_general(get_kernel_heaps());
    file f = (file) desc;
    file_op_begin(current);
    switch (mode) {
    case 0:
    case FALLOC_FL_KEEP_SIZE:
        filesystem_alloc(current->p->fs, f->n, offset, len,
                mode == FALLOC_FL_KEEP_SIZE,
                closure(h, fs_op_complete, current, f));
        break;
    case FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE:
        filesystem_dealloc(current->p->fs, f->n, offset, len,
                closure(h, fs_op_complete, current, f));
        break;
    default:
        set_syscall_error(current, EINVAL);
    }
    return file_op_maybe_sleep(current);
}
