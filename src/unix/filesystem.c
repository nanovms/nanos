#include <unix_internal.h>
#include <filesystem.h>
#include <storage.h>

#define SYMLINK_HOPS_MAX    8

sysreturn sysreturn_from_fs_status(fs_status s)
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

sysreturn sysreturn_from_fs_status_value(status s)
{
    if (is_ok(s))
        return 0;
    value v = table_find(s, sym(fsstatus));
    u64 fss;
    sysreturn rv;

    /* block r/w errors won't include an fs status, so assume I/O error if none found */
    if (v && tagof(v) != tag_tuple && u64_from_value(v, &fss))
        rv = sysreturn_from_fs_status(fss);
    else
        rv = -EIO;
    return rv;
}

tuple lookup_follow_mounts(filesystem *fs, tuple t, symbol a, tuple *p)
{
    *p = t;
    t = lookup(t, a);
    if (!t)
        return t;
    tuple m = table_find(t, sym(mount));
    if (m) {
        t = table_find(m, sym(root));
        if (fs)
            *fs = storage_get_fs(t);
    } else if ((t == *p) && (a == sym_this(".."))) {
        /* t is the root of its filesystem: look for a mount point for this
         * filesystem, and if found look up the parent of the mount directory.
         */
        tuple mp = storage_get_mountpoint(t);
        if (mp) {
            *p = mp;
            t = lookup(mp, a);
            if (fs)
                *fs = current->p->root_fs;
        }
    }
    return t;
}

/* If the file path being resolved crosses a filesystem boundary (i.e. a mount
 * point), the 'fs' argument (if non-null) is updated to point to the new
 * filesystem. */
// fused buffer wrap, split, and resolve
int resolve_cstring(filesystem *fs, tuple cwd, const char *f, tuple *entry,
                    tuple *parent)
{
    if (!f)
        return -EFAULT;

    tuple t = *f == '/' ? filesystem_getroot(current->p->root_fs) : cwd;
    if (fs && (*f == '/'))
        *fs = current->p->root_fs;
    tuple p = t;
    buffer a = little_stack_buffer(NAME_MAX);
    char y;
    int nbytes;
    int err;

    while ((y = *f)) {
        if (y == '/') {
            if (buffer_length(a)) {
                t = lookup_follow_mounts(fs, t, intern(a), &p);
                if (!t) {
                    err = -ENOENT;
                    goto done;
                }
                err = filesystem_follow_links(fs, t, p, &t);
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
        t = lookup_follow_mounts(fs, t, intern(a), &p);
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

/* If the file path being resolved crosses a filesystem boundary (i.e. a mount
 * point), the 'fs' argument (if non-null) is updated to point to the new
 * filesystem. */
int resolve_cstring_follow(filesystem *fs, tuple cwd, const char *f, tuple *entry,
        tuple *parent)
{
    tuple t, p;
    int ret = resolve_cstring(fs, cwd, f, &t, &p);
    if (!ret) {
        ret = filesystem_follow_links(fs, t, p, &t);
    }
    if ((ret == 0) && entry) {
        *entry = t;
    }
    if (parent) {
        *parent = p;
    }
    return ret;
}

int filesystem_follow_links(filesystem *fs, tuple link, tuple parent,
                            tuple *target)
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
        int ret = resolve_cstring(fs, parent, cstring(target_b, buf), &target_t,
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
    filesystem fs = current->p->cwd_fs;
    tuple parent;
    int ret = resolve_cstring(&fs, current->p->cwd, path, 0, &parent);
    if (ret == 0) {
        return -EEXIST;
    }
    if ((ret != -ENOENT) || !parent) {
        return ret;
    }
    return sysreturn_from_fs_status(do_mkentry(fs, parent,
        filename_from_path(path), t, true));
}

void file_readahead(file f, u64 offset, u64 len)
{
    u64 ra_size = 0;
    switch (f->fadv) {
    case POSIX_FADV_NORMAL:
        ra_size = FILE_READAHEAD_DEFAULT;
        break;
    case POSIX_FADV_RANDOM: /* no read-ahead */
        break;
    case POSIX_FADV_SEQUENTIAL:
        ra_size = 2 * FILE_READAHEAD_DEFAULT;
        break;
    }
    if (ra_size > 0)
        pagecache_node_fetch_pages(fsfile_get_cachenode(f->fsf),
            irangel(offset + len, ra_size));
}

closure_function(4, 1, void, fs_sync_complete,
                 filesystem, fs, pagecache_node, pn, status_handler, sh, boolean, fs_flushed,
                 status, s)
{
    if (is_ok(s) && !bound(fs_flushed)) {
        bound(fs_flushed) = true;
        if (bound(pn))
            pagecache_sync_node(bound(pn), (status_handler)closure_self());
        else
            pagecache_sync_volume(filesystem_get_pagecache_volume(bound(fs)),
                (status_handler)closure_self());
        return;
    }
    apply(bound(sh), s);
    closure_finish();
}

static void filesystem_sync_internal(filesystem fs, pagecache_node pn,
                                     status_handler sh)
{
    status_handler sync_complete = closure(heap_general(get_kernel_heaps()),
        fs_sync_complete, fs, pn, sh, false);
    if (sync_complete == INVALID_ADDRESS) {
        apply(sh, timm("result", "cannot allocate closure"));
        return;
    }
    filesystem_flush(fs, sync_complete);
}

void filesystem_sync(filesystem fs, status_handler sh)
{
    filesystem_sync_internal(fs, 0, sh);
}

void filesystem_sync_node(filesystem fs, pagecache_node pn, status_handler sh)
{
    filesystem_sync_internal(fs, pn, sh);
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

static sysreturn symlink_internal(filesystem fs, tuple cwd, const char *path,
        const char *target)
{
    if (!validate_user_string(path) || !validate_user_string(target)) {
        return set_syscall_error(current, EFAULT);
    }
    tuple parent;
    int ret = resolve_cstring(&fs, cwd, path, 0, &parent);
    if ((ret != -ENOENT) || !parent) {
        return set_syscall_return(current, ret);
    }
    if (filesystem_symlink(fs, parent, filename_from_path(path),
        target))
        return 0;
    else
        return -ENOSPC;
}

sysreturn symlink(const char *target, const char *linkpath)
{
    thread_log(current, "symlink %s -> %s", linkpath, target);
    return symlink_internal(current->p->cwd_fs, current->p->cwd, linkpath,
        target);
}

sysreturn symlinkat(const char *target, int dirfd, const char *linkpath)
{
    thread_log(current, "symlinkat %d %s -> %s", dirfd, linkpath, target);
    filesystem fs;
    tuple cwd = resolve_dir(fs, dirfd, linkpath);
    return symlink_internal(fs, cwd, linkpath, target);
}

static sysreturn utime_internal(const char *filename, timestamp actime,
        timestamp modtime)
{
    tuple t;
    filesystem fs = current->p->cwd_fs;
    int ret = resolve_cstring(&fs, current->p->cwd, filename, &t, 0);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    filesystem_set_atime(fs, t, actime);
    filesystem_set_mtime(fs, t, modtime);
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

static sysreturn statfs_internal(filesystem fs, tuple t, struct statfs *buf)
{
    if (!buf) {
        return set_syscall_error(current, EFAULT);
    }
    runtime_memset((u8 *) buf, 0, sizeof(*buf));
    if (fs) {
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
    filesystem fs = current->p->cwd_fs;
    tuple t;
    int ret = resolve_cstring(&fs, current->p->cwd, path, &t, 0);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    return statfs_internal(fs, t, buf);
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
    return statfs_internal(f ? f->fs : 0, f ? file_get_meta(f) : 0, buf);
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
    } else if (!fdesc_is_writable(desc)) {
        return -EBADF;
    }

    heap h = heap_general(get_kernel_heaps());
    file f = (file) desc;
    filesystem fs = f->fs;
    tuple t = fsfile_get_meta(f->fsf);
    file_op_begin(current);
    switch (mode) {
    case 0:
    case FALLOC_FL_KEEP_SIZE:
        filesystem_alloc(fs, t, offset, len,
                mode == FALLOC_FL_KEEP_SIZE,
                closure(h, fs_op_complete, current, f));
        break;
    case FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE:
        filesystem_dealloc(fs, t, offset, len,
                closure(h, fs_op_complete, current, f));
        break;
    default:
        set_syscall_error(current, EINVAL);
    }
    return file_op_maybe_sleep(current);
}

sysreturn fadvise64(int fd, s64 off, u64 len, int advice)
{
    fdesc desc = resolve_fd(current->p, fd);
    if (desc->type != FDESC_TYPE_REGULAR) {
        switch (desc->type) {
        case FDESC_TYPE_PIPE:
        case FDESC_TYPE_STDIO:
            return -ESPIPE;
        default:
            return -EBADF;
        }
    }
    file f = (file)desc;
    switch (advice) {
    case POSIX_FADV_NORMAL:
    case POSIX_FADV_RANDOM:
    case POSIX_FADV_SEQUENTIAL:
        f->fadv = advice;
        break;
    case POSIX_FADV_WILLNEED: {
        pagecache_node pn = fsfile_get_cachenode(f->fsf);
        range r = (len != 0) ? irangel(off, len) :
                irange(off, pagecache_get_node_length(pn));
        pagecache_node_fetch_pages(pn, r);
        break;
    }
    case POSIX_FADV_DONTNEED:
    case POSIX_FADV_NOREUSE:
        break;
    default:
        return -EINVAL;
    }
    return 0;
}
