#include <unix_internal.h>
#include <filesystem.h>
#include <storage.h>

#define FS_KNOWN_SEALS  \
    (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)

sysreturn sysreturn_from_fs_status_value(status s)
{
    if (is_ok(s))
        return 0;
    s64 fss;
    sysreturn rv;

    /* block r/w errors won't include an fs status, so assume I/O error if none found */
    if (get_s64(s, sym(fsstatus), &fss))
        rv = fss;
    else
        rv = -EIO;
    return rv;
}

u16 stat_mode(process p, int type, tuple meta)
{
    u16 mode;
    switch (type) {
    case FDESC_TYPE_REGULAR:
        mode = S_IFREG;
        break;
    case FDESC_TYPE_DIRECTORY:
        mode = S_IFDIR;
        break;
    case FDESC_TYPE_STDIO:
    case FDESC_TYPE_SPECIAL:    /* assuming only character devices */
        mode = S_IFCHR;
        break;
    case FDESC_TYPE_SOCKET:
        mode = S_IFSOCK;
        break;
    case FDESC_TYPE_PIPE:
        mode = S_IFIFO;
        break;
    case FDESC_TYPE_SYMLINK:
        mode = S_IFLNK;
        break;
    default:
        return 0;
    }
    u32 perms = file_meta_perms(p, meta);
    if (perms & ACCESS_PERM_READ)
        mode |= 0444;
    if (perms & ACCESS_PERM_WRITE)
        mode |= 0222;
    if (perms & ACCESS_PERM_EXEC)
        mode |= 0111;
    return mode;
}

closure_function(2, 0, void, file_cache_async,
                 pagecache_node, pn, range, r)
{
    pagecache_node pn = bound(pn);
    pagecache_node_fetch_pages(pn, bound(r), 0, 0);
    pagecache_node_unref(pn);
    closure_finish();
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
    if (ra_size > 0) {
        pagecache_node pn = fsfile_get_cachenode(f->fsf);
        thunk t = closure(heap_locked(get_kernel_heaps()), file_cache_async, pn,
                          irangel(offset + len, ra_size));
        if (t != INVALID_ADDRESS) {
            pagecache_node_ref(pn);
            async_apply(t);
        }
    }
}

static sysreturn file_io_init_internal(file f, u64 offset, struct iovec *iov, int count, sg_list sg)
{
    if (!(f->f.flags & O_DIRECT)) {
        return iov_to_sg(sg, iov, count) ? 0 : -ENOMEM;
    }
    u64 block_mask = fs_blocksize(f->fs) - 1;
    if (offset & block_mask)
        return -EINVAL;
    for (int i = 0; i < count; i++) {
        u64 len = iov[i].iov_len;
        if (len == 0)
            continue;
        void *ptr = iov[i].iov_base;
        if ((u64_from_pointer(ptr) & block_mask) || (len & block_mask))
            return -EINVAL;
        touch_memory(ptr, len);
        u64 phys = physical_from_virtual(ptr);
        if (phys == INVALID_PHYSICAL)
            return -EFAULT;
        void *end = ptr + len;
        /* ensure each SG buffer references a physically contiguous memory range */
        void *contiguous_base = ptr;
        u64 contiguous_len;
        if ((u64_from_pointer(end - 1) & ~PAGEMASK) == (u64_from_pointer(ptr) & ~PAGEMASK)) {
            contiguous_len = end - ptr; /* range fits in a single page */
        } else {
            ptr = pointer_from_u64(pad(u64_from_pointer(ptr + 1), PAGESIZE));
            contiguous_len = ptr - contiguous_base;
            phys += contiguous_len;
            for (; ptr < end; ptr += PAGESIZE, phys += PAGESIZE) {
                u64 next_phys = physical_from_virtual(ptr);
                if ((next_phys != phys) || (contiguous_len + PAGESIZE >= U64_FROM_BIT(32))) {
                    if (next_phys == INVALID_PHYSICAL)
                        return -EFAULT;
                    sg_buf sgb = sg_list_tail_add(sg, contiguous_len);
                    if (sgb == INVALID_ADDRESS)
                        return -ENOMEM;
                    sgb->buf = contiguous_base;
                    sgb->size = contiguous_len;
                    sgb->offset = 0;
                    sgb->refcount = 0;
                    contiguous_base = ptr;
                    contiguous_len = 0;
                    phys = next_phys;
                }
                contiguous_len += MIN(end - ptr, PAGESIZE);
            }
        }
        sg_buf sgb = sg_list_tail_add(sg, contiguous_len);
        if (sgb == INVALID_ADDRESS)
            return -ENOMEM;
        sgb->buf = contiguous_base;
        sgb->size = contiguous_len;
        sgb->offset = 0;
        sgb->refcount = 0;
    }
    return 0;
}

sysreturn file_io_init_sg(file f, u64 offset, struct iovec *iov, int count, sg_list *sgp)
{
    sg_list sg = sg_new(count);
    if (sg == INVALID_ADDRESS)
        return -ENOMEM;
    sysreturn rv;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        rv = -EFAULT;
        goto out;
    }
    rv = file_io_init_internal(f, offset, iov, count, sg);
    if (!rv)
        *sgp = sg;
  out:
    if (rv != -EFAULT)
        context_clear_err(ctx);
    if (rv < 0)
        deallocate_sg_list(sg);
    return rv;
}

int filesystem_chdir(process p, sstring path)
{
    process_lock(p);
    filesystem fs = p->cwd_fs;
    int fss;
    tuple n;
    fss = filesystem_get_node(&fs, p->cwd, path, FS_NODE_FOLLOW, &n, 0, 0);
    if (fss != 0)
        goto out;
    if (!is_dir(n)) {
        fss = -ENOENT;
    } else {
        if (fs != p->cwd_fs) {
            filesystem_release(p->cwd_fs);
            filesystem_reserve(fs);
            p->cwd_fs = fs;
        }
        p->cwd = fs->get_inode(fs, n);
        fss = 0;
    }
    filesystem_put_node(fs, n);
  out:
    process_unlock(p);
    return fss;
}

void filesystem_update_relatime(filesystem fs, tuple md)
{
    timestamp here = now(CLOCK_ID_REALTIME);
    timestamp atime = filesystem_get_atime(fs, md);
    boolean update;
    if (here > atime + seconds(24 * 60 * 60))
        update = true;
    else
        update = (atime <= filesystem_get_mtime(fs, md));
    if (update)
        filesystem_set_atime(fs, md, here);
}

closure_function(2, 1, void, fs_op_complete,
                 thread, t, file, f,
                 int ret)
{
    thread t = bound(t);

    fdesc_put(&bound(f)->f);
    syscall_return(t, ret);     /* returns on kernel context */
    closure_finish();
}

static sysreturn symlink_internal(filesystem fs, inode cwd, sstring path,
        const char *target)
{
    sstring target_ss;
    if (!fault_in_user_string(target, &target_ss))
        return -EFAULT;
    return filesystem_symlink(fs, cwd, path, target_ss);
}

sysreturn symlink(const char *target, const char *linkpath)
{
    sstring path_ss;
    if (!fault_in_user_string(linkpath, &path_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = symlink_internal(cwd_fs, cwd, path_ss, target);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn symlinkat(const char *target, int dirfd, const char *linkpath)
{
    filesystem fs;
    sstring path_ss;
    inode cwd = resolve_dir(fs, dirfd, linkpath, path_ss);
    sysreturn rv = symlink_internal(fs, cwd, path_ss, target);
    filesystem_release(fs);
    return rv;
}

static sysreturn utime_internal(const char *filename, timestamp actime,
        timestamp modtime)
{
    tuple t;
    filesystem fs;
    inode cwd;
    sstring filename_ss;
    if (!fault_in_user_string(filename, &filename_ss))
        return -EFAULT;
    process_get_cwd(current->p, &fs, &cwd);
    filesystem cwd_fs = fs;
    sysreturn rv = filesystem_get_node(&fs, cwd, filename_ss, FS_NODE_FOLLOW, &t, 0, 0);
    if (rv == 0) {
        filesystem_set_atime(fs, t, actime);
        filesystem_set_mtime(fs, t, modtime);
        filesystem_put_node(fs, t);
    }
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn utime(const char *filename, const struct utimbuf *times)
{
    context ctx;
    if (times) {
        ctx = get_current_context(current_cpu());
        if (!validate_user_memory(times, sizeof(struct utimbuf), false) || context_set_err(ctx))
            return -EFAULT;
    }
    timestamp atime = times ? seconds(times->actime) : now(CLOCK_ID_REALTIME);
    timestamp mtime = times ? seconds(times->modtime) : now(CLOCK_ID_REALTIME);
    if (times)
        context_clear_err(ctx);
    return utime_internal(filename, atime, mtime);
}

sysreturn utimes(const char *filename, const struct timeval times[2])
{
    context ctx;
    if (times) {
        ctx = get_current_context(current_cpu());
        if (!validate_user_memory(times, 2 * sizeof(struct timeval), false) || context_set_err(ctx))
            return -EFAULT;
    }
    /* Sub-second precision is not supported. */
    timestamp atime =
            times ? time_from_timeval(&times[0]) : now(CLOCK_ID_REALTIME);
    timestamp mtime =
            times ? time_from_timeval(&times[1]) : now(CLOCK_ID_REALTIME);
    if (times)
        context_clear_err(ctx);
    return utime_internal(filename, atime, mtime);
}

static boolean utimens_is_valid(const struct timespec *t)
{
    return (t->tv_nsec < BILLION) || (t->tv_nsec == UTIME_NOW) || (t->tv_nsec == UTIME_OMIT);
}

static timestamp time_from_utimens(const struct timespec *t)
{
    if (t->tv_nsec == UTIME_NOW)
        return now(CLOCK_ID_REALTIME);
    if (t->tv_nsec == UTIME_OMIT)
        return infinity;
    return time_from_timespec(t);
}

sysreturn utimensat(int dirfd, const char *filename, const struct timespec times[2], int flags)
{
    timestamp atime, mtime;
    if (times) {
        context ctx = get_current_context(current_cpu());
        if (!validate_user_memory(times, 2 * sizeof(struct timespec), false) ||
            context_set_err(ctx))
            return -EFAULT;
        if (!utimens_is_valid(&times[0]) || !utimens_is_valid(&times[1]))
            return -EINVAL;
        atime = time_from_utimens(&times[0]);
        mtime = time_from_utimens(&times[1]);
        context_clear_err(ctx);
    } else {
        atime = mtime = now(CLOCK_ID_REALTIME);
    }
    if (flags & ~AT_SYMLINK_NOFOLLOW)
        return -EINVAL;
    tuple t;
    filesystem fs, cwd_fs;
    sysreturn rv;
    if (filename) {
        sstring filename_ss;
        inode cwd = resolve_dir(fs, dirfd, filename, filename_ss);
        cwd_fs = fs;
        rv = filesystem_get_node(&fs, cwd, filename_ss,
                                 (flags & AT_SYMLINK_NOFOLLOW) ? 0 : FS_NODE_FOLLOW, &t, 0, 0);
        if (rv)
            filesystem_release(cwd_fs);
    } else {
        file f = resolve_fd(current->p, dirfd);
        switch (f->f.type) {
        case FDESC_TYPE_REGULAR:
        case FDESC_TYPE_DIRECTORY:
        case FDESC_TYPE_SYMLINK:
        case FDESC_TYPE_SOCKET:
            fs = f->fs;
            t = filesystem_get_meta(fs, f->n);
            rv = t ? 0 : -ENOENT;
            break;
        default:
            rv = -EACCES;
        }
        fdesc_put(&f->f);
    }
    if (rv == 0) {
        if (atime != infinity)
            filesystem_set_atime(fs, t, atime);
        if (mtime != infinity)
            filesystem_set_mtime(fs, t, mtime);
        if (filename) {
            filesystem_put_node(fs, t);
            filesystem_release(cwd_fs);
        } else {
            filesystem_put_meta(fs, t);
        }
    }
    return rv;
}

static sysreturn statx_internal(filesystem fs, int type, tuple n, fsfile f, struct statx *statxbuf)
{
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(statxbuf, sizeof(struct rlimit), true) || context_set_err(ctx))
        return -EFAULT;
    zero(statxbuf, sizeof(*statxbuf));
    statxbuf->stx_mode = stat_mode(current->p, type, n);
    statxbuf->stx_mask = STATX_TYPE | STATX_MODE;
    switch (type) {
    case FDESC_TYPE_REGULAR:
        statxbuf->stx_size = fsfile_get_length(f);
        statxbuf->stx_blocks = fsfile_get_blocks(f);
        statxbuf->stx_blksize = PAGESIZE;
        statxbuf->stx_dio_mem_align = statxbuf->stx_dio_offset_align = SECTOR_SIZE;
        statxbuf->stx_mask |= STATX_SIZE | STATX_BLOCKS | STATX_DIOALIGN;
        break;
    case FDESC_TYPE_SYMLINK:
        statxbuf->stx_size = buffer_length(linktarget(n));
        statxbuf->stx_mask |= STATX_SIZE;
        break;
    case FDESC_TYPE_STDIO:
        /* Describing stdout as a pseudo-tty makes glibc apply line buffering (instead of full
         * buffering) when the process writes to stdout. */
        statxbuf->stx_rdev_major = UNIX98_PTY_SLAVE_MAJOR;
        statxbuf->stx_rdev_minor = 0;
        break;
    case FDESC_TYPE_SPECIAL:
        if (n) {
            u64 rdev = filesystem_get_rdev(fs, n);
            statxbuf->stx_rdev_major = MAJOR(rdev);
            statxbuf->stx_rdev_minor = MINOR(rdev);
        }
        break;
    }
    if (n) {
        statxbuf->stx_ino = fs->get_inode(fs, n);
        statxbuf->stx_mask |= STATX_INO;
        timestamp t;
        struct timespec ts;
        t = filesystem_get_atime(fs, n);
        if (t) {
            timespec_from_time(&ts, t);
            statxbuf->stx_atime.tv_sec = ts.tv_sec;
            statxbuf->stx_atime.tv_nsec = ts.tv_nsec;
            statxbuf->stx_mask |= STATX_ATIME;
        }
        t = filesystem_get_mtime(fs, n);
        if (t) {
            timespec_from_time(&ts, t);
            statxbuf->stx_mtime.tv_sec = ts.tv_sec;
            statxbuf->stx_mtime.tv_nsec = ts.tv_nsec;
            statxbuf->stx_mask |= STATX_MTIME;
        }
    }
    context_clear_err(ctx);
    return 0;
}

static sysreturn statx_node(filesystem fs, inode cwd, sstring pathname, int flags,
                            struct statx *statxbuf)
{
    tuple n;
    fsfile f;
    sysreturn rv = filesystem_get_node(&fs, cwd, pathname,
                                       (flags & AT_SYMLINK_NOFOLLOW) ? 0 : FS_NODE_FOLLOW,
                                       &n, 0, &f);
    if (rv == 0) {
        rv = statx_internal(fs, file_type_from_tuple(n), n, f, statxbuf);
        filesystem_put_node(fs, n);
        if (f)
            fsfile_release(f);
    }
    return rv;
}

sysreturn statx(int dirfd, const char *pathname, int flags, unsigned int mask,
                struct statx *statxbuf)
{
    if ((flags & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | AT_STATX_SYNC_AS_STAT |
                   AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC)) || (mask & STATX__RESERVED))
        return -EINVAL;
    filesystem fs;
    sysreturn rv;
    if (flags & AT_EMPTY_PATH) {
        process p = current->p;
        if (dirfd == AT_FDCWD) {
            inode cwd;
            process_get_cwd(p, &fs, &cwd);
            rv = statx_node(fs, cwd, ss("."), flags, statxbuf);
            filesystem_release(fs);
        } else {
            fdesc f = resolve_fd(p, dirfd);
            int type = f->type;
            tuple n;
            fsfile fsf = 0;
            switch (type) {
            case FDESC_TYPE_REGULAR:
                fsf = ((file)f)->fsf;
                /* no break */
            case FDESC_TYPE_DIRECTORY:
            case FDESC_TYPE_SPECIAL:
            case FDESC_TYPE_SYMLINK:
                fs = ((file)f)->fs;
                n = filesystem_get_meta(fs, ((file)f)->n);
                break;
            default:
                fs = 0;
                n = 0;
                break;
            }
            rv = statx_internal(fs, type, n, fsf, statxbuf);
            if (n)
                filesystem_put_meta(fs, n);
            fdesc_put(f);
        }
    } else {
        sstring name_ss;
        inode cwd = resolve_dir(fs, dirfd, pathname, name_ss);
        rv = statx_node(fs, cwd, name_ss, flags, statxbuf);
        filesystem_release(fs);
    }
    return rv;
}

static sysreturn statfs_internal(filesystem fs, tuple t, struct statfs *buf)
{
    if (!fault_in_user_memory(buf, sizeof(struct statfs), true))
        return -EFAULT;
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
    filesystem fs;
    inode cwd;
    process_get_cwd(current->p, &fs, &cwd);
    sstring path_ss;
    filesystem cwd_fs = fs;
    tuple t = 0;
    sysreturn rv;
    if (!fault_in_user_string(path, &path_ss)) {
        rv = -EFAULT;
        goto out;
    }
    rv = filesystem_get_node(&fs, cwd, path_ss, 0, &t, 0, 0);
    if (rv == 0)
        rv = statfs_internal(fs, t, buf);
  out:
    if (t)
        filesystem_put_node(fs, t);
    filesystem_release(cwd_fs);
    return rv;
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
    tuple t = 0;
    sysreturn rv;
    if (f)
        t = filesystem_get_meta(f->fs, f->n);
    rv = statfs_internal(f ? f->fs : 0, t, buf);
    fdesc_put(desc);
    if (t)
        filesystem_put_meta(f->fs, t);
    return rv;
}

sysreturn fallocate(int fd, int mode, long offset, long len)
{
    fdesc desc = resolve_fd(current->p, fd);
    sysreturn rv;
    if (desc->type != FDESC_TYPE_REGULAR) {
        switch (desc->type) {
        case FDESC_TYPE_PIPE:
        case FDESC_TYPE_STDIO:
            rv = -ESPIPE;
            break;
        default:
            rv = -ENODEV;
        }
        goto out;
    } else if (!fdesc_is_writable(desc)) {
        rv = -EBADF;
        goto out;
    }

    heap h = heap_locked(get_kernel_heaps());
    file f = (file) desc;
    switch (mode) {
    case 0:
    case FALLOC_FL_KEEP_SIZE:
        filesystem_alloc(f->fsf, offset, len,
                         mode == FALLOC_FL_KEEP_SIZE,
                         closure(h, fs_op_complete, current, f));
        break;
    case FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE:
        filesystem_dealloc(f->fsf, offset, len,
                           closure(h, fs_op_complete, current, f));
        break;
    default:
        rv = -EINVAL;
        goto out;
    }
    return thread_maybe_sleep_uninterruptible(current);
  out:
    fdesc_put(desc);
    return rv;
}

sysreturn fadvise64(int fd, s64 off, u64 len, int advice)
{
    fdesc desc = resolve_fd(current->p, fd);
    sysreturn rv;
    if (desc->type != FDESC_TYPE_REGULAR) {
        switch (desc->type) {
        case FDESC_TYPE_PIPE:
        case FDESC_TYPE_STDIO:
            rv = -ESPIPE;
            break;
        default:
            rv = -EBADF;
        }
        goto out;
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
        pagecache_node_fetch_pages(pn, r, 0, 0);
        break;
    }
    case POSIX_FADV_DONTNEED:
    case POSIX_FADV_NOREUSE:
        break;
    default:
        rv = -EINVAL;
        goto out;
    }
    rv = 0;
  out:
    fdesc_put(desc);
    return rv;
}

void file_release(file f)
{
    release_fdesc(&f->f);
    filesystem_release(f->fs);
    if (f->f.type == FDESC_TYPE_SPECIAL)
        spec_deallocate(f);
    else
        unix_cache_free(get_unix_heaps(), file, f);
}

/* file_path is treated as an absolute path for fsfile_open() and fsfile_open_or_create() */
fsfile fsfile_open(sstring file_path)
{
    tuple file;
    fsfile fsf;
    filesystem fs = get_root_fs();
    int s = filesystem_get_node(&fs, fs->get_inode(fs, filesystem_getroot(fs)),
                                      file_path,
                                      FS_NODE_FOLLOW, &file, 0, &fsf);
    if (s == 0) {
        filesystem_put_node(fs, file);
        return fsf;
    }
    return 0;
}

fsfile fsfile_open_or_create(sstring file_path, boolean truncate)
{
    tuple file;
    fsfile fsf;
    filesystem fs = get_root_fs();
    tuple root = filesystem_getroot(fs);
    char *separator = runtime_strrchr(file_path, '/');
    int s;
    if (separator > file_path.ptr) {
        s = filesystem_mkdirpath(fs, 0, isstring(file_path.ptr, separator - file_path.ptr), true);
        if ((s != 0) && (s != -EEXIST))
            return 0;
    }
    s = filesystem_get_node(&fs, fs->get_inode(fs, root), file_path,
                            FS_NODE_CREATE | (truncate ? FS_NODE_TRUNC : 0),
                            &file, 0, &fsf);
    if (s == 0) {
        filesystem_put_node(fs, file);
        return fsf;
    }
    return 0;
}

/* Can be used for files in the root filesystem only. */
int fsfile_truncate(fsfile f, u64 len)
{
    return (filesystem_truncate(get_root_fs(), f, len));
}

closure_function(2, 1, boolean, fsfile_seal_vmap_handler,
                 pagecache_node, pn, boolean *, writable,
                 vmap vm)
{
    if ((vm->cache_node == bound(pn)) && (vm->allowed_flags & VMAP_FLAG_WRITABLE)) {
        *bound(writable) = true;
        return false;
    }
    return true;
}

sysreturn fsfile_add_seals(fsfile f, u64 seals)
{
    if (seals & ~FS_KNOWN_SEALS)
        return -EINVAL;
    filesystem fs = f->fs;
    if (!fs->set_seals)
        return -EINVAL;
    filesystem_lock(fs);
    u64 current_seals;
    int fss = fs->get_seals(fs, f, &current_seals);
    sysreturn rv;
    if (fss == 0) {
        if (current_seals & F_SEAL_SEAL) {
            rv = -EPERM;
            goto out;
        }
        if (seals & F_SEAL_WRITE) {
            pagecache_node pn = fsfile_get_cachenode(f);
            boolean writable_maps = false;
            vmap_iterator(current->p, stack_closure(fsfile_seal_vmap_handler, pn, &writable_maps));
            if (writable_maps) {
                rv = -EBUSY;
                goto out;
            }
        }
        fss = fs->set_seals(fs, f, current_seals | seals);
    }
    rv = fss;
  out:
    filesystem_unlock(fs);
    return rv;
}

sysreturn fsfile_get_seals(fsfile f, u64 *seals)
{
    filesystem fs = f->fs;
    if (!fs->get_seals)
        return -EINVAL;
    return fs->get_seals(fs, f, seals);
}

notify_entry fs_watch(heap h, tuple n, u64 eventmask, event_handler eh, notify_set *s)
{
    tuple watches = get_tuple(n, sym(watches));
    notify_set ns;
    if (!watches) {
        ns = allocate_notify_set(h);
        if (ns == INVALID_ADDRESS)
            return 0;
        watches = allocate_tuple();
        set(watches, sym(no_encode), null_value);
        set(watches, sym(ns), ns);
        set(n, sym(watches), watches);
    } else {
        ns = get(watches, sym(ns));
    }
    notify_entry ne = notify_add(ns, eventmask, eh);
    if (ne != INVALID_ADDRESS) {
        *s = ns;
        return ne;
    }
    return 0;
}

static void fs_notify_internal(tuple md, u64 event, symbol name, u32 cookie)
{
    tuple watches = get_tuple(md, sym(watches));
    if (watches) {
        struct inotify_evdata evdata = {
            .name = name ? symbol_string(name) : 0,
            .cookie = cookie,
        };
        notify_dispatch_with_arg(get(watches, sym(ns)), event, &evdata);
    }
}

void fs_notify_event(tuple n, u64 event)
{
    if (is_dir(n))
        event |= IN_ISDIR;
    fs_notify_internal(n, event, 0, 0);
    tuple parent = get_tuple(n, sym_this(".."));
    if (parent != n)
        fs_notify_internal(parent, event, tuple_get_symbol(children(parent), n), 0);
}

void fs_notify_create(tuple t, tuple parent, symbol name)
{
    u64 event = IN_CREATE;
    if (is_dir(t))
        event |= IN_ISDIR;
    fs_notify_internal(parent, event, name, 0);
}

void fs_notify_move(tuple t, tuple old_parent, symbol old_name, tuple new_parent, symbol new_name)
{
    u64 flags = is_dir(t) ? IN_ISDIR : 0;
    fs_notify_internal(t, IN_MOVE_SELF | flags, 0, 0);
    u32 cookie = random_u64();
    fs_notify_internal(old_parent, IN_MOVED_FROM | flags, old_name, cookie);
    fs_notify_internal(new_parent, IN_MOVED_TO | flags, new_name, cookie);
}

void fs_notify_delete(tuple t, tuple parent, symbol name)
{
    u64 flags = is_dir(t) ? IN_ISDIR : 0;
    fs_notify_internal(t, IN_DELETE_SELF | flags, 0, 0);
    fs_notify_internal(parent, IN_DELETE | flags, name, 0);
}

void fs_notify_modify(tuple t)
{
    fs_notify_event(t, IN_MODIFY);
}

void fs_notify_release(tuple t, boolean unmounted)
{
    tuple watches = get_tuple(t, sym(watches));
    if (watches) {
        notify_set ns = get(watches, sym(ns));
        if (unmounted)
            notify_dispatch_with_arg(ns, IN_UNMOUNT, 0);
        deallocate_notify_set(ns);
        deallocate_value(watches);
        set(t, sym(watches), 0);
    }
}

boolean fs_file_is_busy(filesystem fs, tuple md)
{
    return (get_tuple(md, sym(watches)) != 0);
}
