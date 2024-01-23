
/* tfs-fuse: a FUSE driver for mounting the root TFS volume from a raw disk
 * image on the host
 *
 * This program requires the FUSE library and kernel driver to be installed,
 * for example:
 * Ubuntu/Debian: sudo apt install fuse libfuse-dev
 * Mac OSX: brew install macfuse
 */

#include <runtime.h>
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pagecache.h>
#include <tfs.h>
#include <storage.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64
#include <fuse.h>

//#define TFS_FUSE_DEBUG
#ifdef TFS_FUSE_DEBUG
#define tfs_fuse_debug(fmt, ...) rprintf(fmt, ##__VA_ARGS__)
#else
#define tfs_fuse_debug(fmt, ...)
#endif

#define FLUSH_TIMEOUT 5

static int dfd;
static heap h;

static filesystem rootfs;
static tuple cwd;
static id_heap fdallocator;
static vector files;
static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

#define cwd_inode   u64_from_pointer(cwd)

/* unix internal */
#define FDESC_TYPE_REGULAR      1
#define FDESC_TYPE_DIRECTORY    2
#define FDESC_TYPE_SYMLINK     11

#define resolve_fd_noret(__fd) vector_get(files, __fd)
#define resolve_fd(__fd) ({void *f ; if (!(f = resolve_fd_noret(__fd))) return -EBADF; f;})

typedef closure_type(file_io, int, void *buf, u64 length, u64 offset);

typedef struct fdesc {
    file_io read, write;
    closure_type(close, void);

    u64 refcnt;
    int type;
    int flags;                  /* F_GETFD/F_SETFD flags */
} *fdesc;

typedef struct file {
    struct fdesc f;             /* must be first */
    filesystem fs;
    struct {
        fsfile fsf;         /* fsfile for regular files */
        sg_io fs_read;
        sg_io fs_write;
        int fadv;           /* posix_fadvise advice */
    };
    inode n;                /* filesystem inode number */
    u64 offset;
    u64 length;
} *file;

static inline void init_fdesc(heap h, fdesc f, int type)
{
    f->read = 0;
    f->write = 0;
    f->close = 0;
    f->refcnt = 1;
    f->type = type;
    f->flags = 0;
}

u64 allocate_fd(void *f)
{
    u64 fd = allocate_u64((heap)fdallocator, 1);
    if (fd == INVALID_PHYSICAL) {
        fprintf(stderr, "fail; maxed out\n");
        return fd;
    }
    if (!vector_set(files, fd, f)) {
        deallocate_u64((heap)fdallocator, fd, 1);
        fd = INVALID_PHYSICAL;
    }
    return fd;
}

void deallocate_fd(int fd)
{
    assert(vector_set(files, fd, 0));
    deallocate_u64((heap)fdallocator, fd, 1);
}

static inline void timespec_from_time(struct timespec *ts, timestamp t)
{
    ts->tv_sec = sec_from_timestamp(t);
    ts->tv_nsec = nsec_from_timestamp(truncate_seconds(t));
}

int rv_from_fs_status(fs_status s)
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
    case FS_STATUS_INVAL:
        return -EINVAL;
    case FS_STATUS_NOTDIR:
        return -ENOTDIR;
    case FS_STATUS_ISDIR:
        return -EISDIR;
    case FS_STATUS_NOTEMPTY:
        return -ENOTEMPTY;
    case FS_STATUS_NOMEM:
        return -ENOMEM;
    case FS_STATUS_LINKLOOP:
        return -ELOOP;
    case FS_STATUS_NAMETOOLONG:
        return -ENAMETOOLONG;
    default:
        return 0;
    }
}

int rv_from_fs_status_value(status s)
{
    if (is_ok(s))
        return 0;
    u64 fss;
    int rv;

    /* block r/w errors won't include an fs status, so assume I/O error if none found */
    if (get_u64(s, sym(fsstatus), &fss))
        rv = rv_from_fs_status(fss);
    else
        rv = -EIO;
    return rv;
}

int resolve_cstring(filesystem *fs, tuple cwd, const char *f, tuple *entry, tuple *parent)
{
    if (!f)
        return -EFAULT;
    return rv_from_fs_status(filesystem_resolve_cstring(fs, cwd, f, entry, parent));
}

int resolve_cstring_follow(filesystem *fs, tuple cwd, const char *f, tuple *entry,
        tuple *parent)
{
    if (!f)
        return -EFAULT;
    return rv_from_fs_status(filesystem_resolve_cstring_follow(fs, cwd, f, entry, parent));
}

static int file_type_from_tuple(tuple n)
{
    if (is_dir(n))
        return FDESC_TYPE_DIRECTORY;
    else if (is_symlink(n))
        return FDESC_TYPE_SYMLINK;
    else
        return FDESC_TYPE_REGULAR;
}

static inline tuple file_get_meta(file f)
{
    return pointer_from_u64(f->n);
}

closure_function(2, 1, void, req_handle,
                 descriptor, d, u64, fs_offset,
                 storage_req, req)
{
    sg_list sg;
    u64 offset;
    u64 total;
    struct iovec iov[IOV_MAX];
    int iov_count;
    boolean write;
    ssize_t xfer;

    tfs_fuse_debug("storage request %d, blocks %R\n", req->op, req->blocks);
    switch (req->op) {
    case STORAGE_OP_READSG:
    case STORAGE_OP_WRITESG:
        write = (req->op == STORAGE_OP_WRITESG);
        sg = req->data;
        offset = bound(fs_offset) + (req->blocks.start << SECTOR_OFFSET);
        total = range_span(req->blocks) << SECTOR_OFFSET;
        lseek(bound(d), offset, SEEK_SET);
        while (total > 0) {
            iov_count = 0;
            xfer = 0;
            sg_list_foreach(sg, sgb) {
                iov[iov_count].iov_base = sgb->buf + sgb->offset;
                iov[iov_count].iov_len = MIN(sg_buf_len(sgb), total - xfer);
                xfer += iov[iov_count].iov_len;
                if ((++iov_count == IOV_MAX) || (xfer == total))
                    break;
            }
            if (write) {
                xfer = writev(bound(d), iov, iov_count);
                if (xfer < 0 && errno != EINTR) {
                    apply(req->completion,
                          timm("result", "write error", "error", "%s", strerror(errno)));
                    return;
                }
            } else {
                xfer = readv(bound(d), iov, iov_count);
                if (xfer < 0 && errno != EINTR) {
                    apply(req->completion,
                          timm("result", "read error", "error", "%s", strerror(errno)));
                    return;
                }
                if (xfer == 0) {
                    apply(req->completion, timm("result", "end of file"));
                    return;
                }
            }
            sg_consume(sg, xfer);
            offset += xfer;
            total -= xfer;
        }
        break;
    case STORAGE_OP_FLUSH:
        break;
    default:
        halt("%s: invalid storage op %d\n", __func__, req->op);
    }
    apply(req->completion, STATUS_OK);
}

static u64 get_fs_offset(descriptor fd, int part, boolean by_index, u64 *length)
{
    char buf[512];

    ssize_t nr = read(fd, buf, sizeof(buf));
    if (nr < 0 || nr < sizeof(buf)) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    struct partition_entry *rootfs_part =
            (by_index ? partition_at(buf, part) : partition_get(buf, part));

    if (!rootfs_part || rootfs_part->lba_start == 0 ||
            rootfs_part->nsectors == 0) {
        // probably raw filesystem
        return 0;
    }

    u64 fs_offset = rootfs_part->lba_start * SECTOR_SIZE;
    if (length)
        *length = rootfs_part->nsectors * SECTOR_SIZE;
    tfs_fuse_debug("detected filesystem at 0x%llx\n", fs_offset);
    return fs_offset;
}

static void set_flush_timeout()
{
    alarm(FLUSH_TIMEOUT);
}

static void fill_stat(int type, tuple n, struct stat *s)
{
    zero(s, sizeof(struct stat));
    switch (type) {
    case FDESC_TYPE_DIRECTORY:
        s->st_mode = S_IFDIR | 0777;
        break;
    case FDESC_TYPE_SYMLINK:
        s->st_mode = S_IFLNK | 0777;
        break;
    case FDESC_TYPE_REGULAR:
        s->st_mode = S_IFREG | 0666;
        break;
    default:
        assert(0);
    }
    s->st_ino = u64_from_pointer(n);
    if (type == FDESC_TYPE_REGULAR) {
        fsfile f = fsfile_from_node(rootfs, n);
        if (f) {
            s->st_size = fsfile_get_length(f);
            s->st_blocks = fsfile_get_blocks(f);
        }
        s->st_blksize = PAGESIZE;   /* "preferred" block size for efficient filesystem I/O */
    }
    if (n) {
        struct timespec ts;
        timespec_from_time(&ts, filesystem_get_atime(rootfs, n));
        s->st_atime = ts.tv_sec;
        timespec_from_time(&ts, filesystem_get_mtime(rootfs, n));
        s->st_mtime = ts.tv_sec;
    }
}

static int tfs_getattr(const char *name, struct stat *s)
{
    tuple n;
    pthread_rwlock_rdlock(&rwlock);
    int r = resolve_cstring(&rootfs, cwd, name, &n, 0);
    if (r) {
        pthread_rwlock_unlock(&rwlock);
        return r;
    }
    fill_stat(file_type_from_tuple(n), n, s);
    pthread_rwlock_unlock(&rwlock);
    return 0;
}

closure_function(6, 1, void, file_read_complete,
                 sg_list, sg, void *, dest, u64, limit, file, f, boolean, is_file_offset, int *, rv,
                 status, s)
{
    int *rv = bound(rv);
    if (is_ok(s)) {
        file f = bound(f);
        u64 count = sg_copy_to_buf_and_release(bound(dest), bound(sg), bound(limit));
        if (bound(is_file_offset)) /* vs specified offset (pread) */
            f->offset += count;
        *rv = count;
    } else {
        *rv = rv_from_fs_status_value(s);
    }
    closure_finish();
}

closure_function(2, 3, int, file_read,
                 file, f, fsfile, fsf,
                 void *, dest, u64, length, u64, offset_arg)
{
    file f = bound(f);

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;

    if (offset >= f->length) {
        return 0;
    }
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        fprintf(stderr, "   unable to allocate sg list");
        return -ENOMEM;
    }
    int rv;
    apply(f->fs_read, sg, irangel(offset, length), closure(h, file_read_complete, sg, dest, length,
                                                           f, is_file_offset, &rv));
    return rv;
}

closure_function(5, 1, void, file_write_complete,
                 file, f, sg_list, sg, u64, length, boolean, is_file_offset, int *, rv,
                 status, s)
{
    tfs_fuse_debug("file_write_complete status %v\n", s);
    sg_list_release(bound(sg));
    deallocate_sg_list(bound(sg));
    file f = bound(f);
    u64 len = bound(length);
    int *rv = bound(rv);
    if (is_ok(s)) {
        /* if regular file, update length */
        if (f->fsf)
            f->length = fsfile_get_length(f->fsf);
        if (bound(is_file_offset))
            f->offset += len;
        *rv = len;
    } else {
        *rv = rv_from_fs_status_value(s);
    }
    closure_finish();
}

closure_function(2, 3, int, file_write,
                file, f, fsfile, fsf,
                void *, src, u64, length, u64, offset_arg)
{
    file f = bound(f);
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;

    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        fprintf(stderr, "   unable to allocate sg list");
        return -ENOMEM;
    }
    sg_buf sgb = sg_list_tail_add(sg, length);
    assert(sgb != INVALID_ADDRESS);
    sgb->buf = src;
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = 0;

    int rv;
    tfs_fuse_debug("file_write range %R\n", irangel(offset, length));
    apply(f->fs_write, sg, irangel(offset, length), closure(h, file_write_complete,
                                                            f, sg, length, is_file_offset, &rv));
    return rv;
}

closure_function(2, 0, void, file_close,
                file, f, fsfile, fsf)
{
    file f = bound(f);
    deallocate_closure(f->f.read);
    deallocate_closure(f->f.write);
    deallocate_closure(f->f.close);
    fsfile_release(f->fsf);
    deallocate(h, f, sizeof(struct file));
}

#ifndef O_PATH
#define O_PATH 0
#endif
static int open_internal(const char *name, int flags, int mode)
{
    tuple n;
    int ret;

    fsfile fsf;
    fs_status fss = filesystem_get_node(&rootfs, cwd_inode, name, !!(flags & O_NOFOLLOW),
        !!(flags & O_CREAT), !!(flags & O_EXCL), !!(flags & O_TRUNC), &n, &fsf);
    ret = rv_from_fs_status(fss);
    if ((ret == 0) && (flags & O_NOFOLLOW) && is_symlink(n) && !(flags & O_PATH)) {
        filesystem_put_node(rootfs, n);
        ret = -ELOOP;
    }

    if (ret)
        return ret;

    u64 length = 0;
    int type = file_type_from_tuple(n);
    if (type == FDESC_TYPE_REGULAR) {
        assert(fsf);
        length = fsfile_get_length(fsf);
    }
    file f = allocate(h, sizeof(struct file));
    if (f == INVALID_ADDRESS) {
        fprintf(stderr, "failed to allocate file\n");
        ret = -ENOMEM;
        goto out;
    }
    int fd = allocate_fd(f);
    if (fd == INVALID_PHYSICAL) {
        fprintf(stderr, "failed to allocate fd");
        ret = -ENOMEM;
        goto out;
    }
    init_fdesc(h, &f->f, type);
    f->f.flags = flags;
    f->f.read = closure(h, file_read, f, fsf);
    f->f.write = closure(h, file_write, f, fsf);
    f->f.close = closure(h, file_close, f, fsf);
    f->fs = rootfs;
    if (type == FDESC_TYPE_REGULAR) {
        f->fsf = fsf;
        f->fs_read = fsfile_get_reader(fsf);
        assert(f->fs_read);
        f->fs_write = fsfile_get_writer(fsf);
        assert(f->fs_write);
    }
    f->n = rootfs->get_inode(rootfs, n);
    f->length = length;
    f->offset = (flags & O_APPEND) ? length : 0;
out:
    filesystem_put_node(rootfs, n);
    if (ret) {
        if (fsf)
            fsfile_release(fsf);
        return ret;
    }
    return fd;
}

static int tfs_open(const char *name, struct fuse_file_info *fi)
{
    pthread_rwlock_wrlock(&rwlock);
    int fd = open_internal(name, fi->flags, 0);
    pthread_rwlock_unlock(&rwlock);
    if (fd < 0)
        return fd;
    fi->fh = fd;
    return 0;
}

static int tfs_create(const char *name, mode_t mode, struct fuse_file_info *fi)
{
    tfs_fuse_debug("%s: path %s\n", __func__, name);
    pthread_rwlock_wrlock(&rwlock);
    int fd = open_internal(name, O_CREAT|O_WRONLY|O_TRUNC, mode);
    pthread_rwlock_unlock(&rwlock);
    if (fd < 0)
        return fd;
    fi->fh = fd;
    set_flush_timeout();
    return 0;
}

static int tfs_opendir(const char *name, struct fuse_file_info *fi)
{
    pthread_rwlock_wrlock(&rwlock);
    int fd = open_internal(name, fi->flags, 0);
    pthread_rwlock_unlock(&rwlock);
    if (fd < 0)
        return fd;
    fi->fh = fd;
    return 0;
}

static int release_internal(const char *name, struct fuse_file_info *fi)
{
    pthread_rwlock_wrlock(&rwlock);
    int fd = fi->fh;
    fdesc f = resolve_fd(fd);
    deallocate_fd(fd);

    if (fetch_and_add(&f->refcnt, -1) == 1) {
        if (f->close)
            apply(f->close);
    }
    pthread_rwlock_unlock(&rwlock);
    return 0;
}

static int tfs_release(const char *name, struct fuse_file_info *fi)
{
    return release_internal(name, fi);
}

static int tfs_releasedir(const char *name, struct fuse_file_info *fi)
{
    return release_internal(name, fi);
}

static int tfs_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    tfs_fuse_debug("%s: path %s\n", __func__, path);
    int rv;
    pthread_rwlock_wrlock(&rwlock);
    int fd = fi->fh;
    fdesc f = resolve_fd(fd);
    if (!f->read) {
        rv = -EINVAL;
        goto out;
    }

    /* use (and update) file offset */
    rv = apply(f->read, buf, size, off);
out:
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

static int tfs_write(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    tfs_fuse_debug("%s: path %s\n", __func__, path);
    pthread_rwlock_wrlock(&rwlock);
    int fd = fi->fh;
    fdesc f = resolve_fd(fd);
    int rv;
    tfs_fuse_debug("  fd %d fdesc %p\n", fd, f);
    if (!f->write){
        rv = -EINVAL;
        goto out;
    }

    /* use (and update) file offset */
    rv = apply(f->write, (void *)buf, size, off);
    set_flush_timeout();
out:
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

closure_function(3, 2, boolean, tfs_readdir_each,
                 void *, buf, file, f, fuse_fill_dir_t, filler,
                 value, k, value, v)
{
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    char *p = cstring(symbol_string(k), tmpbuf);
    tuple n;
    resolve_cstring(&rootfs, file_get_meta(bound(f)), p, &n, 0);
    struct stat s;
    fill_stat(file_type_from_tuple(n), n, &s);
    if (bound(filler)(bound(buf), p, &s, 0))
        return false;
    return true;
}

static int tfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi)
{
    tfs_fuse_debug("%s: path %s\n", __func__, path);
    int rv = 0;
    pthread_rwlock_rdlock(&rwlock);
    file f = resolve_fd(fi->fh);
    tuple md = file_get_meta(f);
    tuple c = md ? children(md) : 0;
    if (c) {
        iterate(c, stack_closure(tfs_readdir_each, buf, f, filler));
    } else {
        rv = -ENOTDIR;
    }
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

static int tfs_readlink(const char *path, char *buf, size_t bufsiz)
{
    tfs_fuse_debug("%s: path %s\n", __func__, path);
    pthread_rwlock_rdlock(&rwlock);
    tuple n;
    int ret = resolve_cstring(&rootfs, cwd, path, &n, 0);
    if (ret)
        goto out;
    if (!is_symlink(n)) {
        ret = -EINVAL;
        goto out;
    }
    buffer target = linktarget(n);
    bytes len = buffer_length(target);
    if (bufsiz < len - 1)
        len = bufsiz - 1;
    runtime_memcpy(buf, buffer_ref(target, 0), len);
    buf[len] = 0;
    ret = 0;
out:
    pthread_rwlock_unlock(&rwlock);
    return ret;
}

static void tfs_destroy(void *v)
{
    alarm(0);
    pthread_rwlock_wrlock(&rwlock);
    filesystem_flush(rootfs, ignore_status);
    pthread_rwlock_unlock(&rwlock);
    close(dfd);
}

static int tfs_mkdir(const char *pathname, mode_t mode)
{
    tfs_fuse_debug("%s: path %s\n", __func__, pathname);
    int rv;
    pthread_rwlock_wrlock(&rwlock);
    rv = rv_from_fs_status(filesystem_mkdir(rootfs, cwd_inode, pathname));
    if (rv == 0)
        set_flush_timeout();
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

static int tfs_rename(const char *oldpath, const char *newpath)
{
    tfs_fuse_debug("%s: oldpath %s newpath %s\n", __func__, oldpath, newpath);
    pthread_rwlock_wrlock(&rwlock);
    int rv = rv_from_fs_status(filesystem_rename(rootfs, cwd_inode, oldpath, rootfs,
        cwd_inode, newpath, false));
    if (rv == 0)
        set_flush_timeout();
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

static int tfs_rmdir(const char *pathname)
{
    tfs_fuse_debug("%s: path %s\n", __func__, pathname);
    int rv;
    pthread_rwlock_wrlock(&rwlock);
    rv = rv_from_fs_status(filesystem_delete(rootfs, cwd_inode, pathname, true));
    if (rv == 0)
        set_flush_timeout();
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

static int tfs_unlink(const char *pathname)
{
    tfs_fuse_debug("%s: unlink %s\n", __func__, pathname);
    pthread_rwlock_wrlock(&rwlock);
    int rv = rv_from_fs_status(filesystem_delete(rootfs, cwd_inode, pathname, false));
    if (rv == 0)
        set_flush_timeout();
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

static int truncate_internal(const char *path, off_t length)
{
    tuple t;
    filesystem fs = rootfs;
    int ret = resolve_cstring_follow(&rootfs, cwd, path, &t, 0);
    if (ret) {
        return ret;
    }
    if (is_dir(t)) {
        return -EISDIR;
    }
    if (length < 0) {
        return -EINVAL;
    }
    fsfile fsf = fsfile_from_node(fs, t);
    if (!fsf) {
        return -ENOENT;
    }
    if (length == fsfile_get_length(fsf))
        return 0;
    fs_status s = filesystem_truncate(fs, fsf, length);
    if (s == FS_STATUS_OK) {
        set_flush_timeout();
    }
    return rv_from_fs_status(s);
}

static int tfs_truncate(const char *path, off_t length)
{
    tfs_fuse_debug("%s: path %s length %ld\n", __func__, path, length);
    pthread_rwlock_wrlock(&rwlock);
    int rv = truncate_internal(path, length);
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

/* The target provided to symlink is provided as-is, and not
 * made relative to the mount point of the fs as paths in other
 * callbacks are. This normally makes sense since the target could be
 * anywhere, but not for tfs where a volume is normally used in a vm.
 * The best implementation of this callback should involve sanitizing
 * and transforming the target path into a relative path between files
 * on the same volume or perhaps an absolute path from the root
 * of the volume (not the host root). Not using the callback seems
 * like the best choice to avoid mis-use or errors in symlinking. */
#if 0
static int tfs_symlink(const char *target, const char *path)
{
    tfs_fuse_debug("%s: path %s target %s\n", __func__, path, target);
    filesystem fs = rootfs;
    tuple parent;
    pthread_rwlock_wrlock(&rwlock);
    int rv = resolve_cstring(&fs, cwd, path, 0, &parent);
    if ((rv != -ENOENT) || !parent) {
        tfs_fuse_debug("symlink ret %d parent %p\n", ret, parent);
        goto out;
    }
    if (filesystem_symlink(fs, parent, filename_from_path(path),
        target)) {
        rv = 0;
        set_flush_timeout();
    } else
        rv = -ENOSPC;
out:
    pthread_rwlock_unlock(&rwlock);
    return rv;
}
#endif

static int statfs_internal(filesystem fs, tuple t, struct statvfs *buf)
{
    if (!buf) {
        return -EFAULT;
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
    buf->f_fsid = id;
    buf->f_namemax = NAME_MAX;
    return 0;
}

static int tfs_statfs(const char *path, struct statvfs *buf)
{
    filesystem fs = rootfs;
    tuple t;
    pthread_rwlock_wrlock(&rwlock);
    int rv = resolve_cstring(&fs, cwd, path, &t, 0);
    if (rv)
        goto out;
    rv = statfs_internal(fs, t, buf);
out:
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

static int utime_internal(const char *filename, timestamp actime,
        timestamp modtime)
{
    tuple t;
    filesystem fs = rootfs;
    int ret = resolve_cstring(&fs, cwd, filename, &t, 0);
    if (ret) {
        return ret;
    }
    filesystem_set_atime(fs, t, actime);
    filesystem_set_mtime(fs, t, modtime);
    return 0;
}

static inline timestamp time_from_timespec(const struct timespec *t)
{
    return seconds(t->tv_sec) + nanoseconds(t->tv_nsec);
}

static int tfs_utimens(const char *filename, const struct timespec tv[2])
{
    timestamp atime =
        tv ? time_from_timespec(&tv[0]) : now(CLOCK_ID_REALTIME);
    timestamp mtime =
        tv ? time_from_timespec(&tv[1]) : now(CLOCK_ID_REALTIME);
    pthread_rwlock_wrlock(&rwlock);
    int rv = utime_internal(filename, atime, mtime);
    pthread_rwlock_unlock(&rwlock);
    return rv;
}

static struct fuse_operations tfs_op = {
    .getattr        = tfs_getattr,
    .open           = tfs_open,
    .opendir        = tfs_opendir,
    .release        = tfs_release,
    .releasedir     = tfs_releasedir,
    .read           = tfs_read,
    .readdir        = tfs_readdir,
    .readlink       = tfs_readlink,
    .write          = tfs_write,
    .create         = tfs_create,
    .destroy        = tfs_destroy,
    .mkdir          = tfs_mkdir,
    .rename         = tfs_rename,
    .rmdir          = tfs_rmdir,
    .unlink         = tfs_unlink,
    .truncate       = tfs_truncate,
    .statfs         = tfs_statfs,
    .utimens        = tfs_utimens,
};

closure_function(0, 2, void, fsc,
                 filesystem, fs, status, s)
{
    if (!is_ok(s)) {
        rprintf("failed to initialize filesystem: %v\n", s);
        exit(EXIT_FAILURE);
    }

    printf("Filesystem load complete, mounting...\n");
    rootfs = fs;
    cwd = filesystem_getroot(rootfs);

    closure_finish();
}

filesystem get_root_fs(void)
{
    return rootfs;
}

void sig_handler(int signum)
{
    tfs_fuse_debug("flush triggered after timeout\n");
    pthread_rwlock_wrlock(&rwlock);
    filesystem_flush(rootfs, ignore_status);
    pthread_rwlock_unlock(&rwlock);
}

void usage(const char *prog)
{
    const char *p = strrchr(prog, '/');
    p = p != NULL ? p + 1 : prog;
    fprintf(stderr, "Usage: %s [OPTION]... <mount point> <fs image>\n", p);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -s\t\t\tSingle threaded\n");
    fprintf(stderr, "  -f\t\t\tStay in foreground\n");
    fprintf(stderr, "  -d\t\t\tFuse debug messages\n");
    fprintf(stderr, "  -b\t\t\tMount boot partition\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int partition = PARTITION_ROOTFS;
    if (argc < 3)
        usage(argv[0]);
    /* if -b is passed, remove it from the args for fuse */
    for (int i = 1; i < argc - 2; i++) {
        if (strcmp(argv[i], "-b") != 0)
            continue;
        partition = PARTITION_BOOTFS;
        memmove(&argv[i], &argv[i+1], (argc - i+1) * sizeof(char *));
        argc--;
    }
    int fd = open(argv[argc - 1], O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "couldn't open fs image file %s: %s\n", argv[argc - 1],
            strerror(errno));
        exit(EXIT_FAILURE);
    }
    dfd = fd;
    --argc;
    h = init_process_runtime();
    init_pagecache(h, h, PAGESIZE);
    u64 length;
    u64 offset = get_fs_offset(fd, partition, false, &length);
    create_filesystem(h,
                      SECTOR_SIZE,
                      length,
                      closure(h, req_handle, fd, offset),
                      0, 0,
                      closure(h, fsc));
    fdallocator = create_id_heap(h, h, 0, infinity, 1, false);
    files = allocate_vector(h, 64);
    fs_set_path_helper(get_root_fs, 0);
    signal(SIGALRM, sig_handler);
    printf("WARNING: Do not externally modify disk image file while mounted!\n");
    return fuse_main(argc, argv, &tfs_op, NULL);
}
