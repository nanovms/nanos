
#include <runtime.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <pagecache.h>
#include <tfs.h>
#include <storage.h>
#include <errno.h>
#include <string.h>

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64
#include <fuse.h>

static heap h;
static int osargc;
static char **osargv;

static filesystem rootfs;
static tuple cwd;
static id_heap fdallocator;
vector files;

/* unix internal */
#define NAME_MAX 255

#define FDESC_TYPE_REGULAR      1
#define FDESC_TYPE_DIRECTORY    2
#define FDESC_TYPE_SYMLINK     11

#define resolve_fd_noret(__fd) vector_get(files, __fd)
#define resolve_fd(__fd) ({void *f ; if (!(f = resolve_fd_noret(__fd))) return -EBADF; f;})

typedef closure_type(file_io, int, void *buf, u64 length, u64 offset);

typedef struct fdesc {
    file_io read, write;
    // sg_file_io sg_read, sg_write;
    // closure_type(events, u32, thread);
    // closure_type(ioctl, sysreturn, unsigned long request, vlist ap);
    // closure_type(close, sysreturn, thread t, io_completion completion);

    u64 refcnt;
    int type;
    int flags;                  /* F_GETFD/F_SETFD flags */
    //notify_set ns;
} *fdesc;

typedef struct file {
    struct fdesc f;             /* must be first */
    filesystem fs;
    union {
        struct {
            fsfile fsf;         /* fsfile for regular files */
            sg_io fs_read;
            sg_io fs_write;
            int fadv;           /* posix_fadvise advice */
        };
        tuple meta;             /* meta tuple for others */
    };
    u64 offset;
    u64 length;
} *file;

static inline void init_fdesc(heap h, fdesc f, int type)
{
    f->read = 0;
    f->write = 0;
    // f->sg_read = 0;
    // f->sg_write = 0;
    // f->close = 0;
    // f->events = 0;
    // f->ioctl = 0;
    f->refcnt = 1;
    f->type = type;
    f->flags = 0;
    //f->ns = allocate_notify_set(h);
}

u64 allocate_fd(void *f)
{
    u64 fd = allocate_u64((heap)fdallocator, 1);
    if (fd == INVALID_PHYSICAL) {
        rprintf("fail; maxed out\n");
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

/* filesystem.h stuff */
#define resolve_dir(__fs, __dirfd, __path) ({ \
    tuple cwd; \
    if (*(__path) == '/') { \
        __fs = current->p->root_fs; \
        cwd = filesystem_getroot(__fs); \
    } else if (__dirfd == AT_FDCWD) { \
        __fs = current->p->cwd_fs; \
        cwd = current->p->cwd; \
    } else { \
        file f = resolve_fd(current->p, __dirfd); \
        tuple t = file_get_meta(f); \
        if (!is_dir(t)) return set_syscall_error(current, ENOTDIR); \
        __fs = f->fs; \
        cwd = t; \
    } \
    cwd; \
})

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
    case FS_STATUS_NOTDIR:
        return -ENOTDIR;
    default:
        return 0;
    }
}

int rv_from_fs_status_value(status s)
{
    if (is_ok(s))
        return 0;
    value v = table_find(s, sym(fsstatus));
    u64 fss;
    int rv;

    /* block r/w errors won't include an fs status, so assume I/O error if none found */
    if (v && tagof(v) != tag_tuple && u64_from_value(v, &fss))
        rv = rv_from_fs_status(fss);
    else
        rv = -EIO;
    return rv;
}

static inline buffer linktarget(table x)
{
    return table_find(x, sym(linktarget));
}

static inline boolean is_dir(tuple n)
{
    return children(n) ? true : false;
}

static inline boolean is_symlink(tuple n)
{
    return linktarget(n) ? true : false;
}

static inline tuple file_get_meta(file f)
{
    return f->f.type == FDESC_TYPE_REGULAR ? fsfile_get_meta(f->fsf) : f->meta;
}

tuple lookup_child(tuple t, symbol a, tuple *p);

int resolve_cstring(filesystem *fs, tuple cwd, const char *f, tuple *entry,
                    tuple *parent);

/* Same as resolve_cstring(), except that if the entry is a symbolic link this
 * function follows the link (recursively). */
int resolve_cstring_follow(filesystem *fs, tuple cwd, const char *f, tuple *entry,
        tuple *parent);

int filesystem_follow_links(filesystem *fs, tuple link, tuple parent,
                            tuple *target);

int filesystem_add_tuple(const char *path, tuple t);

/* end */

static int file_type_from_tuple(tuple n)
{
    if (is_dir(n))
        return FDESC_TYPE_DIRECTORY;
    else if (is_symlink(n))
        return FDESC_TYPE_SYMLINK;
    else
        return FDESC_TYPE_REGULAR;
}

closure_function(2, 3, void, bread,
                 descriptor, d, u64, fs_offset,
                 void *, dest, range, blocks, status_handler, c)
{
    ssize_t xfer, total = 0;
    u64 offset = bound(fs_offset) + (blocks.start << SECTOR_OFFSET);
    u64 length = range_span(blocks) << SECTOR_OFFSET;
    while (total < length) {
        xfer = pread(bound(d), dest + total, length - total, offset + total);
        if (xfer < 0 && errno != EINTR) {
            apply(c, timm("read-error", "%s", strerror(errno)));
            return;
        }
        total += xfer;
    }
    apply(c, STATUS_OK);
}

static u64 get_fs_offset(descriptor fd, int part, boolean by_index)
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
    printf("detected filesystem at 0x%llx\n", fs_offset);
    return fs_offset;
}

static void fill_stat(int type, tuple n, struct stat *s)
{
    zero(s, sizeof(struct stat));
    switch (type) {
    case FDESC_TYPE_DIRECTORY:
        s->st_mode = S_IFDIR | 0777;
        break;
    case FDESC_TYPE_SYMLINK:
        s->st_mode = S_IFLNK;
        break;
    case FDESC_TYPE_REGULAR:
        s->st_mode = S_IFREG | 0644;
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
    filesystem fs = rootfs;
    int r = resolve_cstring(&fs, cwd, name, &n, 0);
    if (r)
        return r;
    fill_stat(file_type_from_tuple(n), n, s);
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
        return 0; //io_complete(completion, t, 0);
    }
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        printf( "   unable to allocate sg list");
        return -ENOMEM;
    }
    int rv;
    apply(f->fs_read, sg, irangel(offset, length), closure(h, file_read_complete, sg, dest, length,
                                                           f, is_file_offset, &rv));
    return rv;
}

#ifndef O_PATH
#define O_PATH 0
#endif
static int open_internal(const char *name, struct fuse_file_info *fi)
{
    tuple n;
    tuple parent;
    int ret;
    filesystem fs = rootfs;

    if (fi->flags & O_NOFOLLOW) {
        ret = resolve_cstring(&fs, cwd, name, &n, &parent);
        if (!ret && is_symlink(n) && !(fi->flags & O_PATH)) {
            ret = -ELOOP;
        }
    } else {
        ret = resolve_cstring_follow(&fs, cwd, name, &n, &parent);
    }
    u64 length = 0;
    fsfile fsf = 0;
    int type = file_type_from_tuple(n);
    if (type == FDESC_TYPE_REGULAR) {
        fsf = fsfile_from_node(fs, n);
        assert(fsf);
        length = fsfile_get_length(fsf);
    }
    file f = allocate(h, sizeof(struct file));
    if (f == INVALID_ADDRESS) {
        rprintf("failed to allocate file\n");
        return -ENOMEM;
    }
    int fd = allocate_fd(f);
    if (fd == INVALID_PHYSICAL) {
        rprintf("failed to allocate fd");
        return -ENOMEM;
    }
    init_fdesc(h, &f->f, type);
    f->f.flags = fi->flags;
    f->f.read = closure(h, file_read, f, fsf);
    //f->f.write = closure(h, file_write, f, fsf);
    f->fs = fs;
    if (type == FDESC_TYPE_REGULAR) {
        f->fsf = fsf;
        f->fs_read = fsfile_get_reader(fsf);
        assert(f->fs_read);
        // f->fs_write = fsfile_get_writer(fsf);
        // assert(f->fs_write);
        //f->fadv = POSIX_FADV_NORMAL;
    } else {
        f->meta = n;
    }
    f->length = length;
    f->offset = (fi->flags & O_APPEND) ? length : 0;
    fi->fh = fd;
    if (ret)
        return ret;
    return 0;
}

static int tfs_open(const char *name, struct fuse_file_info *fi)
{
    return open_internal(name, fi);
}

static int tfs_opendir(const char *name, struct fuse_file_info *fi)
{
    return open_internal(name, fi);
}

static int release_internal(const char *name, struct fuse_file_info *fi)
{
    int fd = fi->fh;
    fdesc f = resolve_fd(fd);
    deallocate_fd(fd);

    if (fetch_and_add(&f->refcnt, -1) == 1) {
        // if (f->close)
        //     return apply(f->close, current, syscall_io_complete);
    }
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
    int fd = fi->fh;
    fdesc f = resolve_fd(fd);
    if (!f->read)
        return -EINVAL;

    /* use (and update) file offset */
    return apply(f->read, buf, size, off);
}

static int tfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi)
{
    file f = resolve_fd(fi->fh);
    tuple c = children(file_get_meta(f));
    if (!c)
        return -ENOTDIR;

    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    table_foreach(c, k, v) {
        char *p = cstring(symbol_string(k), tmpbuf);
        tuple n;
        resolve_cstring(0, file_get_meta(f), p, &n, 0);
        struct stat s;
        fill_stat(file_type_from_tuple(n), n, &s);
        if (filler(buf, p, &s, 0))
            break;
    }
    return 0;
}

static struct fuse_operations tfs_op = {
    .getattr        = tfs_getattr,
    .open           = tfs_open,
    .opendir        = tfs_opendir,
    .release        = tfs_release,
    .releasedir     = tfs_releasedir,
    .read           = tfs_read,
    .readdir        = tfs_readdir,
};

closure_function(0, 2, void, fsc,
                 filesystem, fs, status, s)
{
    if (!is_ok(s)) {
        rprintf("failed to initialize filesystem: %v\n", s);
        exit(EXIT_FAILURE);
    }

    printf("filesystem load complete\n");
    rootfs = fs;

    closure_finish();
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return -1;
    int fd = open(argv[argc - 1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "couldn't open file %s: %s\n", argv[argc - 1],
            strerror(errno));
        exit(EXIT_FAILURE);
    }
    osargc = --argc;
    osargv = argv;

    h = init_process_runtime();
    init_pagecache(h, h, 0, PAGESIZE);
    create_filesystem(h,
                      SECTOR_SIZE,
                      infinity,
                      closure(h, bread, fd, get_fs_offset(fd, PARTITION_ROOTFS, false)),
                      0, /* no write */
                      false,
                      closure(h, fsc));
    fdallocator = create_id_heap(h, h, 0, infinity, 1, false);
    files = allocate_vector(h, 64);
    return fuse_main(osargc, osargv, &tfs_op, NULL);
}

/* filesystem.c stuff */
#define SYMLINK_HOPS_MAX    8

/* If the file path being resolved crosses a filesystem boundary (i.e. a mount
 * point), the 'fs' argument (if non-null) is updated to point to the new
 * filesystem. */
// fused buffer wrap, split, and resolve
int resolve_cstring(filesystem *fs, tuple cwd, const char *f, tuple *entry,
                    tuple *parent)
{
    if (!f)
        return -EFAULT;

    tuple t = *f == '/' ? filesystem_getroot(rootfs) : cwd;
    if (fs && (*f == '/'))
        *fs = rootfs;
    tuple p = t;
    buffer a = little_stack_buffer(NAME_MAX);
    char y;
    int nbytes;
    int err;

    while ((y = *f)) {
        if (y == '/') {
            if (buffer_length(a)) {
                t = lookup_child(t, intern(a), &p);
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
                rprintf("Invalid UTF-8 sequence.\n");
                err = -ENOENT;
                p = false;
                goto done;
            }
            f += nbytes;
        }
    }

    if (buffer_length(a)) {
        t = lookup_child(t, intern(a), &p);
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

tuple lookup_child(tuple t, symbol a, tuple *p)
{
    *p = t;
    return lookup(t, a);
}
