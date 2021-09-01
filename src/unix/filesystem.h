#define resolve_dir(__fs, __dirfd, __path) ({ \
    tuple cwd; \
    process p = current->p; \
    if (*(__path) == '/') { \
        __fs = p->root_fs;              \
        cwd = filesystem_getroot(__fs); \
    } else if (__dirfd == AT_FDCWD) { \
        process_lock(p);              \
        __fs = p->cwd_fs;             \
        cwd = p->cwd;                 \
        process_unlock(p);            \
    } else { \
        file f = resolve_fd(p, __dirfd);    \
        __fs = f->fs;               \
        tuple t = file_get_meta(f); \
        fdesc_put(&f->f);           \
        if (!t || !is_dir(t)) return set_syscall_error(current, ENOTDIR); \
        cwd = t; \
    } \
    cwd; \
})

sysreturn sysreturn_from_fs_status(fs_status s);
sysreturn sysreturn_from_fs_status_value(status s);

int resolve_cstring(filesystem *fs, tuple cwd, const char *f, tuple *entry,
                    tuple *parent);

/* Same as resolve_cstring(), except that if the entry is a symbolic link this
 * function follows the link (recursively). */
int resolve_cstring_follow(filesystem *fs, tuple cwd, const char *f, tuple *entry,
        tuple *parent);

int filesystem_follow_links(filesystem *fs, tuple link, tuple parent,
                            tuple *target);

/* Perform read-ahead following a userspace read request.
 * offset and len arguments refer to the byte range being read from userspace,
 * not to the range to be read ahead. */
void file_readahead(file f, u64 offset, u64 len);

fs_status filesystem_chdir(process p, const char *path);

sysreturn symlink(const char *target, const char *linkpath);
sysreturn symlinkat(const char *target, int dirfd, const char *linkpath);

sysreturn utime(const char *filename, const struct utimbuf *times);
sysreturn utimes(const char *filename, const struct timeval times[2]);

sysreturn statfs(const char *path, struct statfs *buf);
sysreturn fstatfs(int fd, struct statfs *buf);

sysreturn fallocate(int fd, int mode, long offset, long len);

sysreturn fadvise64(int fd, s64 off, u64 len, int advice);

void file_release(file f);

fsfile fsfile_open_or_create(buffer file_path);
