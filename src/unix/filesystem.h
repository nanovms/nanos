#define resolve_dir(__fs, __dirfd, __path) ({ \
    inode cwd; \
    process p = current->p; \
    if (*(__path) == '/') { \
        __fs = p->root_fs;              \
        filesystem_reserve(__fs);       \
        cwd = inode_from_tuple(filesystem_getroot(__fs));   \
    } else if (__dirfd == AT_FDCWD) { \
        process_get_cwd(p, &__fs, &cwd);    \
    } else { \
        file f = resolve_fd(p, __dirfd);    \
        __fs = f->fs;               \
        filesystem_reserve(__fs);   \
        cwd = f->n;                 \
        fdesc_put(&f->f);           \
    } \
    cwd; \
})

sysreturn sysreturn_from_fs_status(fs_status s);
sysreturn sysreturn_from_fs_status_value(status s);

/* Perform read-ahead following a userspace read request.
 * offset and len arguments refer to the byte range being read from userspace,
 * not to the range to be read ahead. */
void file_readahead(file f, u64 offset, u64 len);

fs_status filesystem_chdir(process p, const char *path);

void filesystem_update_relatime(filesystem fs, tuple md);

sysreturn symlink(const char *target, const char *linkpath);
sysreturn symlinkat(const char *target, int dirfd, const char *linkpath);

sysreturn utime(const char *filename, const struct utimbuf *times);
sysreturn utimes(const char *filename, const struct timeval times[2]);

sysreturn statfs(const char *path, struct statfs *buf);
sysreturn fstatfs(int fd, struct statfs *buf);

sysreturn fallocate(int fd, int mode, long offset, long len);

sysreturn fadvise64(int fd, s64 off, u64 len, int advice);

sysreturn fs_rename(buffer oldpath, buffer newpath);

void file_release(file f);

fsfile fsfile_open_or_create(buffer file_path, boolean truncate);
fs_status fsfile_truncate(fsfile f, u64 len);

notify_entry fs_watch(heap h, tuple n, u64 eventmask, event_handler eh, notify_set *s);
void fs_notify_event(tuple n, u64 event);
