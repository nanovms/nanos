#define resolve_dir(__fs, __dirfd, __path, __path_ss) ({ \
    if (!fault_in_user_string(__path, &(__path_ss))) return -EFAULT;    \
    inode cwd; \
    process p = current->p; \
    if (*(__path) == '/') { \
        __fs = p->root_fs;              \
        filesystem_reserve(__fs);       \
        cwd = (__fs)->get_inode(__fs, filesystem_getroot(__fs));    \
    } else if (__dirfd == AT_FDCWD) { \
        process_get_cwd(p, &__fs, &cwd);    \
    } else { \
        file f = resolve_fd(p, __dirfd);    \
        if (f->f.type != FDESC_TYPE_DIRECTORY) {    \
            fdesc_put(&f->f);                       \
            return -ENOTDIR;                        \
        }                                           \
        __fs = f->fs;               \
        filesystem_reserve(__fs);   \
        cwd = f->n;                 \
        fdesc_put(&f->f);           \
    } \
    cwd; \
})

sysreturn sysreturn_from_fs_status_value(status s);

u16 stat_mode(process p, int type, tuple meta);

/* Perform read-ahead following a userspace read request.
 * offset and len arguments refer to the byte range being read from userspace,
 * not to the range to be read ahead. */
void file_readahead(file f, u64 offset, u64 len);

sysreturn file_io_init_sg(file f, u64 offset, struct iovec *iov, int count, sg_list *sgp);

int filesystem_chdir(process p, sstring path);

void filesystem_update_relatime(filesystem fs, tuple md);

sysreturn openat(int dirfd, const char *name, int flags, int mode);

sysreturn link(const char *oldpath, const char *newpath);
sysreturn linkat(int olddirfd, const char *oldpath,
                 int newdirfd, const char *newpath, int flags);
sysreturn symlink(const char *target, const char *linkpath);
sysreturn symlinkat(const char *target, int dirfd, const char *linkpath);

sysreturn utime(const char *filename, const struct utimbuf *times);
sysreturn utimes(const char *filename, const struct timeval times[2]);
sysreturn utimensat(int dirfd, const char *filename, const struct timespec times[2], int flags);

sysreturn statx(int dirfd, const char *pathname, int flags, unsigned int mask,
                struct statx *statxbuf);

sysreturn statfs(const char *path, struct statfs *buf);
sysreturn fstatfs(int fd, struct statfs *buf);

sysreturn setxattr(const char *path, const char *name, const void *value, u64 size, int flags);
sysreturn lsetxattr(const char *path, const char *name, const void *value, u64 size, int flags);
sysreturn fsetxattr(int fd, const char *name, const void *value, u64 size, int flags);
sysreturn getxattr(const char *path, const char *name, void *value, u64 size);
sysreturn lgetxattr(const char *path, const char *name, void *value, u64 size);
sysreturn fgetxattr(int fd, const char *name, void *value, u64 size);

sysreturn fallocate(int fd, int mode, long offset, long len);

sysreturn fadvise64(int fd, s64 off, u64 len, int advice);

sysreturn fs_rename(sstring oldpath, sstring newpath);

int file_open(filesystem fs, tuple n, tuple parent, int flags, fsfile fsf);
void file_release(file f);
int file_type_from_tuple(tuple n);

fsfile fsfile_open(sstring file_path);
fsfile fsfile_open_or_create(sstring file_path, boolean truncate);
int fsfile_truncate(fsfile f, u64 len);

sysreturn fsfile_add_seals(fsfile f, u64 seals);
sysreturn fsfile_get_seals(fsfile f, u64 *seals);

notify_entry fs_watch(heap h, tuple n, u64 eventmask, event_handler eh, notify_set *s);
void fs_notify_event(tuple n, tuple parent, u64 event);
