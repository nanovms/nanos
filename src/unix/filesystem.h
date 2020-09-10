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

static inline boolean is_socket(tuple n)
{
    return table_find(n, sym(socket)) ? true : false;
}

static inline symbol lookup_sym(tuple parent, tuple t)
{
    void *c = children(parent);
    if (!c) return false;
    table_foreach(c, k, v) {
        if (v == t)
            return k;
    }
    return false;
}

static inline char *path_find_last_delim(const char *path, unsigned int len)
{
    return (char *)utf8_findn_r((u8 *)path, len, '/');
}

static inline const char *filename_from_path(const char *path)
{
    const char *filename = path_find_last_delim(path, PATH_MAX);
    if (!filename) {
        filename = path;
    } else {
        filename++;
    }
    return filename;
}

/* Expects an empty buffer, and never resizes the buffer. */
static inline boolean dirname_from_path(buffer dest, const char *path)
{
    int pathlen = runtime_strlen(path);
    const char *last_delim = path_find_last_delim(path, PATH_MAX);
    const char *dirname;
    int len;
    if (!last_delim) {
        dirname = path;
        len = pathlen;
    } else if (last_delim < path + pathlen - 1) {
        dirname = last_delim + 1;
        len = pathlen - (dirname - path);
    } else {    /* The path ends with '/'. */
        const char *delim = path_find_last_delim(path, last_delim - path);
        if (!delim) {
            dirname = path;
            len = pathlen - 1;
        } else {
            dirname = delim + 1;
            len = last_delim - dirname;
        }
    }
    if (len >= dest->length)
        return false;
    buffer_write(dest, dirname, len);
    push_u8(dest, '\0');
    return true;
}

sysreturn sysreturn_from_fs_status(fs_status s);
sysreturn sysreturn_from_fs_status_value(status s);

tuple lookup_follow_mounts(filesystem *fs, tuple t, symbol a, tuple *p);

int resolve_cstring(filesystem *fs, tuple cwd, const char *f, tuple *entry,
                    tuple *parent);

/* Same as resolve_cstring(), except that if the entry is a symbolic link this
 * function follows the link (recursively). */
int resolve_cstring_follow(filesystem *fs, tuple cwd, const char *f, tuple *entry,
        tuple *parent);

int filesystem_follow_links(filesystem *fs, tuple link, tuple parent,
                            tuple *target);

int filesystem_add_tuple(const char *path, tuple t);

static inline int filesystem_get_tuple(const char *path, tuple *t)
{
    return resolve_cstring(0, current->p->cwd, path, t, 0);
}

/* Perform read-ahead following a userspace read request.
 * offset and len arguments refer to the byte range being read from userspace,
 * not to the range to be read ahead. */
void file_readahead(file f, u64 offset, u64 len);

sysreturn symlink(const char *target, const char *linkpath);
sysreturn symlinkat(const char *target, int dirfd, const char *linkpath);

sysreturn utime(const char *filename, const struct utimbuf *times);
sysreturn utimes(const char *filename, const struct timeval times[2]);

sysreturn statfs(const char *path, struct statfs *buf);
sysreturn fstatfs(int fd, struct statfs *buf);

sysreturn fallocate(int fd, int mode, long offset, long len);

sysreturn fadvise64(int fd, s64 off, u64 len, int advice);
