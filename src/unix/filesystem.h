#define resolve_dir(__dirfd, __path) ({ \
    tuple cwd; \
    if (*(__path) == '/') cwd = filesystem_getroot(current->p->fs); \
    else if (__dirfd == AT_FDCWD) cwd = current->p->cwd; \
    else { \
        file f = resolve_fd(current->p, __dirfd); \
        tuple t = file_get_meta(f); \
        if (!is_dir(t)) return set_syscall_error(current, ENOTDIR); \
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

sysreturn sysreturn_from_fs_status_value(status s);

int resolve_cstring(tuple cwd, const char *f, tuple *entry, tuple *parent);

/* Same as resolve_cstring(), except that if the entry is a symbolic link this
 * function follows the link (recursively). */
int resolve_cstring_follow(tuple cwd, const char *f, tuple *entry,
        tuple *parent);

int filesystem_follow_links(tuple link, tuple parent, tuple *target);

int filesystem_add_tuple(const char *path, tuple t);

static inline int filesystem_get_tuple(const char *path, tuple *t)
{
    return resolve_cstring(current->p->cwd, path, t, 0);
}

sysreturn symlink(const char *target, const char *linkpath);
sysreturn symlinkat(const char *target, int dirfd, const char *linkpath);

sysreturn utime(const char *filename, const struct utimbuf *times);
sysreturn utimes(const char *filename, const struct timeval times[2]);

sysreturn statfs(const char *path, struct statfs *buf);
sysreturn fstatfs(int fd, struct statfs *buf);

sysreturn fallocate(int fd, int mode, long offset, long len);
