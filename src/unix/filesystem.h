#define resolve_dir(__dirfd, __path) ({ \
    tuple cwd; \
    if (*(__path) == '/') cwd = filesystem_getroot(current->p->fs); \
    else if (__dirfd == AT_FDCWD) cwd = current->p->cwd; \
    else { \
        file f = resolve_fd(current->p, __dirfd); \
        if (!is_dir(f->n)) return set_syscall_error(current, ENOTDIR); \
        cwd = f->n; \
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

static inline const char *filename_from_path(const char *path)
{
    const char *filename = (char *) utf8_find_r((u8 *) path, '/');
    if (!filename) {
        filename = path;
    } else {
        filename++;
    }
    return filename;
}

int resolve_cstring(tuple cwd, const char *f, tuple *entry, tuple *parent);

/* Same as resolve_cstring(), except that if the entry is a symbolic link this
 * function follows the link (recursively). */
int resolve_cstring_follow(tuple cwd, const char *f, tuple *entry,
        tuple *parent);

int filesystem_follow_links(tuple link, tuple parent, tuple *target);

sysreturn symlink(const char *target, const char *linkpath);
sysreturn symlinkat(const char *target, int dirfd, const char *linkpath);
