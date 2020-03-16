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
