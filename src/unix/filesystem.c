#include <unix_internal.h>
#include <filesystem.h>

// fused buffer wrap, split, and resolve
int resolve_cstring(tuple cwd, const char *f, tuple *entry, tuple *parent)
{
    if (!f)
        return -EFAULT;

    tuple t = *f == '/' ? filesystem_getroot(current->p->fs) : cwd;
    tuple p = t;
    buffer a = little_stack_buffer(NAME_MAX);
    char y;
    int nbytes;

    while ((y = *f)) {
        if (y == '/') {
            if (buffer_length(a)) {
                p = t;
                t = lookup(t, intern(a));
                if (!t)
                    goto done;
                if (!children(t))
                    return -ENOTDIR;
                buffer_clear(a);
            }
            f++;
        } else {
            nbytes = push_utf8_character(a, f);
            if (!nbytes) {
                thread_log(current, "Invalid UTF-8 sequence.\n");
                p = false;
                goto done;
            }
            f += nbytes;
        }
    }

    if (buffer_length(a)) {
        p = t;
        t = lookup(t, intern(a));
    }
done:
    if (!t && (*f == '/') && (*(f + 1)))
        /* The path being resolved contains entries under a non-existent
         * directory. */
        p = false;
    if (parent)
        *parent = p;
    if (entry)
        *entry = t;
    return (t ? 0 : -ENOENT);
}
