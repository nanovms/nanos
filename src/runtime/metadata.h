static inline tuple resolve_path(tuple n, vector v)
{
    buffer i;
    vector_foreach(v, i) {
        /* null entries ("//") are skipped in path */
        if (buffer_length(i) == 0)
            continue;
        tuple c = get_tuple(n, sym(children));
        if (!c)
            return c;
        n = get_tuple(c, intern(i));
        if (!n)
            return n;
    }
    return n;
}

static inline tuple children(tuple x)
{
    return get_tuple(x, sym(children));
}

static inline string contents(tuple x)
{
    return get_string(x, sym(contents));
}

static inline tuple lookup(tuple t, symbol a)
{
    if (a == sym_this(".."))
        return get_tuple(t, a);
    if (a == sym_this("."))
        return t;
    tuple c = children(t);
    if (!c)
        return c;
    return get_tuple(c, a);
}
