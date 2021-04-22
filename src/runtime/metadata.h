#include <stringtok.h>

static inline vector vector_from_tuple(heap h, tuple n)
{
    if (!n)
        return 0;

    vector r = allocate_vector(h, 100); //table_elements(n));
    if (r == INVALID_ADDRESS)
        return r;

    void *x;
    for (int i = 0; (x = get(n, intern_u64(i))); i++)
        vector_push(r, x);
    
    return r;
}

// destructive
static inline tuple tuple_from_vector(vector v)
{
    void *p;
    int i = 0;
    tuple t = allocate_tuple();
    if (t == INVALID_ADDRESS)
        return t;

    // reversal?
    while ((p = vector_pop(v))) 
        set(t, intern_u64(i++), p);

    return t;
}

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
    tuple c = children(t);
    if (!c)
        return c;
    return get_tuple(c, a);
}
