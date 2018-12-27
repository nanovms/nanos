#pragma once

#include <list.h>
#include <stringtok.h>

static inline vector vector_from_tuple(heap h, tuple n)
{
    if (!n)
        return 0;

    vector r = allocate_vector(h, 100); //table_elements(n));
    void *x;
    
    for (int i = 0; (x = table_find(n, intern_u64(i))); i++)
        vector_push(r, x);
    
    return r;
}

// destructive
static inline tuple tuple_from_vector(vector v)
{
    tuple t = allocate_tuple();
    void *p;
    int i = 0;

    // reversal?
    while ((p = vector_pop(v))) 
        table_set(t, intern_u64(i++), p);

    return t;
}

static inline tuple resolve_path(tuple n, vector v)
{
    buffer i;
    vector_foreach(v, i) {
        /* null entries ("//") are skipped in path */
        if (buffer_length(i) == 0)
            continue;
        tuple c = table_find(n, sym(children));
        assert(c);
        n = table_find(c, intern(i));
        assert(n);
    }
    return n;
}

static inline table children(table x)
{
    return table_find(x, sym(children));
}

static inline buffer contents(table x)
{
    return table_find(x, sym(contents));
}

static inline tuple lookup(tuple t, symbol a)
{
    void *c = children(t);
    if (!c) return c;
    return table_find(c, a);
}

extern int strcmp(const char *, const char *);

// fused buffer wrap, split, and resolve
static inline tuple resolve_cstring(tuple root, char *f)
{
    buffer a = little_stack_buffer(50);
    char *x = f;
    tuple t = root;
    char y;

    if (strcmp(f, ".") == 0)
        return root;

    while ((y = *x++)) {
        if (y == '/') {
            if (buffer_length(a)) {
                t = lookup(t, intern(a));
                if (!t) return t;
                buffer_clear(a);
            }                
        } else {
            push_character(a, y);
        }
    }
    
    if (buffer_length(a)) {
        t = lookup(t, intern(a));
        return t;
    }
    return 0;
}

