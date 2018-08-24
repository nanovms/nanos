static vector node_vector(heap h, tuple n)
{
    vector r = allocate_vector(h, 100); //table_elements(n));
    void *x;
    
    for (int i = 0; (x = table_find(n, intern_u64(i)));  i++) 
        vector_push(r, x);
    
    return r;
}

static inline tuple resolve_path(tuple n, vector v)
{
    buffer i;
    // xx destructive, relative
    vector_pop(v);
    vector_foreach(v, i) {
        tuple c = table_find(n, sym(children));
        n = table_find(c, intern(i));
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


// fused buffer wrap, split, and resolve
static inline tuple resolve_cstring(tuple root, char *f)
{
    buffer a = little_stack_buffer(50);
    char *x = f;
    tuple t = root;
    char y;

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
    if (buffer_length(a)) t = lookup(t, intern(a));
    return t;
}

