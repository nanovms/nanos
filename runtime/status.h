
typedef tuple status;
typedef closure_type(status_handler, void, status);

// initialize..transient?
extern heap errheap;

static inline void timm_term(table t, char *n, vlist a)
{
    symbol k = intern(alloca_wrap_buffer(n, runtime_strlen(n)));
    char *f = varg(a, char *);
    buffer b = allocate_buffer(errheap, 100);
    vbprintf(b, alloca_wrap_buffer(f, runtime_strlen(f)), a);
    table_set(t, k, b);
}

// if the format strings and subsequent arguments dont line up, this whole thing goes sideways
static inline tuple timm_internal(char *first, ...)
{
    vlist e;
    vstart(e, first);
    tuple t = allocate_tuple();

    // deal with the mandatory first argument
    if (first != INVALID_ADDRESS) {
        char *n; 
        timm_term(t, first, e);
        while((n = varg(e, char *)) != INVALID_ADDRESS)  
            timm_term(t, n, e);
    }
    return t;
}

// fix for zero argument case
#define timm(...)  timm_internal(__VA_ARGS__, INVALID_ADDRESS)

#define STATUS_OK ((tuple)0)
static inline boolean is_ok(status s)
{
    return (s == STATUS_OK);
}



