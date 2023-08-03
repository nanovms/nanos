#define STATUS_OK ((tuple)0)

typedef tuple status;
typedef closure_type(status_handler, void, status);

extern tuple timm_oom;

static inline void timm_term(tuple t, char *n, vlist *a)
{
    symbol k = intern(alloca_wrap_buffer(n, runtime_strlen(n)));
    char *f = varg(*a, char *);
    string s = allocate_string(100);
    vbprintf(s, alloca_wrap_buffer(f, runtime_strlen(f)), a);
    set(t, k, s);
}

// if the format strings and subsequent arguments dont line up, this whole thing goes sideways
static inline tuple timm_internal(tuple t, char *first, ...)
{
    vlist e;
    vstart(e, first);
    if (t == STATUS_OK)
        t = allocate_tuple();
    if (t == INVALID_ADDRESS)
        return timm_oom;

    // deal with the mandatory first argument
    if (first != INVALID_ADDRESS) {
        char *n; 
        timm_term(t, first, &e);
        while((n = varg(e, char *)) != INVALID_ADDRESS)  
            timm_term(t, n, &e);
    }
    return t;
}

tuple timm_clone(tuple t);

void timm_dealloc(tuple t);

// fix for zero argument case
#define timm(first, ...)  timm_internal(STATUS_OK, first, __VA_ARGS__, INVALID_ADDRESS)
#define timm_append(s, first, ...)  timm_internal(s, first, __VA_ARGS__, INVALID_ADDRESS)

// build up status chain
#define timm_up(sd, first, ...)                     \
    ({                                              \
        tuple __up = timm(first, __VA_ARGS__);      \
        set(__up, sym(down), sd);                   \
        __up;                                       \
    })

static inline boolean is_ok(status s)
{
    return (s == STATUS_OK);
}
