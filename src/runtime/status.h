#define STATUS_OK ((tuple)0)

typedef tuple status;
closure_type(status_handler, void, status s);

extern tuple timm_oom;

static inline void timm_term(tuple t, sstring n, sstring f, ...)
{
    vlist a;
    vstart(a, f);
    symbol k = sym_sstring(n);
    string s = allocate_string(100);
    vbprintf(s, f, &a);
    vend(a);
    set(t, k, s);
}

tuple timm_clone(tuple t);

void timm_dealloc(tuple t);

#define timm(n, f, ...) ({                          \
    tuple s = allocate_tuple();                     \
    if (s != INVALID_ADDRESS)                       \
        timm_term(s, ss(n), ss(f), ## __VA_ARGS__); \
    else                                            \
        s = timm_oom;                               \
    s;                                              \
})

#define timm_sstring(n, f, ...) ({          \
    tuple s = allocate_tuple();             \
    if (s != INVALID_ADDRESS)               \
        timm_term(s, n, f, ## __VA_ARGS__); \
    else                                    \
        s = timm_oom;                       \
    s;                                      \
})

#define timm_append(s, n, f, ...)   ({              \
    if (s != timm_oom)                              \
        timm_term(s, ss(n), ss(f), ## __VA_ARGS__); \
    s;                                              \
})

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
