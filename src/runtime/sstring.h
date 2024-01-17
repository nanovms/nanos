/* Simple string structure that does not use NULL string terminators. */
typedef struct sstring {
    bytes len;
    char *ptr;
} sstring;

#define ss(x)  ({               \
    assert_string_literal(x);   \
    sstring s = {               \
        .len = sizeof(x) - 1,   \
        .ptr = x,               \
    };                          \
    s;                          \
})

/* Should only be used for initialization of static variables.
 * For all other uses, ss() is more efficient. */
#define ss_static_init(x)   {   \
    .len = sizeof(x) - 1,       \
    .ptr = string_literal(x),   \
}

#define sstring_foreach(__i, __c, __s)              \
    for (bytes __i = 0, __c, __limit = (__s).len;     \
         (__c = (__s).ptr[__i]), (__i) < __limit;   \
         (__i)++)

#define file_ss isstring((char *)__FILE__, sizeof(__FILE__) - 1)
#define func_ss isstring((char *)__func__, sizeof(__func__) - 1)

static inline sstring isstring(char *ptr, bytes len)
{
    sstring s = {
        .len = len,
        .ptr = ptr,
    };
    return s;
}

static inline sstring sstring_null(void)
{
    sstring s = {
        .ptr = 0,
    };
    return s;
}

static inline sstring sstring_empty(void)
{
    sstring s = {
        .len = 0,
        .ptr = "",
    };
    return s;
}

static inline sstring sstring_from_cstring(const char *cstring, bytes maxlen)
{
    sstring s = {
        .ptr = (char *)cstring,
    };
    bytes len;
    for (len = 0; len < maxlen; len++)
        if (cstring[len] == '\0')
            break;
    s.len = len;
    return s;
}

static inline boolean sstring_is_null(sstring s)
{
    return (s.ptr == 0);
}

static inline boolean sstring_is_empty(sstring s)
{
    return (s.len == 0);
}
