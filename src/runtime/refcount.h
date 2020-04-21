/* a lightweight, inline version of merge without status handling */
typedef struct refcount {
    word c;
    thunk completion;
} *refcount;

static inline void init_refcount(refcount r, int c, thunk completion)
{
    r->c = c;
    r->completion = completion;
}

static inline void refcount_reserve(refcount r)
{
    fetch_and_add(&r->c, 1);
}

static inline boolean refcount_release(refcount r)
{
    word n = fetch_and_add(&r->c, (word)-1);
    if (n < 1)
        halt("%s: invalid count %ld\n", __func__, n);
    if (n == 1) {
        if (r->completion)
            apply(r->completion);
        return true;
    }
    return false;
}
