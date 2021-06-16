enum {
    KLIB_INIT_OK = 0,
    KLIB_LOAD_FAILED,
    KLIB_MISSING_DEP,
    KLIB_INIT_FAILED
};

typedef void *(*klib_get_sym)(const char *name);

typedef void (*klib_add_sym)(void *e, const char *a, void *v);
