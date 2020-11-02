enum {
    KLIB_INIT_OK = 0,
    KLIB_INIT_FAILED
};

typedef void (*klib_add_sym)(void *e, const char *a, void *v);
