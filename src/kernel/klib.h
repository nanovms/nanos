/* in-kernel loadable library interface */
#include "../klib/klib.h"
#define KLIB_MAX_NAME 16

typedef struct klib_mapping {
    struct rmnode n; /* virtual */
    u64 phys;
    u64 flags;
} *klib_mapping;

typedef struct klib {
    char name[KLIB_MAX_NAME];
    tuple syms;
    rangemap mappings;
    buffer elf;
} *klib;

typedef closure_type(klib_handler, void, klib, status);
typedef int (*klib_init)(void *md, klib_add_sym add_sym);

static inline void *klib_sym(klib kl, symbol s)
{
    void *p = table_find(kl->syms, s);
    if (p == 0)
        return INVALID_ADDRESS;
    else if (p == INVALID_ADDRESS)
        return 0;
    else
        return p;
}

void load_klib(const char *name, klib_handler complete);

/* The caller must assure no references to klib remain before unloading. */
void unload_klib(klib kl);

void init_klib(kernel_heaps kh, void *fs, tuple root);
