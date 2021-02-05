/* in-kernel loadable library interface */
#include "../klib/klib.h"
#define KLIB_MAX_NAME 16

typedef struct klib_mapping {
    struct rmnode n; /* virtual */
    u64 phys;
    pageflags flags;
} *klib_mapping;

typedef struct klib {
    char name[KLIB_MAX_NAME];
    table syms;
    range load_range;
    rangemap mappings;
    buffer elf;
} *klib;

typedef closure_type(klib_handler, void, klib, status);
typedef int (*klib_init)(void *md, klib_get_sym get_sym, klib_add_sym add_sym);

void *klib_sym(klib kl, symbol s);

void load_klib(const char *name, klib_handler complete);

/* The caller must assure no references to klib remain before unloading. */
void unload_klib(klib kl);

void init_klib(kernel_heaps kh, void *fs, tuple root, tuple klib_md);
