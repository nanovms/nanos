/* in-kernel loadable library interface */
#include "../klib/klib.h"
#define KLIB_MAX_NAME 16

typedef struct klib_mapping {
    struct rmnode n; /* virtual */
    u64 phys;
    pageflags flags;
} *klib_mapping;

typedef int (*klib_init)(status_handler complete);

typedef struct klib {
    char name[KLIB_MAX_NAME];
    range load_range;
    rangemap mappings;
    buffer elf;
    klib_init ki;
} *klib;

typedef closure_type(klib_handler, void, klib, int);

void load_klib(const char *name, klib_handler complete, status_handler sh);

/* The caller must assure no references to klib remain before unloading. */
void unload_klib(klib kl);

void init_klib(kernel_heaps kh, void *fs, tuple root, status_handler complete);
