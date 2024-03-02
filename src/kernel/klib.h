/* in-kernel loadable library interface */
#include "../klib/klib.h"

typedef struct klib_mapping {
    struct rmnode n; /* virtual */
    u64 phys;
    pageflags flags;
} *klib_mapping;

typedef int (*klib_init)(status_handler complete);

typedef struct klib {
    buffer name;
    range load_range;
    rangemap mappings;
    buffer elf;
    klib_init ki;
} *klib;

closure_type(klib_handler, void, klib ks, int rv);

void load_klib(buffer name, klib_handler complete, status_handler sh);

/* The caller must assure no references to klib remain before unloading. */
void unload_klib(klib kl);

void init_klib(kernel_heaps kh, void *fs, tuple root, status_handler complete);

void print_loaded_klibs(void);
