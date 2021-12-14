/* attributes for compiling+linking */

#define NOTRACE __attribute__((no_instrument_function))
#define HIDDEN  __attribute__((visibility("hidden")))
#define VDSO     HIDDEN
#define VVAR     HIDDEN
#define VSYSCALL NOTRACE __attribute__((section(".vsyscall")))
#ifdef KERNEL
#define RO_AFTER_INIT       __attribute__((section(".ro_after_init")))
#define BSS_RO_AFTER_INIT   __attribute__((section(".bss.ro_after_init")))
#else
#define RO_AFTER_INIT
#define BSS_RO_AFTER_INIT
#endif
