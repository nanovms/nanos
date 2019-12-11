/* attributes for compiling+linking */
#pragma once

#define NOTRACE __attribute__((no_instrument_function))
#define HIDDEN  __attribute__((visibility("hidden")))
#define VDSO     HIDDEN
#define VVAR     HIDDEN
#define VSYSCALL NOTRACE __attribute__((section(".vsyscall")))
