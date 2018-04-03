#include <io.h>
#include <disk.h>
#include <booto.h>


void *load_elf(buffer, u64 offset, heap pages, heap bss);
#define mov_to_cr(__x, __y) __asm__("mov %0,%%"__x: :"a"(__y):);
#define mov_from_cr(__x, __y) __asm__("mov %%"__x", %0":"=a"(__y):);

// the handler for this in qemu overwrites the exit code to insure its nonzero
#define QEMU_HALT()  out8(0x501, 0);
