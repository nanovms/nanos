#include <io.h>

#define VM_EXIT_GDB 0x7d
#define VM_EXIT_FAULT 0x7e
#define VM_EXIT_HALT 0x7f

static inline void QEMU_HALT(u8 code) __attribute__((noreturn));

static inline void QEMU_HALT(u8 code)
{
    /* special qemu debug exit; returns ((code << 1) | 1) to shell */
    out8(0x501, code);

    /* fallback (when no QEMU) */
    __asm__("cli");
    __asm__("hlt");

    while (1);
}

boolean kvm_detect(kernel_heaps kh);
