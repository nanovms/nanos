#include <io.h>

static inline void QEMU_HALT(u8 code) __attribute__((noreturn));

static inline void QEMU_HALT(u8 code)
{
    /* special qemu debug exit; returns ((code << 1) | 1) to shell */
    out8(0x501, code);

    /* fallback (when no QEMU) */

    /* Issue a CPU reset via port 0x64 of the PS/2 controller. */
    out8(0x64, 0xfe);

    __asm__("cli");
    __asm__("hlt");

    while (1);
}

boolean kvm_detect(kernel_heaps kh);
