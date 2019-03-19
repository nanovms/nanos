#pragma once
#include <io.h>
#include <region.h>

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
