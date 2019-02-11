#pragma once
#include <io.h>
#include <region.h>

static inline void QEMU_HALT() __attribute__((noreturn));

static inline void QEMU_HALT()
{
    out8(0x501, 0); // does not return
    while (1);
}
