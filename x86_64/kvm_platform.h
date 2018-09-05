#pragma once
#include <io.h>
#include <disk.h>
#include <booto.h>

#define QEMU_HALT()  out8(0x501, 0);

static inline void haltf(char *f, ...)
{
    buffer bf = alloca_wrap_buffer(f, runtime_strlen(f));
    buffer b = little_stack_buffer(2048);
    vlist ap;
    vstart (ap, f);
    vbprintf(b, bf,  &ap);
    debug(b->contents);
    QEMU_HALT();
}

