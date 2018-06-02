#include <runtime.h>
#include <kvm_platform.h>

// the handler for this in qemu overwrites the exit code to insure its nonzero
void halt(char *x, ...)
{
    console(x);
    QEMU_HALT();
}

