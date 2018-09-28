#include <runtime.h>
#include <kvm_platform.h>

// the handler for this in qemu overwrites the exit code to insure its nonzero
void halt(char *format, ...)
{
    vlist a;
    buffer b = little_stack_buffer(512);
    struct buffer f;
    f.start = 0;
    f.contents = format;
    f.end = runtime_strlen(format);

    vstart(a, format);
    vbprintf(b, &f, &a);
    debug(b);
    QEMU_HALT();
}

