#include <runtime.h>
#include <kvm_platform.h>

void vm_exit(u8 code)
{
    QEMU_HALT(code);
}

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
    buffer_print(b);
    vm_exit(VM_EXIT_HALT);
}

