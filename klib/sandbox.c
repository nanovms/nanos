#include <unix_internal.h>

#include "sandbox.h"

static struct sb_syscall sb_syscalls[SYS_MAX];

static sysreturn sb_handler(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    sb_syscall sbsc = &sb_syscalls[sc->call];
    sb_syscall_handler h;
    sysreturn rv;
    vector_foreach(&sbsc->sb_handlers, h) {
        if (h(arg0, arg1, arg2, arg3, arg4, arg5, &rv))
            return rv;
    }
    if (sbsc->default_handler)
        return sbsc->default_handler(arg0, arg1, arg2, arg3, arg4, arg5);
    else
        return -ENOSYS;
}

int init(status_handler complete)
{
    tuple root = get_root_tuple();
    if (!root)
        return KLIB_INIT_FAILED;
    tuple sb_config = get_tuple(root, sym(sandbox));
    if (!sb_config)
        return KLIB_INIT_OK;
    heap h = heap_locked(get_kernel_heaps());
    for (int i = 0; i < SYS_MAX; i++) {
        bytes handler_memsize = 2 * sizeof(sb_syscall_handler);
        void *handlers_mem = mem_alloc(h, handler_memsize, MEM_NOFAIL);
        init_buffer(&sb_syscalls[i].sb_handlers, handler_memsize, false, h, handlers_mem);
    }
    tuple pledge_cfg = get_tuple(sb_config, sym(pledge));
    if (pledge_cfg && !pledge_init(sb_syscalls, pledge_cfg))
        return KLIB_INIT_FAILED;
    tuple unveil_cfg = get_tuple(sb_config, sym(unveil));
    if (unveil_cfg && !unveil_init(sb_syscalls, unveil_cfg))
        return KLIB_INIT_FAILED;
    for (int i = 0; i < SYS_MAX; i++) {
        sb_syscall sbsc = &sb_syscalls[i];
        if (buffer_length(&sbsc->sb_handlers) != 0)
            sbsc->default_handler = swap_syscall_handler(linux_syscalls, i, sb_handler);
    }
    return KLIB_INIT_OK;
}
