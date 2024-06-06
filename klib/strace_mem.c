#include "strace.h"

static void strace_brk_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%p", sc_arg0(t));
    ctx->rv_fmt = STRACE_RV_XE;
}

static void strace_mmap_enter(thread t, strace_sc_ctx ctx)
{
    buffer trace_buf = ctx->trace_buf;
    bprintf(trace_buf, "%p, %lu, ", sc_arg0(t), sc_arg1(t));
    int prot = sc_arg2(t);
    if (prot == 0) {
        buffer_write_cstring(trace_buf, "PROT_NONE");
    } else {
        boolean empty = true;
        TRACEBUF_WRITE_FLAG(prot, PROT_READ);
        TRACEBUF_WRITE_FLAG(prot, PROT_WRITE);
        TRACEBUF_WRITE_FLAG(prot, PROT_EXEC);
    }
    int flags = sc_arg3(t);
    buffer_write_cstring(trace_buf, ", ");
    if (flags == 0) {
        push_u8(trace_buf, '0');
    } else {
        boolean empty;
        if ((flags & MAP_TYPE_MASK) == MAP_SHARED_VALIDATE) {
            buffer_write_cstring(trace_buf, "MAP_SHARED_VALIDATE");
            empty = false;
        } else {
            empty = true;
            TRACEBUF_WRITE_FLAG(flags, MAP_SHARED);
            TRACEBUF_WRITE_FLAG(flags, MAP_PRIVATE);
        }
        TRACEBUF_WRITE_FLAG(flags, MAP_FIXED);
        TRACEBUF_WRITE_FLAG(flags, MAP_ANONYMOUS);
        TRACEBUF_WRITE_FLAG(flags, MAP_GROWSDOWN);
        TRACEBUF_WRITE_FLAG(flags, MAP_DENYWRITE);
        TRACEBUF_WRITE_FLAG(flags, MAP_EXECUTABLE);
        TRACEBUF_WRITE_FLAG(flags, MAP_LOCKED);
        TRACEBUF_WRITE_FLAG(flags, MAP_NORESERVE);
        TRACEBUF_WRITE_FLAG(flags, MAP_POPULATE);
        TRACEBUF_WRITE_FLAG(flags, MAP_NONBLOCK);
        TRACEBUF_WRITE_FLAG(flags, MAP_STACK);
        TRACEBUF_WRITE_FLAG(flags, MAP_HUGETLB);
        TRACEBUF_WRITE_FLAG(flags, MAP_SYNC);
        TRACEBUF_WRITE_FLAG(flags, MAP_FIXED_NOREPLACE);
        TRACEBUF_WRITE_FLAG(flags, MAP_UNINITIALIZED);
#if defined(__x86_64__)
        TRACEBUF_WRITE_FLAG(flags, MAP_32BIT);
#endif
        if (flags & ~MASK(HUGETLB_FLAG_ENCODE_SHIFT)) {
            if (!empty)
                push_u8(trace_buf, '|');
            bprintf(trace_buf, "0x%x", flags & ~MASK(HUGETLB_FLAG_ENCODE_SHIFT));
        }
    }
    bprintf(trace_buf, ", %d, %ld", sc_arg4(t), sc_arg5(t));
    ctx->rv_fmt = STRACE_RV_XE;
}

static void strace_munmap_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%p, %lu", sc_arg0(t), sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_mremap_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%p, %lu, %lu, 0x%x, %p", sc_arg0(t), sc_arg1(t), sc_arg2(t),
            sc_arg3(t), sc_arg4(t));
    ctx->rv_fmt = STRACE_RV_XE;
}

static void strace_mprotect_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%p, %lu, 0x%x", sc_arg0(t), sc_arg1(t), sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_msync_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%p, %lu, 0x%x", sc_arg0(t), sc_arg1(t), sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_mincore_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%p, %lu, %p", sc_arg0(t), sc_arg1(t), sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

void strace_mem_init(void)
{
    strace_register_sc_entry_handler(brk);
    strace_register_sc_entry_handler(mmap);
    strace_register_sc_entry_handler(munmap);
    strace_register_sc_entry_handler(mremap);
    strace_register_sc_entry_handler(mprotect);
    strace_register_sc_entry_handler(msync);
    strace_register_sc_entry_handler(mincore);
}
