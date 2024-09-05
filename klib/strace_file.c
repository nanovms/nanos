#include "strace.h"
#include "sandbox.h"

typedef struct strace_newfstatat_ctx {
    struct stat *s;
    int flags;
} *strace_newfstatat_ctx;

static void strace_print_iov_entry(strace_sc_ctx ctx, const void *data)
{
    const struct iovec *iov = data;
    bprintf(ctx->trace_buf, "{iov_base=%p, iov_len=%lu}", iov->iov_base, iov->iov_len);
}

static void strace_print_iov(strace_sc_ctx ctx, const struct iovec *iov, int iovcnt)
{
    for (int i = 0; i < iovcnt; i++) {
        if (i != 0)
            buffer_write_cstring(ctx->trace_buf, ", ");
        strace_print_user_data(ctx, &iov[i], strace_print_iov_entry);
    }
}

static void strace_print_stat(strace_sc_ctx ctx, const void *data)
{
    const struct stat *s = data;
    bprintf(ctx->trace_buf, "[{st_ino=0x%lx, st_mode=0x%lx, st_size=%ld}]",
            s->st_ino, s->st_mode, s->st_size);
}

static void strace_print_statx_mask(buffer trace_buf, const unsigned int mask)
{
    boolean empty = true;
    if ((mask & STATX_BASIC_STATS) == STATX_BASIC_STATS) {
        buffer_write_cstring(trace_buf, "STATX_BASIC_STATS");
        empty = false;
    } else {
        TRACEBUF_WRITE_FLAG(mask, STATX_TYPE);
        TRACEBUF_WRITE_FLAG(mask, STATX_MODE);
        TRACEBUF_WRITE_FLAG(mask, STATX_NLINK);
        TRACEBUF_WRITE_FLAG(mask, STATX_UID);
        TRACEBUF_WRITE_FLAG(mask, STATX_GID);
        TRACEBUF_WRITE_FLAG(mask, STATX_ATIME);
        TRACEBUF_WRITE_FLAG(mask, STATX_MTIME);
        TRACEBUF_WRITE_FLAG(mask, STATX_CTIME);
        TRACEBUF_WRITE_FLAG(mask, STATX_INO);
        TRACEBUF_WRITE_FLAG(mask, STATX_SIZE);
        TRACEBUF_WRITE_FLAG(mask, STATX_BLOCKS);
    }
    TRACEBUF_WRITE_FLAG(mask, STATX_BTIME);
    TRACEBUF_WRITE_FLAG(mask, STATX_MNT_ID);
    TRACEBUF_WRITE_FLAG(mask, STATX_DIOALIGN);
    u32 unknown_flags = mask & 0xffffc000;
    if (unknown_flags) {
        if (!empty)
            push_u8(trace_buf, '|');
        bprintf(trace_buf, "0x%x", unknown_flags);
    }
}

static void strace_print_statx(strace_sc_ctx ctx, const void *data)
{
    buffer trace_buf = ctx->trace_buf;
    const struct statx *s = data;
    u32 mask = s->stx_mask;
    buffer_write_cstring(trace_buf, "[{stx_mask=");
    strace_print_statx_mask(trace_buf, mask);
    if (mask & (STATX_TYPE | STATX_MODE))
        bprintf(trace_buf, ", stx_mode=0x%x", s->stx_mode);
    if (mask & STATX_ATIME)
        bprintf(trace_buf, ", stx_atime={tv_sec=%ld, tv_nsec=%u}",
                s->stx_atime.tv_sec, s->stx_atime.tv_nsec);
    if (mask & STATX_MTIME)
        bprintf(trace_buf, ", stx_mtime={tv_sec=%ld, tv_nsec=%u}",
                s->stx_mtime.tv_sec, s->stx_mtime.tv_nsec);
    if (mask & STATX_INO)
        bprintf(trace_buf, ", stx_ino=%lu", s->stx_ino);
    if (mask & STATX_SIZE)
        bprintf(trace_buf, ", stx_size=%lu", s->stx_size);
    if (mask & STATX_BLOCKS)
        bprintf(trace_buf, ", stx_blocks=%lu", s->stx_blocks);
    if (mask & STATX_DIOALIGN)
        bprintf(trace_buf, ", stx_dio_mem_align=%u, stx_dio_offset_align=%u", s->stx_dio_mem_align,
                s->stx_dio_offset_align);
    bprintf(trace_buf, ", stx_blksize=%u, stx_rdev_major=%u, stx_rdev_minor=%u}]", s->stx_blksize,
            s->stx_rdev_major, s->stx_rdev_minor);
}

static void strace_print_iocb(strace_sc_ctx ctx, const void *data)
{
    const struct iocb *iocb = data;
    bprintf(ctx->trace_buf, "{filedes=%u, lio_op_code=%u}", iocb->aio_fildes, iocb->aio_lio_opcode);
}

static void strace_openat_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", 0x%x, 0x%x", sc_arg2(t), sc_arg3(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_rw_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, %p, %lu", sc_arg0(t), sc_arg1(t), sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_prw_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, %p, %lu, %ld", sc_arg0(t), sc_arg1(t), sc_arg2(t), sc_arg3(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_rwv_enter(thread t, strace_sc_ctx ctx)
{
    struct iovec *iov = pointer_from_u64(sc_arg1(t));
    int iovcnt = sc_arg2(t);
    buffer trace_buf = ctx->trace_buf;
    bprintf(trace_buf, "%d, [", sc_arg0(t));
    strace_print_iov(ctx, iov, iovcnt);
    bprintf(trace_buf, "], %d", iovcnt);
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_prwv_enter(thread t, strace_sc_ctx ctx)
{
    struct iovec *iov = pointer_from_u64(sc_arg1(t));
    int iovcnt = sc_arg2(t);
    buffer trace_buf = ctx->trace_buf;
    bprintf(trace_buf, "%d, [", sc_arg0(t));
    strace_print_iov(ctx, iov, iovcnt);
    bprintf(trace_buf, "], %d, %ld", iovcnt, sc_arg3(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_lseek_enter(thread t, strace_sc_ctx ctx)
{
    int whence = sc_arg2(t);
    sstring whence_str;
    switch (whence) {
    SWITCH_NUM_TO_STRING(SEEK_SET, whence_str);
    SWITCH_NUM_TO_STRING(SEEK_CUR, whence_str);
    SWITCH_NUM_TO_STRING(SEEK_END, whence_str);
    SWITCH_NUM_TO_STRING(SEEK_DATA, whence_str);
    SWITCH_NUM_TO_STRING(SEEK_HOLE, whence_str);
    default: {
        buffer b = little_stack_buffer(16);
        bprintf(b, "%d", whence);
        whence_str = buffer_to_sstring(b);
        break;
    }
    }
    bprintf(ctx->trace_buf, "%d, %ld, %s", sc_arg0(t), sc_arg1(t), whence_str);
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_ioctl_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, 0x%lx", sc_arg0(t), sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_close_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d", sc_arg0(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_dup_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d", sc_arg0(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_fcntl_enter(thread t, strace_sc_ctx ctx)
{
    int cmd = sc_arg1(t);
    sstring cmd_str;
    switch (cmd) {
    SWITCH_NUM_TO_STRING(F_DUPFD, cmd_str);
    SWITCH_NUM_TO_STRING(F_GETFD, cmd_str);
    SWITCH_NUM_TO_STRING(F_SETFD, cmd_str);
    SWITCH_NUM_TO_STRING(F_GETFL, cmd_str);
    SWITCH_NUM_TO_STRING(F_SETFL, cmd_str);
    SWITCH_NUM_TO_STRING(F_GETLK, cmd_str);
    SWITCH_NUM_TO_STRING(F_SETLK, cmd_str);
    SWITCH_NUM_TO_STRING(F_SETLKW, cmd_str);
    SWITCH_NUM_TO_STRING(F_DUPFD_CLOEXEC, cmd_str);
    SWITCH_NUM_TO_STRING(F_SETPIPE_SZ, cmd_str);
    SWITCH_NUM_TO_STRING(F_GETPIPE_SZ, cmd_str);
    default: {
        buffer b = little_stack_buffer(16);
        bprintf(b, "0x%x", cmd);
        cmd_str = buffer_to_sstring(b);
    }
    }
    bprintf(ctx->trace_buf, "%d, %s, 0x%lx", sc_arg0(t), cmd_str, sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_sendfile_enter(thread t, strace_sc_ctx ctx)
{
    long *offset = pointer_from_u64(sc_arg2(t));
    bprintf(ctx->trace_buf, "%d, %d, ", sc_arg0(t), sc_arg1(t));
    strace_print_user_long(ctx, offset, false);
    bprintf(ctx->trace_buf, ", %ld", sc_arg3(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_truncate_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", %ld", sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_ftruncate_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, %ld", sc_arg0(t), sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_fstat_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d,", sc_arg0(t));
    ctx->priv = pointer_from_u64(sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_stat_exit(thread t, strace_sc_ctx ctx)
{
    const struct stat *s = ctx->priv;
    buffer trace_buf = ctx->trace_buf;
    push_u8(trace_buf, ' ');
    if (sc_retval(t) == 0)
        strace_print_user_data(ctx, s, strace_print_stat);
    else
        bprintf(trace_buf, "%p", s);
}

static void strace_newfstatat_enter(thread t, strace_sc_ctx ctx)
{
    strace_newfstatat_ctx newfstatat_ctx = allocate(heap_locked(get_kernel_heaps()),
                                                     sizeof(*newfstatat_ctx));
    ctx->priv = newfstatat_ctx;
    if (newfstatat_ctx != INVALID_ADDRESS) {
        newfstatat_ctx->s = pointer_from_u64(sc_arg2(t));
        newfstatat_ctx->flags = sc_arg3(t);
    }
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    push_u8(ctx->trace_buf, ',');
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_newfstatat_exit(thread t, strace_sc_ctx ctx)
{
    strace_newfstatat_ctx newfstatat_ctx = ctx->priv;
    if (newfstatat_ctx != INVALID_ADDRESS) {
        struct stat *s = newfstatat_ctx->s;
        int flags = newfstatat_ctx->flags;
        deallocate(heap_locked(get_kernel_heaps()), newfstatat_ctx, sizeof(*newfstatat_ctx));
        buffer trace_buf = ctx->trace_buf;
        push_u8(trace_buf, ' ');
        if (sc_retval(t) == 0)
            strace_print_user_data(ctx, s, strace_print_stat);
        else
            bprintf(trace_buf, "%p", s);
        bprintf(trace_buf, ", %d", flags);
    }
}

static void strace_statx_enter(thread t, strace_sc_ctx ctx)
{
    ctx->priv = pointer_from_u64(sc_arg4(t));
    buffer trace_buf = ctx->trace_buf;
    bprintf(trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(trace_buf, ", 0x%x, ", sc_arg2(t));
    strace_print_statx_mask(trace_buf, sc_arg3(t));
    push_u8(ctx->trace_buf, ',');
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_statx_exit(thread t, strace_sc_ctx ctx)
{
    const struct statx *s = ctx->priv;
    buffer trace_buf = ctx->trace_buf;
    push_u8(trace_buf, ' ');
    if (sc_retval(t) == 0)
        strace_print_user_data(ctx, s, strace_print_statx);
    else if (s)
        bprintf(trace_buf, "%p", s);
    else
        buffer_write_cstring(trace_buf, "NULL");
}

static void strace_faccessat_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", 0x%x", sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_chdir_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_mkdirat_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", 0x%x", sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_unlinkat_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", 0x%x", sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_readlinkat_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", %p, %lu", sc_arg2(t), sc_arg3(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_symlinkat_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", %d, ", sc_arg1(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg2(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_renameat_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", %d, ", sc_arg2(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg3(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_renameat2_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", %d, ", sc_arg2(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg3(t)));
    bprintf(ctx->trace_buf, ", 0x%x", sc_arg4(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_utimensat_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", %p, 0x%x", sc_arg2(t), sc_arg3(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_statfs_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", %p", sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_io_submit_enter(thread t, strace_sc_ctx ctx)
{
    long nr = sc_arg1(t);
    const struct iocb **iocbpp = pointer_from_u64(sc_arg2(t));
    buffer trace_buf = ctx->trace_buf;
    bprintf(trace_buf, "%p, %ld, ", sc_arg0(t), nr);
    if (fault_in_user_memory(iocbpp, nr * sizeof(*iocbpp), false)) {
        push_u8(trace_buf, '[');
        for (int io_op = 0; io_op < nr; io_op++) {
            if (io_op > 0)
                buffer_write_cstring(trace_buf, ", ");
            strace_print_user_data(ctx, iocbpp[io_op], strace_print_iocb);
        }
        push_u8(trace_buf, ']');
    } else if (iocbpp) {
        bprintf(trace_buf, "%p", iocbpp);
    } else {
        buffer_write_cstring(trace_buf, "NULL");
    }
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_inotify_add_watch_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    bprintf(ctx->trace_buf, ", 0x%x", sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_pledge_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    buffer_write_cstring(ctx->trace_buf, ", ");
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_unveil_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    buffer_write_cstring(ctx->trace_buf, ", ");
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

#if defined(__x86_64__)

static void strace_open_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", 0x%x, 0x%x", sc_arg1(t), sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_creat_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", 0x%x", sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_dup2_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, %d", sc_arg0(t), sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_access_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", 0x%x", sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_unlink_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_readlink_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", %p, %lu", sc_arg1(t), sc_arg2(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_symlink_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    buffer_write_cstring(ctx->trace_buf, ", ");
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_rename_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    buffer_write_cstring(ctx->trace_buf, ", ");
    strace_print_user_string(ctx, pointer_from_u64(sc_arg1(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_stat_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    push_u8(ctx->trace_buf, ',');
    ctx->priv = pointer_from_u64(sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_mkdir_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", 0x%x", sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_rmdir_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_utime_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", %p", sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_utimes_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_string(ctx, pointer_from_u64(sc_arg0(t)));
    bprintf(ctx->trace_buf, ", %p", sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

#endif

void strace_file_init(void)
{
    strace_register_sc_entry_handler(openat);
    strace_register_sc_handlers(SYS_read, strace_rw_enter, 0);
    strace_register_sc_handlers(SYS_write, strace_rw_enter, 0);
    strace_register_sc_handlers(SYS_pread64, strace_prw_enter, 0);
    strace_register_sc_handlers(SYS_pwrite64, strace_prw_enter, 0);
    strace_register_sc_handlers(SYS_readv, strace_rwv_enter, 0);
    strace_register_sc_handlers(SYS_writev, strace_rwv_enter, 0);
    strace_register_sc_handlers(SYS_preadv, strace_prwv_enter, 0);
    strace_register_sc_handlers(SYS_pwritev, strace_prwv_enter, 0);
    strace_register_sc_entry_handler(lseek);
    strace_register_sc_entry_handler(ioctl);
    strace_register_sc_entry_handler(close);
    strace_register_sc_entry_handler(dup);
    strace_register_sc_entry_handler(fcntl);
    strace_register_sc_entry_handler(sendfile);
    strace_register_sc_entry_handler(truncate);
    strace_register_sc_entry_handler(ftruncate);
    strace_register_sc_handlers(SYS_fstat, strace_fstat_enter, strace_stat_exit);
    strace_register_sc_handlers(SYS_newfstatat, strace_newfstatat_enter, strace_newfstatat_exit);
    strace_register_sc_handlers(SYS_statx, strace_statx_enter, strace_statx_exit);
    strace_register_sc_entry_handler(faccessat);
    strace_register_sc_entry_handler(chdir);
    strace_register_sc_entry_handler(mkdirat);
    strace_register_sc_entry_handler(unlinkat);
    strace_register_sc_entry_handler(readlinkat);
    strace_register_sc_entry_handler(symlinkat);
    strace_register_sc_entry_handler(renameat);
    strace_register_sc_entry_handler(renameat2);
    strace_register_sc_entry_handler(utimensat);
    strace_register_sc_entry_handler(statfs);
    strace_register_sc_entry_handler(io_submit);
    strace_register_sc_entry_handler(inotify_add_watch);
    strace_register_sc_entry_handler(pledge);
    strace_register_sc_entry_handler(unveil);
#if defined(__x86_64__)
    strace_register_sc_entry_handler(open);
    strace_register_sc_entry_handler(creat);
    strace_register_sc_entry_handler(dup2);
    strace_register_sc_entry_handler(access);
    strace_register_sc_entry_handler(unlink);
    strace_register_sc_entry_handler(readlink);
    strace_register_sc_entry_handler(symlink);
    strace_register_sc_entry_handler(rename);
    strace_register_sc_handlers(SYS_stat, strace_stat_enter, strace_stat_exit);
    strace_register_sc_handlers(SYS_lstat, strace_stat_enter, strace_stat_exit);
    strace_register_sc_entry_handler(mkdir);
    strace_register_sc_entry_handler(rmdir);
    strace_register_sc_entry_handler(utime);
    strace_register_sc_entry_handler(utimes);
#endif
}
