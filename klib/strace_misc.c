#include "strace.h"

typedef struct strace_clock_nanosleep_ctx {
    int flags;
    struct timespec *rem;
} *strace_clock_nanosleep_ctx;

static void strace_print_clone_args(strace_sc_ctx ctx, const void *data)
{
    const struct clone_args *args = data;
    bprintf(ctx->trace_buf, "{pidfd=%p, child_tid=%p, parent_tid=%p, exit_signal=%lu, stack=%p, "
            "stack_size=%lu, tls=%p}", args->pidfd, args->child_tid, args->parent_tid,
            args->exit_signal, args->stack, args->stack_size, args->tls);
}

static void strace_print_tms(strace_sc_ctx ctx, const void *data)
{
    const struct tms *tms = data;
    bprintf(ctx->trace_buf, "{tms_utime=%ld, tms_stime=%ld, tms_cutime=%ld, tms_cstime=%ld}",
            tms->tms_utime, tms->tms_stime, tms->tms_cutime, tms->tms_cstime);
}

static void strace_print_timespec(strace_sc_ctx ctx, const void *data)
{
    const struct timespec *ts = data;
    bprintf(ctx->trace_buf, "{tv_sec=%lu, tv_nsec=%lu}", ts->tv_sec, ts->tv_nsec);
}

static void strace_print_rlimit(strace_sc_ctx ctx, const void *data)
{
    const struct rlimit *rlim = data;
    bprintf(ctx->trace_buf, "{rlim_cur=%lu, rlim_max=%lu}",rlim->rlim_cur, rlim->rlim_max);
}

static void strace_clone_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf,
#if defined(__x86_64__)
            "0x%lx, %p, %p, %p, 0x%lx",
#else
            "0x%lx, %p, %p, 0x%lx, %p",
#endif
            sc_arg0(t), sc_arg1(t), sc_arg2(t), sc_arg3(t), sc_arg4(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_clone3_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_data(ctx, pointer_from_u64(sc_arg0(t)), strace_print_clone_args);
    bprintf(ctx->trace_buf, ", %lu", sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_nanosleep_enter(thread t, strace_sc_ctx ctx)
{
    strace_print_user_data(ctx, pointer_from_u64(sc_arg0(t)), strace_print_timespec);
    push_u8(ctx->trace_buf, ',');
    ctx->priv = pointer_from_u64(sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_nanosleep_exit(thread t, strace_sc_ctx ctx)
{
    buffer trace_buf = ctx->trace_buf;
    struct timespec *rem = ctx->priv;
    push_u8(trace_buf, ' ');
    if (sc_retval(t) == 0)
        strace_print_user_data(ctx, rem, strace_print_timespec);
    else if (rem)
        bprintf(trace_buf, "%p", rem);
    else
        buffer_write_cstring(trace_buf, "NULL");
}

static void strace_clock_nanosleep_enter(thread t, strace_sc_ctx ctx)
{
    strace_clock_nanosleep_ctx clock_nanosleep_ctx = allocate(heap_locked(get_kernel_heaps()),
                                                              sizeof(*clock_nanosleep_ctx));
    ctx->priv = clock_nanosleep_ctx;
    if (clock_nanosleep_ctx != INVALID_ADDRESS) {
        clock_nanosleep_ctx->flags = sc_arg1(t);
        clock_nanosleep_ctx->rem = pointer_from_u64(sc_arg3(t));
    }
    buffer trace_buf = ctx->trace_buf;
    bprintf(trace_buf, "%d, 0x%x, ", sc_arg0(t), sc_arg1(t));
    strace_print_user_data(ctx, pointer_from_u64(sc_arg2(t)), strace_print_timespec);
    push_u8(trace_buf, ',');
    if (clock_nanosleep_ctx == INVALID_ADDRESS)
        bprintf(trace_buf, " %p", sc_arg3(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_clock_nanosleep_exit(thread t, strace_sc_ctx ctx)
{
    strace_clock_nanosleep_ctx clock_nanosleep_ctx = ctx->priv;
    if (clock_nanosleep_ctx == INVALID_ADDRESS)
        return;
    struct timespec *rem = clock_nanosleep_ctx->rem;
    buffer trace_buf = ctx->trace_buf;
    push_u8(trace_buf, ' ');
    if ((sc_retval(t) == 0) && !(clock_nanosleep_ctx->flags & TIMER_ABSTIME) && rem)
        strace_print_user_data(ctx, rem, strace_print_timespec);
    else if (rem)
        bprintf(trace_buf, "%p", rem);
    else
        buffer_write_cstring(trace_buf, "NULL");
    deallocate(heap_locked(get_kernel_heaps()), clock_nanosleep_ctx, sizeof(*clock_nanosleep_ctx));
}

static void strace_times_enter(thread t, strace_sc_ctx ctx)
{
    ctx->priv = pointer_from_u64(sc_arg0(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_times_exit(thread t, strace_sc_ctx ctx)
{
    strace_print_user_data(ctx, ctx->priv, strace_print_tms);
}

static void strace_clock_gettime_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d,", sc_arg0(t));
    ctx->priv = pointer_from_u64(sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_clock_gettime_exit(thread t, strace_sc_ctx ctx)
{
    push_u8(ctx->trace_buf, ' ');
    strace_print_user_data(ctx, ctx->priv, strace_print_timespec);
}

static void strace_clock_settime_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, ", sc_arg0(t));
    strace_print_user_data(ctx, pointer_from_u64(sc_arg1(t)), strace_print_timespec);
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_futex_enter(thread t, strace_sc_ctx ctx)
{
    u32 *uaddr = pointer_from_u64(sc_arg0(t));
    int futex_op = sc_arg1(t);
    u32 val = sc_arg2(t);
    const struct timespec *timeout = pointer_from_u64(sc_arg3(t));
    u32 val2 = u64_from_pointer(timeout);
    u32 *uaddr2 = pointer_from_u64(sc_arg4(t));
    u32 val3 = sc_arg5(t);
    buffer trace_buf = ctx->trace_buf;
    sstring op_str;
    switch (futex_op) {
    case FUTEX_WAIT:
    case FUTEX_WAIT | FUTEX_PRIVATE_FLAG:
        op_str = (futex_op == FUTEX_WAIT) ? ss("FUTEX_WAIT") : ss("FUTEX_WAIT_PRIVATE");
        bprintf(trace_buf, "%p, %s, %u, ", uaddr, op_str, val);
        strace_print_user_data(ctx, timeout, strace_print_timespec);
        break;
    case FUTEX_WAIT_BITSET:
    case FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG:
        op_str = (futex_op == FUTEX_WAIT_BITSET) ?
             ss("FUTEX_WAIT_BITSET") : ss("FUTEX_WAIT_BITSET_PRIVATE");
        bprintf(trace_buf, "%p, %s, %u, ", uaddr, op_str, val);
        strace_print_user_data(ctx, timeout, strace_print_timespec);
        bprintf(trace_buf, ", val3=0x%x", val3);
        break;
    case FUTEX_WAKE:
        bprintf(trace_buf, "%p, FUTEX_WAKE, %u", uaddr, val);
        break;
    case FUTEX_WAKE | FUTEX_PRIVATE_FLAG:
        bprintf(trace_buf, "%p, FUTEX_WAKE_PRIVATE, %u", uaddr, val);
        break;
    case FUTEX_CMP_REQUEUE:
        bprintf(trace_buf, "%p, FUTEX_CMP_REQUEUE, %u, %u, %p, %u", uaddr, val, val2, uaddr2, val3);
        break;
    case FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG:
        bprintf(trace_buf, "%p, FUTEX_CMP_REQUEUE_PRIVATE, %u, %u, %p, %u", uaddr, val, val2,
                uaddr2, val3);
        break;
    case FUTEX_WAKE_OP:
    case FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG: {
        op_str = (futex_op == FUTEX_WAKE_OP) ? ss("FUTEX_WAKE_OP") : ss("FUTEX_WAKE_OP_PRIVATE");
        unsigned int op = (val3 >> 28) & MASK(4);
        unsigned int oparg = (val3 >> 12) & MASK(12);
        unsigned int cmp = (val3 >> 24) & MASK(4);
        unsigned int cmparg = val3 & MASK(12);
        bprintf(trace_buf, "%p, %s, %u, %u, %p, {op=%u, oparg=%u, cmp=%u, cmparg=%u}", uaddr,
                op_str, val, val2, uaddr2, op, oparg, cmp, cmparg);
        break;
    }
    default:
        bprintf(trace_buf, "%p, %d, %u, %p, %p, %u", uaddr, futex_op, val, timeout, uaddr2, val3);
    }
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_get_robust_list_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d", sc_arg0(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_set_robust_list_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%p, %lu", sc_arg0(t), sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_prctl_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, 0x%lx, 0x%lx, 0x%lx, 0x%lx", sc_arg0(t), sc_arg1(t), sc_arg2(t),
            sc_arg3(t), sc_arg4(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_getrlimit_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d,", sc_arg0(t));
    ctx->priv = pointer_from_u64(sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_getrlimit_exit(thread t, strace_sc_ctx ctx)
{
    struct rlimit *rlim = ctx->priv;
    buffer trace_buf = ctx->trace_buf;
    push_u8(trace_buf, ' ');
    if (sc_retval(t) == 0)
        strace_print_user_data(ctx, rlim, strace_print_rlimit);
    else if (rlim)
        bprintf(trace_buf, "%p", rlim);
    else
        buffer_write_cstring(trace_buf, "NULL");
}

static void strace_prlimit64_enter(thread t, strace_sc_ctx ctx)
{
    buffer trace_buf = ctx->trace_buf;
    bprintf(trace_buf, "%d, %d, ", sc_arg0(t), sc_arg1(t));
    strace_print_user_data(ctx, pointer_from_u64(sc_arg2(t)), strace_print_rlimit);
    ctx->priv = pointer_from_u64(sc_arg3(t));
    push_u8(trace_buf, ',');
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_prlimit64_exit(thread t, strace_sc_ctx ctx)
{
    const struct rlimit *old_limit = ctx->priv;
    buffer trace_buf = ctx->trace_buf;
    push_u8(trace_buf, ' ');
    if (sc_retval(t) == 0)
        strace_print_user_data(ctx, old_limit, strace_print_rlimit);
    else if (old_limit)
        bprintf(trace_buf, "%p", old_limit);
    else
        buffer_write_cstring(trace_buf, "NULL");
}

static void strace_getrusage_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, %p", sc_arg0(t), sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

static void strace_exit_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d", sc_arg0(t));
}

#if defined(__x86_64__)

static void strace_arch_prctl_enter(thread t, strace_sc_ctx ctx)
{
    bprintf(ctx->trace_buf, "%d, %p", sc_arg0(t), sc_arg1(t));
    ctx->rv_fmt = STRACE_RV_DE;
}

#endif

void strace_misc_init(void)
{
    strace_register_sc_entry_handler(clone);
    strace_register_sc_entry_handler(clone3);
    strace_register_sc_handlers(SYS_nanosleep, strace_nanosleep_enter, strace_nanosleep_exit);
    strace_register_sc_handlers(SYS_clock_nanosleep,
                                strace_clock_nanosleep_enter, strace_clock_nanosleep_exit);
    strace_register_sc_handlers(SYS_times, strace_times_enter, strace_times_exit);
    strace_register_sc_handlers(SYS_clock_gettime,
                                strace_clock_gettime_enter, strace_clock_gettime_exit);
    strace_register_sc_entry_handler(clock_settime);
    strace_register_sc_entry_handler(futex);
    strace_register_sc_entry_handler(get_robust_list);
    strace_register_sc_entry_handler(set_robust_list);
    strace_register_sc_entry_handler(prctl);
    strace_register_sc_handlers(SYS_getrlimit, strace_getrlimit_enter, strace_getrlimit_exit);
    strace_register_sc_handlers(SYS_prlimit64, strace_prlimit64_enter, strace_prlimit64_exit);
    strace_register_sc_entry_handler(getrusage);
    strace_register_sc_entry_handler(exit);
#if defined(__x86_64__)
    strace_register_sc_entry_handler(arch_prctl);
#endif
}
