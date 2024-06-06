#ifndef STRACE_H_
#define STRACE_H_

#include <unix_internal.h>

#define sc_arg0(t)  thread_frame(t)[SYSCALL_FRAME_ARG0]
#define sc_arg1(t)  thread_frame(t)[SYSCALL_FRAME_ARG1]
#define sc_arg2(t)  thread_frame(t)[SYSCALL_FRAME_ARG2]
#define sc_arg3(t)  thread_frame(t)[SYSCALL_FRAME_ARG3]
#define sc_arg4(t)  thread_frame(t)[SYSCALL_FRAME_ARG4]
#define sc_arg5(t)  thread_frame(t)[SYSCALL_FRAME_ARG5]

#define sc_retval(t)    thread_frame(t)[SYSCALL_FRAME_RETVAL1]

enum strace_rv_fmt {
    STRACE_RV_DE,   /* decimal if >= 0, errno otherwise */
    STRACE_RV_XE,   /* hexadecimal if >= 0, errno otherwise */
};

typedef struct strace_sc_ctx {
    u64 call;
    void (*pause)(context);
    void (*resume)(context);
    buffer trace_buf;
    enum strace_rv_fmt rv_fmt;
    timestamp enter_ts;
    timestamp cpu_time;
    void *priv;
} *strace_sc_ctx;

typedef void (*strace_sc_enter)(thread t, strace_sc_ctx ctx);
typedef void (*strace_sc_exit)(thread t, strace_sc_ctx ctx);

#define strace_register_sc_entry_handler(sc_name)    \
    strace_register_sc_handlers(SYS_##sc_name, strace_##sc_name##_enter, 0)

void strace_register_sc_handlers(int sc, strace_sc_enter enter, strace_sc_exit exit);
void strace_print_user_long(strace_sc_ctx ctx, const long *data, boolean hex);
void strace_print_user_string(strace_sc_ctx ctx, const char *str);
void strace_print_user_data(strace_sc_ctx ctx, const void *data,
                            void handler(strace_sc_ctx, const void *));

void strace_file_init(void);
void strace_mem_init(void);
void strace_misc_init(void);

#define SWITCH_NUM_TO_STRING(num, str)  case num: str = ss(#num); break

#define TRACEBUF_WRITE_FLAG(var, flag)  do {                        \
    if ((var) & (flag)) {                                           \
        if (!empty) push_u8(trace_buf, '|'); else empty = false;    \
        buffer_write_cstring(trace_buf, #flag);                     \
    }                                                               \
} while (0)

#endif
