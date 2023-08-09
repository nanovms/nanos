typedef boolean (*sb_syscall_handler)(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                      sysreturn *rv);

typedef struct sb_syscall {
    struct buffer sb_handlers;
    sysreturn (*default_handler)(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5);
} *sb_syscall;

/* OpenBSD syscalls, mapped to unused syscall numbers in Linux */
#define SYS_pledge  335
#define SYS_unveil  336

boolean pledge_init(sb_syscall syscalls, tuple cfg);
boolean unveil_init(sb_syscall syscalls, tuple cfg);
