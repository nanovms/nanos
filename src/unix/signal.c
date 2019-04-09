#include <unix_internal.h>

sysreturn sigaction(int signum,
              const struct sigaction *act,
              struct sigaction *oldact)
{
    if (oldact) oldact->_u._sa_handler = SIG_DFL;
    return 0;
}


sysreturn sigprocmask(int how, u64 *new, u64 *old)
{
    if (old) *old = 0;
    return 0;
}

void register_signal_syscalls(struct syscall *map)
{
    register_syscall(map, rt_sigprocmask, sigprocmask);
    register_syscall(map, rt_sigaction, sigaction);
    register_syscall(map, sigaltstack, syscall_ignore);
}
