#include <unix_internal.h>

int sigaction(int signum,
              const struct sigaction *act,
              struct sigaction *oldact)
{
    if (oldact) oldact->_u._sa_handler = SIG_DFL;
    return 0;
}


int sigprocmask(int how, u64 *new, u64 *old)
{
    if (old) *old = 0;
    return 0;
}

void register_signal_syscalls(void **map)
{
    register_syscall(map, SYS_rt_sigprocmask, sigprocmask);
    register_syscall(map, SYS_rt_sigaction, sigaction);
    register_syscall(map, SYS_sigaltstack, syscall_ignore);    
}
