#include <unix_internal.h>

sysreturn sigaction(int signum,
              const struct sigaction *act,
              struct sigaction *oldact)
{
    if (oldact) oldact->_u._sa_handler = SIG_DFL;
    return 0;
}

sysreturn rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, u64 sigsetsize)
{
    if (oldset)
        runtime_memset((void *) oldset, 0, sigsetsize);

    return 0;
}

void register_signal_syscalls(struct syscall *map)
{
    register_syscall(map, rt_sigprocmask, rt_sigprocmask);
    register_syscall(map, rt_sigaction, sigaction);
    register_syscall(map, sigaltstack, syscall_ignore);
}
