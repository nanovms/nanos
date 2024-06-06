#include <net_system_structs.h>
#include <unix_internal.h>
#include <socket.h>

#include "sandbox.h"

#define PLEDGE_STDIO        U64_FROM_BIT(0)
#define PLEDGE_RPATH        U64_FROM_BIT(1)
#define PLEDGE_WPATH        U64_FROM_BIT(2)
#define PLEDGE_CPATH        U64_FROM_BIT(3)
#define PLEDGE_DPATH        U64_FROM_BIT(4)
#define PLEDGE_TMPPATH      U64_FROM_BIT(5)
#define PLEDGE_INET         U64_FROM_BIT(6)
#define PLEDGE_MCAST        U64_FROM_BIT(7)
#define PLEDGE_FATTR        U64_FROM_BIT(8)
#define PLEDGE_CHOWN        U64_FROM_BIT(9)
#define PLEDGE_FLOCK        U64_FROM_BIT(10)
#define PLEDGE_UNIX         U64_FROM_BIT(11)
#define PLEDGE_DNS          U64_FROM_BIT(12)
#define PLEDGE_GETPW        U64_FROM_BIT(13)
#define PLEDGE_SENDFD       U64_FROM_BIT(14)
#define PLEDGE_RECVFD       U64_FROM_BIT(15)
#define PLEDGE_TAPE         U64_FROM_BIT(16)
#define PLEDGE_TTY          U64_FROM_BIT(17)
#define PLEDGE_PROC         U64_FROM_BIT(18)
#define PLEDGE_EXEC         U64_FROM_BIT(19)
#define PLEDGE_PROT_EXEC    U64_FROM_BIT(20)
#define PLEDGE_SETTIME      U64_FROM_BIT(21)
#define PLEDGE_PS           U64_FROM_BIT(22)
#define PLEDGE_VMINFO       U64_FROM_BIT(23)
#define PLEDGE_ID           U64_FROM_BIT(24)
#define PLEDGE_PF           U64_FROM_BIT(25)
#define PLEDGE_ROUTE        U64_FROM_BIT(26)
#define PLEDGE_WROUTE       U64_FROM_BIT(27)
#define PLEDGE_AUDIO        U64_FROM_BIT(28)
#define PLEDGE_VIDEO        U64_FROM_BIT(29)
#define PLEDGE_BPF          U64_FROM_BIT(30)
#define PLEDGE_UNVEIL       U64_FROM_BIT(31)
#define PLEDGE_ERROR        U64_FROM_BIT(32)

#define PLEDGE_NEVER    U64_FROM_BIT(63)    /* these syscalls cannot be enabled by any promise */
#define PLEDGE_ALL      -1ull

static struct {
    u64 sc_abilities[SYS_MAX];
    u64 abilities;
    struct spinlock lock;
} pldg;

#define pledge_syscall_register(syscalls, call, abil, handler)  do {    \
    pldg.sc_abilities[SYS_##call] = abil;                               \
    vector_push(&(syscalls)[SYS_##call].sb_handlers, pledge_##handler); \
} while(0)

#define pledge_syscall_register_default(syscalls, call, abil)   \
    pledge_syscall_register(syscalls, call, abil, default_handler)

static sysreturn pledge_fail(thread t)
{
    if (pldg.abilities & PLEDGE_ERROR)
        return -ENOSYS;
    struct siginfo s = {
        .si_signo = SIGABRT,
        .si_errno = 0,
        .si_code = 0,
    };
    deliver_signal_to_thread(t, &s);
    return 0;
}

static boolean pledge_syscall_check(syscall_context sc, sysreturn *rv)
{
    if (pldg.abilities & pldg.sc_abilities[sc->call])
        return false;
    *rv = pledge_fail(sc->t);
    return true;
}

static boolean pledge_default_handler(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                      sysreturn *rv)
{
    if (pldg.abilities == PLEDGE_ALL)
        return false;
    return pledge_syscall_check((syscall_context)get_current_context(current_cpu()), rv);
}

static const sstring promises[] = {
    ss_static_init("stdio"),
    ss_static_init("rpath"),
    ss_static_init("wpath"),
    ss_static_init("cpath"),
    ss_static_init("dpath"),
    ss_static_init("tmppath"),
    ss_static_init("inet"),
    ss_static_init("mcast"),
    ss_static_init("fattr"),
    ss_static_init("chown"),
    ss_static_init("flock"),
    ss_static_init("unix"),
    ss_static_init("dns"),
    ss_static_init("getpw"),
    ss_static_init("sendfd"),
    ss_static_init("recvfd"),
    ss_static_init("tape"),
    ss_static_init("tty"),
    ss_static_init("proc"),
    ss_static_init("exec"),
    ss_static_init("prot_exec"),
    ss_static_init("settime"),
    ss_static_init("ps"),
    ss_static_init("vminfo"),
    ss_static_init("id"),
    ss_static_init("pf"),
    ss_static_init("route"),
    ss_static_init("wroute"),
    ss_static_init("audio"),
    ss_static_init("video"),
    ss_static_init("bpf"),
    ss_static_init("unveil"),
    ss_static_init("error"),
};

static u64 pledge_get_ability(buffer promise)
{
    for (int i = 0; i < _countof(promises); i++)
        if (!buffer_compare_with_sstring(promise, promises[i]))
            return U64_FROM_BIT(i);
    return 0;
}

static sysreturn pledge(const char *promises, const char *execpromises)
{
    if (!promises)
        return 0;
    sstring promises_ss;
    if (!fault_in_user_string(promises, &promises_ss))
        return -EFAULT;
    heap h = heap_locked(&get_unix_heaps()->kh);
    u64 new_abilities = 0;
    vector prom = split(h, alloca_wrap_sstring(promises_ss), ' ');
    string pr;
    vector_foreach(prom, pr) {
        u64 ability = pledge_get_ability(pr);
        if (!ability)
            return -EINVAL;
        new_abilities |= ability;
    }
    spin_lock(&pldg.lock);
    sysreturn rv;
    if (new_abilities & ~pldg.abilities) {
        rv = -EPERM;
    } else {
        pldg.abilities = new_abilities;
        rv = 0;
    }
    spin_unlock(&pldg.lock);
    split_dealloc(prom);
    return rv;
}

static boolean pledge_prot_exec(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    if ((pldg.abilities & PLEDGE_PROT_EXEC) || !(arg2 & PROT_EXEC))
        return false;
    *rv = pledge_fail(sc->t);
    return true;
}

static boolean pledge_ioctl(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                            sysreturn *rv)
{
    if (pldg.abilities == PLEDGE_ALL)
        return false;
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    int fd = arg0;
    unsigned long request = arg1;
    fdesc f = 0;
    switch (request) {
    case FIONREAD:
    case FIONBIO:
    case FIONCLEX:
    case FIOCLEX:
        goto pass;
    }
    thread t = sc->t;
    f = fdesc_get(t->p, fd);
    if (f) {
        if (f->type == FDESC_TYPE_SOCKET) {
            if (pldg.abilities & PLEDGE_ROUTE)
                switch (request) {
                case SIOCGIFADDR:
                case SIOCGIFFLAGS:
                case SIOCGIFMETRIC:
                    goto pass;
                }
            if (pldg.abilities & PLEDGE_WROUTE)
                switch (request) {
                case SIOCSIFADDR:
                case SIOCDIFADDR:
                case SIOCSIFFLAGS:
                case SIOCSIFMETRIC:
                    goto pass;
                }
        }
        fdesc_put(f);
    }
    *rv = pledge_fail(t);
    return true;
  pass:
    if (f)
        fdesc_put(f);
    return false;
}

static boolean pledge_socket_check_domain(thread t, int domain, sysreturn *rv)
{
    switch (domain) {
    case AF_INET:
    case AF_INET6:
        if (!(pldg.abilities & PLEDGE_INET))
            goto fail;
        break;
    case AF_UNIX:
        if (!(pldg.abilities & PLEDGE_UNIX))
            goto fail;
        break;
    default:
        if (pldg.abilities != PLEDGE_ALL)
            goto fail;
    }
    return false;
  fail:
    *rv = pledge_fail(t);
    return true;
}

static boolean pledge_socket(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    return pledge_socket_check_domain(sc->t, arg0, rv);
}

static boolean pledge_sockfd(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    thread t = sc->t;
    fdesc f = fdesc_get(t->p, arg0);
    if (!f)
        return false;
    boolean result;
    if (f->type == FDESC_TYPE_SOCKET)
        result = pledge_socket_check_domain(t, ((struct sock *)f)->domain, rv);
    else
        result = false;
    fdesc_put(f);
    return result;
}

static boolean pledge_sendto(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    struct sockaddr *dest_addr = (struct sockaddr *)arg4;
    if (!dest_addr || (pldg.abilities & (PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS)))
        return false;
    *rv = pledge_fail(sc->t);
    return true;
}

static boolean pledge_sendmsg(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                              sysreturn *rv)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    const struct msghdr *msg = (const struct msghdr *)arg1;
    if (!(pldg.abilities & (PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS)) &&
        validate_user_memory(msg, sizeof(*msg), false) && msg->msg_name) {
        *rv = pledge_fail(sc->t);
        return true;
    }
    return false;
}

static boolean pledge_sockopt_check(boolean set, int level, int optname, sysreturn *rv)
{
    if (pldg.abilities == PLEDGE_ALL)
        return false;
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_RCVBUF:
        case SO_ERROR:
            return false;
        }
        break;
    case SOL_TCP:
        switch (optname) {
        case TCP_NODELAY:
            return false;
        }
        break;
    }
    if (!(pldg.abilities & (PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS)))
        goto fail;
    if ((level == SOL_SOCKET) && (optname == SO_TIMESTAMP))
        return false;
    if ((pldg.abilities & PLEDGE_DNS) && (level == IPPROTO_IPV6))
        switch (optname) {
        case IPV6_RECVPKTINFO:
        case IPV6_USE_MIN_MTU:
            return false;
        }
    if (!(pldg.abilities & (PLEDGE_INET | PLEDGE_UNIX)))
        goto fail;
    if (level == SOL_SOCKET)
        return false;
    if (!(pldg.abilities & PLEDGE_INET))
        goto fail;
    switch (level) {
    case SOL_TCP:
        switch (optname) {
        case TCP_MD5SIG:
        case TCP_MAXSEG:
        case TCP_INFO:
            return false;
        }
        break;
    case IPPROTO_IP:
        switch (optname) {
        case IP_OPTIONS:
            if (!set)
                return false;
            break;
        case IP_TOS:
        case IP_TTL:
        case IP_MINTTL:
            return false;
        case IP_MULTICAST_IF:
        case IP_MULTICAST_TTL:
        case IP_MULTICAST_LOOP:
        case IP_ADD_MEMBERSHIP:
        case IP_DROP_MEMBERSHIP:
            if (pldg.abilities & PLEDGE_MCAST)
                return false;
            break;
        }
        break;
    case IPPROTO_IPV6:
        switch (optname) {
        case IPV6_TCLASS:
        case IPV6_UNICAST_HOPS:
        case IPV6_MINHOPCOUNT:
        case IPV6_RECVHOPLIMIT:
        case IPV6_RECVPKTINFO:
        case IPV6_V6ONLY:
            return false;
        case IPV6_MULTICAST_IF:
        case IPV6_MULTICAST_HOPS:
        case IPV6_MULTICAST_LOOP:
            if (pldg.abilities & PLEDGE_MCAST)
                return false;
            break;
        }
        break;
    }
  fail:
    *rv = pledge_fail(sc->t);
    return true;
}

static boolean pledge_setsockopt(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                 sysreturn *rv)
{
    return pledge_sockopt_check(true, arg1, arg2, rv);
}

static boolean pledge_getsockopt(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                 sysreturn *rv)
{
    return pledge_sockopt_check(false, arg1, arg2, rv);
}

static boolean path_canonicalize(sstring path, sstring *canon_path, int buf_size)
{
    if (sstring_is_empty(path) || (path.ptr[0] != '/'))
        return false;
    bytes offset = 0;
    char *q = canon_path->ptr;
    while ((offset < path.len) && (q - canon_path->ptr < buf_size)) {
        const char *p = path.ptr + offset;
        if (p[0] == '/') {
            if ((offset + 1 == path.len) || (p[1] == '/')) {
                offset++;
                continue;
            }
            if (p[1] == '.') {
                if ((offset + 2 == path.len) || (p[2] == '/')) {
                    offset += 2;
                    continue;
                }
                if ((p[2] == '.') && ((offset + 3 == path.len) || (p[3] == '/'))) {
                    offset += 3;
                    if (q != canon_path->ptr)
                        /* remove the last path component */
                        do {
                            q--;
                        } while (*q != '/');
                    continue;
                }
            }
        }
        *q++ = *p;
        offset++;
    }
    if ((offset == path.len) && (q - canon_path->ptr < buf_size)) {
        if (q == canon_path->ptr)
            *q++ = '/';
        canon_path->len = q - canon_path->ptr;
        return true;
    }
    return false;
}

static boolean path_is_in_dir(sstring path, sstring dir)
{
    if (path.len < dir.len)
        return false;
    return (runtime_memcmp(path.ptr, dir.ptr, dir.len) == 0);
}

static boolean pledge_filepath_create(const char *path, sysreturn *rv)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    if (pldg.abilities & PLEDGE_CPATH)
        return false;
    sstring path_ss;
    if (!fault_in_user_string(path, &path_ss))
        return false;
    char canon_path_array[PATH_MAX];
    sstring canon_path;
    canon_path.ptr = canon_path_array;
    boolean canon = path_canonicalize(path_ss, &canon_path, sizeof(canon_path_array));
    if ((pldg.abilities & PLEDGE_TMPPATH) && canon && path_is_in_dir(canon_path, ss("/tmp/")))
        return false;
    *rv = pledge_fail(sc->t);
    return true;
}

static boolean pledge_filepath_io(int call, const char *path, int flags, sysreturn *rv)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    sstring path_ss;
    if (!fault_in_user_string(path, &path_ss))
        return false;
    char canon_path_array[PATH_MAX];
    sstring canon_path;
    canon_path.ptr = canon_path_array;
    boolean canon = path_canonicalize(path_ss, &canon_path, sizeof(canon_path_array));
    if ((pldg.abilities & PLEDGE_TMPPATH) && canon && path_is_in_dir(canon_path, ss("/tmp/")))
        return false;
    if (!(pldg.abilities & PLEDGE_CPATH) && (flags & O_CREAT))
        goto fail;
    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        if (!(pldg.abilities & PLEDGE_RPATH)) {
            if (!canon)
                goto fail;
            switch (call) {
            case SYS_openat:
                if (path_is_in_dir(canon_path, ss("/usr/share/zoneinfo/")) ||
                    !runtime_strcmp(canon_path, ss("/etc/localtime")))
                    return false;
                if ((pldg.abilities & PLEDGE_DNS) &&
                    (!runtime_strcmp(canon_path, ss("/etc/resolv.conf")) ||
                     !runtime_strcmp(canon_path, ss("/etc/hosts")) ||
                     !runtime_strcmp(canon_path, ss("/etc/services")) ||
                     !runtime_strcmp(canon_path, ss("/etc/protocols"))))
                    return false;
                break;
            case SYS_faccessat:
                if (!runtime_strcmp(canon_path, ss("/etc/localtime")))
                    return false;
                break;
            case SYS_newfstatat:
                if ((pldg.abilities & PLEDGE_DNS) &&
                    (!runtime_strcmp(canon_path, ss("/etc/resolv.conf")) ||
                     !runtime_strcmp(canon_path, ss("/etc/hosts"))))
                    return false;
                break;
            }
            goto fail;
        }
        break;
    case O_WRONLY:
        if (!(pldg.abilities & PLEDGE_WPATH))
            goto fail;
        break;
    case O_RDWR:
        if (!(pldg.abilities & PLEDGE_RPATH) || !(pldg.abilities & PLEDGE_WPATH))
            goto fail;
        break;
    }
    return false;
  fail:
    *rv = pledge_fail(sc->t);
    return true;
}

static boolean pledge_openat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return pledge_filepath_io(SYS_openat, (const char *)arg1, arg2, rv);
}

static boolean pledge_create_arg1(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                  sysreturn *rv)
{
    return pledge_filepath_create((const char *)arg1, rv);
}

static boolean pledge_newfstatat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                 sysreturn *rv)
{
    return pledge_filepath_io(SYS_newfstatat, (const char *)arg1, O_RDONLY, rv);
}

static boolean pledge_symlinkat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    return pledge_filepath_create((const char *)arg2, rv);
}

static boolean pledge_readlinkat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                 sysreturn *rv)
{
    return pledge_filepath_io(SYS_readlinkat, (const char *)arg1, O_RDONLY, rv);
}

static boolean pledge_renameat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    return pledge_filepath_create((const char *)arg1, rv) ||
           pledge_filepath_create((const char *)arg3, rv);
}

static boolean pledge_faccessat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                sysreturn *rv)
{
    return pledge_filepath_io(SYS_faccessat, (const char *)arg1, O_RDONLY, rv);
}

#ifdef __x86_64__

static boolean pledge_open(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                           sysreturn *rv)
{
    return pledge_filepath_io(SYS_openat, (const char *)arg0, arg1, rv);
}

static boolean pledge_stat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                           sysreturn *rv)
{
    return pledge_filepath_io(SYS_newfstatat, (const char *)arg0, O_RDONLY, rv);
}

static boolean pledge_lstat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                            sysreturn *rv)
{
    return pledge_filepath_io(SYS_lstat, (const char *)arg0, O_RDONLY, rv);
}

static boolean pledge_access(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return pledge_filepath_io(SYS_faccessat, (const char *)arg0, O_RDONLY, rv);
}

static boolean pledge_rename(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    return pledge_filepath_create((const char *)arg0, rv) ||
           pledge_filepath_create((const char *)arg2, rv);
}

static boolean pledge_create_arg0(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                                  sysreturn *rv)
{
    return pledge_filepath_create((const char *)arg0, rv);
}

static boolean pledge_creat(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                            sysreturn *rv)
{
    return pledge_filepath_io(SYS_creat, (const char *)arg0, O_CREAT | O_WRONLY | O_TRUNC, rv);
}

static boolean pledge_readlink(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    return pledge_filepath_io(SYS_readlinkat, (const char *)arg0, O_RDONLY, rv);
}

static boolean pledge_uselib(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                             sysreturn *rv)
{
    if (pledge_filepath_io(SYS_uselib, (const char *)arg0, O_RDONLY, rv))
        return true;
    if (pldg.abilities & PLEDGE_PROT_EXEC)
        return false;
    *rv = pledge_fail(current);
    return true;
}

#endif

static boolean pledge_sendmmsg(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5,
                               sysreturn *rv)
{
    syscall_context sc = (syscall_context)get_current_context(current_cpu());
    if (pledge_syscall_check(sc, rv))
        return true;
    struct mmsghdr *msgvec = (struct mmsghdr *)arg1;
    unsigned int vlen = arg2;
    if (!(pldg.abilities & (PLEDGE_INET | PLEDGE_UNIX)) &&
        validate_user_memory(msgvec, vlen * sizeof(struct mmsghdr), false))
        for (unsigned int i = 0; i < vlen; i++)
            if (msgvec[i].msg_hdr.msg_name) {
                *rv = pledge_fail(sc->t);
                return true;
            }
    return false;
}

boolean pledge_init(sb_syscall syscalls, tuple cfg)
{
    pldg.abilities = PLEDGE_ALL;
    register_syscall(linux_syscalls, pledge, pledge);
    pledge_syscall_register_default(syscalls, read, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, write, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, close, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, fstat, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, lseek, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, mmap, PLEDGE_STDIO, prot_exec);
    pledge_syscall_register(syscalls, mprotect, PLEDGE_STDIO, prot_exec);
    pledge_syscall_register_default(syscalls, munmap, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, brk, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, rt_sigaction, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, rt_sigprocmask, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, rt_sigreturn, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, ioctl, PLEDGE_STDIO, ioctl);
    pledge_syscall_register_default(syscalls, pread64, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, pwrite64, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, readv, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, writev, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_yield, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, mremap, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, msync, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, mincore, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, madvise, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, dup, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, nanosleep, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getitimer, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, setitimer, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getpid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sendfile, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, socket, PLEDGE_INET | PLEDGE_UNIX, socket);
    pledge_syscall_register(syscalls, connect, PLEDGE_INET | PLEDGE_UNIX, sockfd);
    pledge_syscall_register(syscalls, accept, PLEDGE_INET | PLEDGE_UNIX, sockfd);
    pledge_syscall_register(syscalls, sendto, PLEDGE_STDIO, sendto);
    pledge_syscall_register_default(syscalls, recvfrom, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, sendmsg, PLEDGE_STDIO, sendmsg);
    pledge_syscall_register_default(syscalls, recvmsg, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, shutdown, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, bind, PLEDGE_INET | PLEDGE_UNIX, sockfd);
    pledge_syscall_register(syscalls, listen, PLEDGE_INET | PLEDGE_UNIX, sockfd);
    pledge_syscall_register(syscalls, getsockname, PLEDGE_INET | PLEDGE_UNIX, sockfd);
    pledge_syscall_register(syscalls, getpeername, PLEDGE_INET | PLEDGE_UNIX, sockfd);
    pledge_syscall_register_default(syscalls, socketpair, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, setsockopt, PLEDGE_STDIO, setsockopt);
    pledge_syscall_register(syscalls, getsockopt, PLEDGE_STDIO, getsockopt);
    pledge_syscall_register_default(syscalls, clone, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, wait4, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, kill, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, uname, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, fcntl, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, flock, PLEDGE_FLOCK);
    pledge_syscall_register_default(syscalls, fsync, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, fdatasync, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, truncate, PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, ftruncate, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getcwd, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, chdir, PLEDGE_RPATH);
    pledge_syscall_register_default(syscalls, fchdir, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, fchmod, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, fchown, PLEDGE_FATTR | PLEDGE_CHOWN);
    pledge_syscall_register_default(syscalls, umask, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, gettimeofday, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getrlimit, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getrusage, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, times, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getuid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getgid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, setuid, PLEDGE_ID);
    pledge_syscall_register_default(syscalls, setgid, PLEDGE_ID);
    pledge_syscall_register_default(syscalls, geteuid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getegid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, setreuid, PLEDGE_ID);
    pledge_syscall_register_default(syscalls, setregid, PLEDGE_ID);
    pledge_syscall_register_default(syscalls, getgroups, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, setgroups, PLEDGE_ID);
    pledge_syscall_register_default(syscalls, setresuid, PLEDGE_ID);
    pledge_syscall_register_default(syscalls, getresuid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getresgid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getpgid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getsid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, rt_sigpending, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, rt_sigtimedwait, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, rt_sigqueueinfo, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, rt_sigsuspend, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sigaltstack, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, statfs, PLEDGE_RPATH);
    pledge_syscall_register_default(syscalls, fstatfs, PLEDGE_RPATH);
    pledge_syscall_register_default(syscalls, sched_setparam, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_getparam, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_setscheduler, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_getscheduler, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_get_priority_max, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_get_priority_min, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_rr_get_interval, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, mlock, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, munlock, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, mlockall, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, munlockall, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, pivot_root, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, prctl, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, adjtimex, PLEDGE_SETTIME);
    pledge_syscall_register_default(syscalls, setrlimit, PLEDGE_PROC | PLEDGE_ID);
    pledge_syscall_register_default(syscalls, chroot, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, sync, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, acct, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, settimeofday, PLEDGE_SETTIME);
    pledge_syscall_register_default(syscalls, mount, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, umount2, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, swapon, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, swapoff, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, reboot, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, sethostname, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, setdomainname, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, init_module, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, delete_module, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, quotactl, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, gettid, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, readahead, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, setxattr, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, lsetxattr, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, fsetxattr, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, getxattr, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, lgetxattr, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, fgetxattr, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, listxattr, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, llistxattr, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, flistxattr, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, removexattr, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, lremovexattr, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, fremovexattr, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, tkill, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, futex, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_setaffinity, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_getaffinity, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, io_setup, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, io_destroy, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, io_getevents, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, io_submit, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, io_cancel, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, lookup_dcookie, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, getdents64, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, set_tid_address, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, fadvise64, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, timer_create, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, timer_settime, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, timer_gettime, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, timer_getoverrun, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, timer_delete, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, clock_settime, PLEDGE_SETTIME);
    pledge_syscall_register_default(syscalls, clock_gettime, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, clock_getres, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, clock_nanosleep, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, epoll_ctl, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, tgkill, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, mbind, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, set_mempolicy, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, get_mempolicy, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, add_key, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, request_key, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, keyctl, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, ioprio_get, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, ioprio_set, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, inotify_add_watch, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, inotify_rm_watch, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, migrate_pages, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, openat, PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH, openat);
    pledge_syscall_register(syscalls, mkdirat, PLEDGE_CPATH | PLEDGE_TMPPATH, create_arg1);
    pledge_syscall_register_default(syscalls, mknodat, PLEDGE_DPATH);
    pledge_syscall_register_default(syscalls, fchownat, PLEDGE_FATTR | PLEDGE_CHOWN);
    pledge_syscall_register(syscalls, newfstatat, PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH,
                            newfstatat);
    pledge_syscall_register(syscalls, unlinkat, PLEDGE_CPATH | PLEDGE_TMPPATH, create_arg1);
    pledge_syscall_register(syscalls, renameat, PLEDGE_CPATH | PLEDGE_TMPPATH, renameat);
    pledge_syscall_register_default(syscalls, linkat, PLEDGE_CPATH);
    pledge_syscall_register(syscalls, symlinkat, PLEDGE_CPATH | PLEDGE_TMPPATH, symlinkat);
    pledge_syscall_register(syscalls, readlinkat, PLEDGE_RPATH | PLEDGE_TMPPATH, readlinkat);
    pledge_syscall_register_default(syscalls, fchmodat, PLEDGE_FATTR);
    pledge_syscall_register(syscalls, faccessat, PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH,
                            faccessat);
    pledge_syscall_register_default(syscalls, pselect6, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, ppoll, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, set_robust_list, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, get_robust_list, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, splice, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, tee, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sync_file_range, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, vmsplice, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, move_pages, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, utimensat, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, epoll_pwait, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, timerfd_create, PLEDGE_STDIO);
#ifdef __x86_64__
    pledge_syscall_register(syscalls, open, PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH, open);
    pledge_syscall_register(syscalls, stat, PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH, stat);
    pledge_syscall_register(syscalls, lstat, PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH, lstat);
    pledge_syscall_register_default(syscalls, poll, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, access, PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH, access);
    pledge_syscall_register_default(syscalls, pipe, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, select, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, dup2, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, pause, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, alarm, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, getdents, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, rename, PLEDGE_CPATH | PLEDGE_TMPPATH, rename);
    pledge_syscall_register(syscalls, mkdir, PLEDGE_CPATH | PLEDGE_TMPPATH, create_arg0);
    pledge_syscall_register(syscalls, rmdir, PLEDGE_CPATH | PLEDGE_TMPPATH, create_arg0);
    pledge_syscall_register(syscalls, creat, PLEDGE_CPATH | PLEDGE_TMPPATH, creat);
    pledge_syscall_register(syscalls, unlink, PLEDGE_CPATH | PLEDGE_TMPPATH, create_arg0);
    pledge_syscall_register(syscalls, symlink, PLEDGE_CPATH | PLEDGE_TMPPATH, create_arg1);
    pledge_syscall_register(syscalls, readlink, PLEDGE_RPATH | PLEDGE_TMPPATH, readlink);
    pledge_syscall_register_default(syscalls, chmod, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, chown, PLEDGE_FATTR | PLEDGE_CHOWN);
    pledge_syscall_register_default(syscalls, lchown, PLEDGE_FATTR | PLEDGE_CHOWN);
    pledge_syscall_register_default(syscalls, getpgrp, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, utime, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, mknod, PLEDGE_DPATH);
    pledge_syscall_register(syscalls, uselib, PLEDGE_STDIO, uselib);
    pledge_syscall_register_default(syscalls, modify_ldt, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, _sysctl, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, arch_prctl, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, iopl, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, ioperm, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, time, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, set_thread_area, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, get_thread_area, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, epoll_create, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, epoll_wait, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, utimes, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, inotify_init, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, futimesat, PLEDGE_FATTR);
    pledge_syscall_register_default(syscalls, signalfd, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, eventfd, PLEDGE_STDIO);
#endif
    pledge_syscall_register_default(syscalls, fallocate, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, timerfd_settime, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, timerfd_gettime, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, accept4, PLEDGE_INET | PLEDGE_UNIX, sockfd);
    pledge_syscall_register_default(syscalls, signalfd4, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, eventfd2, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, epoll_create1, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, dup3, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, pipe2, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, inotify_init1, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, preadv, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, pwritev, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, rt_tgsigqueueinfo, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, perf_event_open, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, recvmmsg, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, fanotify_init, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, fanotify_mark, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, prlimit64, PLEDGE_PROC | PLEDGE_ID);
    pledge_syscall_register_default(syscalls, name_to_handle_at, PLEDGE_RPATH | PLEDGE_WPATH);
    pledge_syscall_register_default(syscalls, open_by_handle_at, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, clock_adjtime, PLEDGE_SETTIME);
    pledge_syscall_register_default(syscalls, syncfs, PLEDGE_NEVER);
    pledge_syscall_register(syscalls, sendmmsg, PLEDGE_STDIO, sendmmsg);
    pledge_syscall_register_default(syscalls, getcpu, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, finit_module, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, sched_setattr, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, sched_getattr, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, renameat2, PLEDGE_CPATH);
    pledge_syscall_register_default(syscalls, seccomp, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, getrandom, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, memfd_create, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, bpf, PLEDGE_BPF);
    pledge_syscall_register_default(syscalls, userfaultfd, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, membarrier, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, mlock2, PLEDGE_NEVER);
    pledge_syscall_register_default(syscalls, copy_file_range, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, preadv2, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, pwritev2, PLEDGE_STDIO);
    pledge_syscall_register(syscalls, pkey_mprotect, PLEDGE_STDIO, prot_exec);
    pledge_syscall_register_default(syscalls, pkey_alloc, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, pkey_free, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, io_uring_setup, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, io_uring_enter, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, io_uring_register, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, clone3, PLEDGE_STDIO);
    pledge_syscall_register_default(syscalls, unveil, PLEDGE_UNVEIL);
    return true;
}
