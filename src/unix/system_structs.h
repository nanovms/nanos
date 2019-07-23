// structs that live on the user-kernel boundary

/* fields from linux asm/stat.h - 64-bit only */
struct stat {
    /* 0 - 3 */
    u64 st_dev;
    u64 st_ino;
    u64 st_nlink;
    u32 st_mode;
    u32 st_uid;

    /* 4 - 7 */
    u32 st_gid;
    u32 pad0;
    u64 st_rdev;
    s64 st_size;
    s64 st_blksize;

    /* 8 - 11 */
    s64 st_blocks;
    u64 st_atime;
    u64 st_atime_nsec;
    u64 st_mtime;

    /* 12 - 17 */
    u64 st_mtime_nsec;
    u64 st_ctime;
    u64 st_ctime_nsec;
    u64 unused[3];
} __attribute__((packed));

// better to just do this by offset

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

// take this from filesystem
struct utsname {
    char sysname[65];    
    char nodename[65];   
    char release[65];    
    char version[65];    
    char machine[65];    
};
    
typedef struct iovec {
    void *iov_base;
    u64 iov_len;
} *iovec;

#define EPERM           1               /* Operation not permitted */
#define ENOENT          2               /* No such file or directory */
#define ESRCH           3               /* No such process */
#define EINTR           4               /* Interrupted system call */
#define EIO             5               /* Input/output error */
#define ENXIO           6               /* Device not configured */
#define E2BIG           7               /* Argument list too long */
#define ENOEXEC         8               /* Exec format error */
#define EBADF           9               /* Bad file descriptor */
#define ECHILD          10              /* No child processes */
#define EAGAIN          11              /* Resource deadlock avoided */
#define ENOMEM          12              /* Cannot allocate memory */
#define EACCES          13              /* Permission denied */
#define EFAULT          14              /* Bad address */
#define EBUSY           16              /* Device busy */
#define EEXIST          17              /* File exists */
#define EXDEV           18              /* Cross-device link */
#define ENODEV          19              /* Operation not supported by device */
#define ENOTDIR         20              /* Not a directory */
#define EISDIR          21              /* Is a directory */
#define EINVAL          22              /* Invalid argument */
#define ENFILE          23              /* Too many open files in system */
#define EMFILE          24              /* Too many open files */
#define ENOTTY          25              /* Inappropriate ioctl for device */
#define EFBIG           27              /* File too large */
#define ENOSPC          28              /* No space left on device */
#define ESPIPE          29              /* Illegal seek */
#define EROFS           30              /* Read-only filesystem */
#define EMLINK          31              /* Too many links */
#define EPIPE           32              /* Broken pipe */
#define ERANGE          34              /* Math result not representable */

#define ENOSYS          38              /* Invalid system call number */
#define ENOTEMPTY       39              /* Directory not empty */
#define ENOPROTOOPT     42              /* Protocol not available */

#define EDESTADDRREQ    89		/* Destination address required */
#define EOPNOTSUPP      95		/* Operation not supported */
#define ETIMEDOUT       110     /* Connection timed out */

#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#define O_CREAT		00000100
#define O_EXCL          00000200
#define O_NOCTTY        00000400
#define O_TRUNC		00001000
#define O_APPEND	00002000
#define O_NONBLOCK	00004000
#define O_DIRECT        00040000
#define O_CLOEXEC       02000000

#define F_LINUX_SPECIFIC_BASE   0x400

/* Values for the second argument to `fcntl'.  */
#define F_DUPFD         0       /* Duplicate file descriptor.  */
#define F_GETFD         1       /* Get file descriptor flags.  */
#define F_SETFD         2       /* Set file descriptor flags.  */
#define F_GETFL         3       /* Get file status flags.  */
#define F_SETFL         4       /* Set file status flags.  */
#define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE + 6)

#define FIONBIO		0x5421
#define FIONCLEX        0x5450
#define FIOCLEX         0x5451

#define AT_NULL         0               /* End of vector */
#define AT_IGNORE       1               /* Entry should be ignored */
#define AT_EXECFD       2               /* File descriptor of program */
#define AT_PHDR         3               /* Program headers for program */
#define AT_PHENT        4               /* Size of program header entry */
#define AT_PHNUM        5               /* Number of program headers */
#define AT_PAGESZ       6               /* System page size */
#define AT_BASE         7               /* Base address of interpreter */
#define AT_FLAGS        8               /* Flags */
#define AT_ENTRY        9               /* Entry point of program */
#define AT_NOTELF       10              /* Program is not ELF */
#define AT_UID          11              /* Real uid */
#define AT_EUID         12              /* Effective uid */
#define AT_GID          13              /* Real gid */
#define AT_EGID         14              /* Effective gid */
#define AT_CLKTCK       17              /* Frequency of times() */
#define AT_RANDOM       25   
#define AT_FDCWD        -100            /* openat should use the current working directory.*/

#define AT_SYMLINK_NOFOLLOW 0x100       /* Do not follow symbolic links.  */
#define AT_REMOVEDIR        0x200       /* Remove directory instead of unlinking file. */
#define AT_SYMLINK_FOLLOW   0x400       /* Follow symbolic links.  */
#define AT_NO_AUTOMOUNT     0x800       /* Suppress terminal automount traversal */
#define AT_EMPTY_PATH       0x1000      /* Allow empty relative pathname */

#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_PRIVATE	0x02
#define MREMAP_MAYMOVE	1
#define MREMAP_FIXED	2
#define MAP_STACK	0x20000
#define MAP_32BIT	0x40

#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4

// straight from linux
#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

typedef int clockid_t;

#define CLOCK_REALTIME              0
#define CLOCK_MONOTONIC             1
#define CLOCK_PROCESS_CPUTIME_ID    2
#define CLOCK_THREAD_CPUTIME_ID     3
#define CLOCK_MONOTONIC_RAW         4
#define CLOCK_REALTIME_COARSE       5
#define CLOCK_MONOTONIC_COARSE      6

struct timespec {
	u64 ts_sec;
	u64 ts_nsec;
};

// straight from linux
#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12

#define  FUTEX_OP_SET        0  /* uaddr2 = oparg; */
#define  FUTEX_OP_ADD        1  /* uaddr2 += oparg; */
#define  FUTEX_OP_OR         2  /* uaddr2 |= oparg; */
#define  FUTEX_OP_ANDN       3  /* uaddr2 &= ~oparg; */
#define  FUTEX_OP_XOR        4  /* uaddr2 ^= oparg; */

#define FUTEX_OP_CMP_EQ     0  /* if (oldval == cmparg) wake */
#define FUTEX_OP_CMP_NE     1  /* if (oldval != cmparg) wake */
#define FUTEX_OP_CMP_LT     2  /* if (oldval < cmparg) wake */
#define FUTEX_OP_CMP_LE     3  /* if (oldval <= cmparg) wake */
#define FUTEX_OP_CMP_GT     4  /* if (oldval > cmparg) wake */
#define FUTEX_OP_CMP_GE     5  /* if (oldval >= cmparg) wake */


#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

struct rlimit {
    u64 rlim_cur;  /* Soft limit */
    u64 rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};


#define RLIMIT_CPU		0	/* CPU time in sec */
#define RLIMIT_FSIZE		1	/* Maximum filesize */
#define RLIMIT_DATA		2	/* max data size */
#define RLIMIT_STACK		3	/* max stack size */
#define RLIMIT_CORE		4	/* max core file size */
#define RLIMIT_RSS		5	/* max resident set size */
#define RLIMIT_NPROC		6	/* max number of processes */
#define RLIMIT_NOFILE		7	/* max number of open files */
#define RLIMIT_MEMLOCK		8	/* max locked-in-memory address space */
#define RLIMIT_AS		9	/* address space limit */
#define RLIMIT_LOCKS		10	/* maximum file locks held */
#define RLIMIT_SIGPENDING	11	/* max number of pending signals */
#define RLIMIT_MSGQUEUE		12	/* maximum bytes in POSIX mqueues */
#define RLIMIT_NICE		13	/* max nice prio allowed to raise to */
#define RLIMIT_RTPRIO		14	/* maximum realtime priority */
#define RLIMIT_RTTIME		15	/* timeout for RT tasks in us */

#define SIGHUP		 1
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
#define SIGTRAP		 5
#define SIGABRT		 6
#define SIGIOT		 6
#define SIGBUS		 7
#define SIGFPE		 8
#define SIGKILL		 9
#define SIGUSR1		10
#define SIGSEGV		11
#define SIGUSR2		12
#define SIGPIPE		13
#define SIGALRM		14
#define SIGTERM		15
#define SIGSTKFLT	16
#define SIGCHLD		17
#define SIGCONT		18
#define SIGSTOP		19
#define SIGTSTP		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGURG		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28
#define SIGIO		29


typedef void __signalfn_t(int);
typedef __signalfn_t *__sighandler_t;

#define SIG_DFL	((__sighandler_t)0)	/* default signal handling */
#define SIG_IGN	((__sighandler_t)1)	/* ignore signal */
#define SIG_ERR	((__sighandler_t)-1)	/* error return from signal */

struct siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    // plus big hairy union...we dont plan on delivering any of these at the moment
};

typedef u64 fd_set;

typedef unsigned long int nfds_t;

struct pollfd {
    int   fd;         /* file descriptor */
    short events;     /* requested events */
    short revents;    /* returned events */
};

#define NSIG 64
typedef struct {
    unsigned long sig[NSIG/sizeof(unsigned long)];
} sigset_t;

struct sigaction {
	union {
	  __sighandler_t _sa_handler;
	  void (*_sa_sigaction)(int, struct siginfo *, void *);
	} _u;
	sigset_t sa_mask;
	unsigned long sa_flags;
	void (*sa_restorer)(void);
};

typedef s64 time_t;

struct timeval {
    time_t tv_sec;  /* seconds */
    u64 tv_usec;    /* microseconds */
};

#define CLOCKS_PER_SEC  100

typedef s64 clock_t;

struct tms {
    clock_t tms_utime;
    clock_t tms_stime;
    clock_t tms_cutime;
    clock_t tms_cstime;
};

#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
#define CLONE_THREAD	0x00010000	/* Same thread group? */
#define CLONE_NEWNS	0x00020000	/* New mount namespace group */
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* Clone io context */

struct epoll_event {
    u32     events;      /* Epoll events */
    u64 data;
}  __attribute__((packed));

#define	EPOLL_CTL_ADD 0x1
#define	EPOLL_CTL_DEL 0x2
#define	EPOLL_CTL_MOD 0x3


#define EPOLLIN		0x00000001
#define EPOLLPRI	0x00000002
#define EPOLLOUT	0x00000004
#define EPOLLERR	0x00000008
#define EPOLLHUP	0x00000010
#define EPOLLRDNORM	0x00000040
#define EPOLLRDBAND	0x00000080
#define EPOLLWRNORM	0x00000100
#define EPOLLWRBAND	0x00000200
#define EPOLLMSG	0x00000400
#define EPOLLRDHUP	0x00002000
#define EPOLLEXCLUSIVE	(1u << 29)
#define EPOLLWAKEUP	(1u << 29)
#define EPOLLONESHOT	(1u << 30)
#define EPOLLET		(1u << 31)

typedef struct aux {u64 tag; u64 val;} *aux;

typedef u32 uid_t;
typedef u32 gid_t;


/* set/getsockopt optnames */
#define SO_TYPE 3


/* eventfd flags */
#define EFD_CLOEXEC     02000000
#define EFD_NONBLOCK    00004000
#define EFD_SEMAPHORE   00000001

/* renameat2 flags */
#define RENAME_NOREPLACE    (1 << 0)
#define RENAME_EXCHANGE     (1 << 1)
