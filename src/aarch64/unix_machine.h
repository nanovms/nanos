/* arch-specific syscall definitions */
struct stat {
    /* 0 - 3 */
    u64 st_dev;
    u64 st_ino;
    u32 st_mode;
    u32 st_nlink;
    u32 st_uid;
    u32 st_gid;

    /* 4 - 7 */
    u64 st_rdev;
    u64 pad1;
    s64 st_size;
    s32 st_blksize;
    s32 pad2;

    /* 8 - 11 */
    s64 st_blocks;
    s64 st_atime;
    u64 st_atime_nsec;
    s64 st_mtime;

    /* 12 - 15 */
    u64 st_mtime_nsec;
    s64 st_ctime;
    u64 st_ctime_nsec;
    s32 unused[2];
} __attribute__((packed));

#define O_DIRECTORY     00040000
#define O_NOFOLLOW      00100000
#define O_DIRECT        00200000
#define O_LARGEFILE     00400000

struct epoll_event {
    u32 events;                 /* Epoll events */
    u64 data;
};

/* kernel stuff */

#define SYSCALL_FRAME_ARG0    FRAME_X0
#define SYSCALL_FRAME_ARG1    FRAME_X1
#define SYSCALL_FRAME_ARG2    FRAME_X2
#define SYSCALL_FRAME_ARG3    FRAME_X3
#define SYSCALL_FRAME_ARG4    FRAME_X4
#define SYSCALL_FRAME_ARG5    FRAME_X5
#define SYSCALL_FRAME_RETVAL1 FRAME_X0
#define SYSCALL_FRAME_RETVAL2 FRAME_X1
#define SYSCALL_FRAME_SP      FRAME_SP
#define SYSCALL_FRAME_PC      FRAME_ELR

#define MINSIGSTKSZ 5120

struct sigcontext {
    u64 fault_address;
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
    u8 reserved[4096] __attribute__((__aligned__(16)));
};

struct ucontext {
    unsigned long uc_flags;
    struct ucontext * uc_link;
    stack_t uc_stack;
    sigset_t uc_sigmask;
    u8 pad[1024 / 8 - sizeof(sigset_t)];
    struct sigcontext uc_mcontext;
};

struct rt_sigframe {
    struct siginfo info;
    struct ucontext uc;
};

static inline u64 page_flags_from_vmflags(u64 vmflags)
{
    u64 flags = PAGE_USER;
    if ((vmflags & VMAP_FLAG_EXEC) == 0)
        flags |= PAGE_NO_EXEC;
    flags |= (vmflags & VMAP_FLAG_WRITABLE) ? PAGE_WRITABLE : PAGE_READONLY;
    return flags;
}

void syscall_entry_arch_fixup(thread t);
void syscall_restart_arch_fixup(thread t);
