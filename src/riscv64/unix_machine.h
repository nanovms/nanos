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

#define O_DIRECTORY     00200000
#define O_NOFOLLOW      00400000
#define O_DIRECT        00040000
#define O_LARGEFILE     00100000

struct epoll_event {
    u32 events;                 /* Epoll events */
    u64 data;
};

/* kernel stuff */

#define SYSCALL_FRAME_ARG0       FRAME_A0
#define SYSCALL_FRAME_ARG1       FRAME_A1
#define SYSCALL_FRAME_ARG2       FRAME_A2
#define SYSCALL_FRAME_ARG3       FRAME_A3
#define SYSCALL_FRAME_ARG4       FRAME_A4
#define SYSCALL_FRAME_ARG5       FRAME_A5
#define SYSCALL_FRAME_RETVAL1    FRAME_A0
#define SYSCALL_FRAME_RETVAL2    FRAME_A1
#define SYSCALL_FRAME_SP         FRAME_SP
#define SYSCALL_FRAME_PC         FRAME_PC

#define MINSIGSTKSZ 5120

struct user_regs_struct {
    u64 pc;
    u64 ra;
    u64 sp;
    u64 gp;
    u64 tp;
    u64 t0;
    u64 t1;
    u64 t2;
    u64 s0;
    u64 s1;
    u64 a0;
    u64 a1;
    u64 a2;
    u64 a3;
    u64 a4;
    u64 a5;
    u64 a6;
    u64 a7;
    u64 s2;
    u64 s3;
    u64 s4;
    u64 s5;
    u64 s6;
    u64 s7;
    u64 s8;
    u64 s9;
    u64 s10;
    u64 s11;
    u64 t3;
    u64 t4;
    u64 t5;
    u64 t6;
};

struct __riscv_f_ext_state {
    u32 f[32];
    u32 fcsr;
};

struct __riscv_d_ext_state {
    u64 f[32];
    u32 fcsr;
};

struct __riscv_q_ext_state {
    u64 f[64] __attribute__((aligned(16)));
    u32 fcsr;
    u32 reserved[3];
};

union __riscv_fp_state {
    struct __riscv_f_ext_state f;
    struct __riscv_d_ext_state d;
    struct __riscv_q_ext_state q;
};

struct sigcontext {
    struct user_regs_struct sc_regs;
    union __riscv_fp_state sc_fpregs;
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

static inline pageflags pageflags_from_vmflags(u64 vmflags)
{
    pageflags flags = pageflags_user(pageflags_memory());
    if (vmflags & VMAP_FLAG_EXEC)
        flags = pageflags_exec(flags);
    if (vmflags & VMAP_FLAG_WRITABLE)
        flags = pageflags_writable(flags);
    return flags;
}

static inline u64 get_tls(context f)
{
    return f[FRAME_TP];
}

static inline void set_tls(context f, u64 tls)
{
    f[FRAME_TP] = tls;
}

static inline void syscall_restart_arch_setup(context f)
{
    f[FRAME_SAVED_A0] = f[FRAME_A0];
}

static inline void syscall_restart_arch_fixup(context f)
{
    /* rewind to syscall */
    f[FRAME_PC] -= 4;
    f[FRAME_A0] = f[FRAME_SAVED_A0];
}

#define thread_frame_save_tls(f) ((void)f)
#define thread_frame_restore_tls(f) ((void)f)
#define thread_frame_save_fpsimd(f) ((void)f)
#define thread_frame_restore_fpsimd(f) ((void)f)

