#define VVAR_DEF(type, name) type name
#define VVAR_REF(name) __vdso_ ## name
#define VVAR_DECL(type, name) extern VVAR type __vdso_ ## name

#define VDSO_NO_NOW (timestamp)-1

#define do_syscall(sysnr, rdi, rsi) ({\
    sysreturn rv;\
    asm("syscall"\
        : "=a" (rv)\
        : "0" (sysnr), "D" (rdi), "S"(rsi)\
        : "memory"\
    );\
    rv;\
})

/* An instance of this struct is shared between kernel and userspace
 * Make sure there are no pointers embedded in it
 */
struct vdso_dat_struct {
    vdso_clock_id clock_src;
    timestamp rtc_offset;
    u64 pvclock_offset;
    u8 platform_has_rdtscp;
} __attribute((packed));

/* VDSO accessible variables */
VVAR_DECL(struct vdso_dat_struct, vdso_dat);

/* now() routines that are accessible from both the VDSO and the core kernel */
struct pvclock_vcpu_time_info;
VDSO u64 vdso_pvclock_now_ns(volatile struct pvclock_vcpu_time_info *);
VDSO timestamp vdso_now(clock_id id);
