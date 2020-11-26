#if !(defined(KERNEL) || defined(BOOT) || defined(KLIB))
#error must be in kernel or bootloader build
#endif

#define MBR_ADDRESS 0x7c00

#define KERNEL_BASE  0xffffffff80000000ull
#define KERNEL_LIMIT 0xfffffffffffff000ull
#define KMEM_LIMIT   0xffffffff00000000ull
#define PAGES_BASE   0xffffffffc0000000ull

#define KERNEL_BASE_PHYS 0x00200000ul
#define STACK_ALIGNMENT     16

#define VIRTUAL_ADDRESS_BITS 48

#define KERNEL_CODE_SELECTOR 0x08
#define USER_CODE32_SELECTOR 0x18

#define TSC_DEADLINE_MSR 0x6e0

#define EFER_MSR         0xc0000080
#define EFER_SCE         0x0001
#define EFER_LME         0x0100
#define EFER_LMA         0x0400
#define EFER_NXE         0x0800
#define EFER_SVME        0x1000
#define EFER_LMSLE       0x2000
#define EFER_FFXSR       0x4000
#define EFER_TCE         0x8000
#define STAR_MSR         0xc0000081
#define LSTAR_MSR        0xc0000082
#define SFMASK_MSR       0xc0000084

#define FS_MSR           0xc0000100
#define GS_MSR           0xc0000101
#define KERNEL_GS_MSR    0xc0000102

#define C0_MP   0x00000002
#define C0_EM   0x00000004
#define C0_WP   0x00010000

#define CR4_PAE         (1 << 5)
#define CR4_OSFXSR      (1 << 9)
#define CR4_OSXMMEXCPT  (1 << 10)
#define CR4_OSXSAVE     (1 << 18)

#define FLAG_INTERRUPT 9

#define TSS_SIZE 0x68

/* AP boot page */
extern void * AP_BOOT_PAGE;
#define AP_BOOT_START u64_from_pointer(&AP_BOOT_PAGE)
#define AP_BOOT_END (AP_BOOT_START + PAGESIZE)

static inline void cpuid(u32 fn, u32 ecx, u32 * v)
{
    asm volatile("cpuid" : "=a" (v[0]), "=b" (v[1]), "=c" (v[2]), "=d" (v[3]) : "0" (fn), "2" (ecx));
}

static inline void enable_interrupts()
{
    asm volatile("sti");
}

static inline void disable_interrupts()
{
    asm volatile("cli");
}

static inline u32 read_eflags(void)
{
    u32 out;
    asm volatile("pushfd");
    asm volatile("popl %0":"=g"(out));
    return out;
}

static inline u64 read_flags(void)
{
    u64 out;
    asm volatile("pushfq");
    asm volatile("popq %0":"=g"(out));
    return out;
}

static inline u64 irq_disable_save(void)
{
    u64 flags = read_flags();
    disable_interrupts();
    return flags;
}

static inline void irq_restore(u64 flags)
{
    if ((flags & U64_FROM_BIT(FLAG_INTERRUPT)))
        enable_interrupts();
}

#ifdef KERNEL
#include <lock.h>
#endif

extern u64 read_msr(u64);
extern void write_msr(u64, u64);
extern u64 read_xmsr(u64);
extern void write_xmsr(u64, u64);

#define mov_to_cr(__x, __y) asm volatile("mov %0,%%"__x : : "a"(__y) : "memory");
#define mov_from_cr(__x, __y) asm volatile("mov %%"__x", %0" : "=a"(__y) : : "memory");

#define switch_stack(__s, __target) {                           \
        asm volatile("mov %0, %%rdx": :"r"(__s):"%rdx");        \
        asm volatile("mov %0, %%rax": :"r"(__target));          \
        asm volatile("mov %%rdx, %%rsp"::);                     \
        asm volatile("jmp *%%rax"::);                           \
    }

/* for vdso */
#define do_syscall(sysnr, rdi, rsi) ({\
    sysreturn rv;\
    asm("syscall"\
        : "=a" (rv)\
        : "0" (sysnr), "D" (rdi), "S"(rsi)\
        : "memory"\
    );\
    rv;\
})

static inline u64 xsave_frame_size(void)
{
#if 0
    u32 v[4];
    cpuid(0xd, 0, v);
    return v[1];
#else
    return 512;                 /* XXX fx only right now */
#endif
}
