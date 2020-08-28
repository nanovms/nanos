#if !(defined(KERNEL) || defined(BOOT))
#error must be in kernel or bootloader build
#endif

#define MBR_ADDRESS 0x7c00

#include "frame.h"

#define KERNEL_BASE 0xffffffff80000000ull
#define KMEM_LIMIT  0xffffffff00000000ull
#define PAGES_BASE  0xffffffffc0000000ull

#define HUGE_PAGESIZE 0x100000000ull

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

#include <lock.h>

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

static inline void cpu_setgs(int cpu)
{
    u64 addr = u64_from_pointer(cpuinfo_from_id(cpu));
    write_msr(KERNEL_GS_MSR, 0); /* clear user GS */
    write_msr(GS_MSR, addr);
}

static inline cpuinfo current_cpu(void)
{
    u64 addr;
    asm volatile("movq %%gs:0, %0":"=r"(addr));
    return (cpuinfo)pointer_from_u64(addr);
}

static inline void set_syscall_handler(void *syscall_entry)
{
    write_msr(LSTAR_MSR, u64_from_pointer(syscall_entry));
    u32 selectors = ((USER_CODE32_SELECTOR | 0x3) << 16) | KERNEL_CODE_SELECTOR;
    write_msr(STAR_MSR, (u64)selectors << 32);
    write_msr(SFMASK_MSR, U64_FROM_BIT(FLAG_INTERRUPT));
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
}

static inline void set_page_write_protect(boolean enable)
{
    word cr0;
    mov_from_cr("cr0", cr0);
    cr0 = enable ? (cr0 | C0_WP) : (cr0 & ~C0_WP);
    mov_to_cr("cr0", cr0);
}

static inline boolean is_protection_fault(context f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_P) != 0;
}

static inline boolean is_usermode_fault(context f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_US) != 0;
}

static inline boolean is_write_fault(context f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_RW) != 0;
}

static inline boolean is_instruction_fault(context f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_ID) != 0;
}

/* page table integrity check? open to interpretation for other archs... */
static inline boolean is_pte_error(context f)
{
    /* XXX check sdm before merging - seems suspicious */
    return (is_protection_fault(f) && (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_RSV));
}

static inline u64 frame_return_address(context f)
{
    return f[FRAME_RIP];
}

static inline u64 fault_address(context f)
{
    return f[FRAME_CR2];
}

static inline u64 total_frame_size(void)
{
    return FRAME_EXTENDED_SAVE * sizeof(u64) + xsave_frame_size();
}

extern void xsave(context f);

/* per-cpu info, saved contexts and stacks */
typedef u64 *context;

#define KERNEL_STACK_WORDS (KERNEL_STACK_SIZE / sizeof(u64))
typedef struct kernel_context {
    u64 stackbase[KERNEL_STACK_WORDS];
    u64 frame[0];
} *kernel_context;

typedef struct cpuinfo {
    /*** Fields accessed by low-level entry points. ***/
    /* Don't move these without updating gs-relative accesses in crt0.s ***/

    /* For accessing cpuinfo via %gs:0; must be first */
    void *self;

    /* This points to the frame of the current, running context. +8 */
    context running_frame;

    /* Default frame and stack installed at kernel entry points (init,
       syscall) and calls to runloop. +16 */
    kernel_context kernel_context;

    /* One temporary for syscall enter to use so that we don't need to touch the user stack. +24 */
    u64 tmp;

    /*** End of fields touched by kernel entries ***/

    u32 id;
    int state;
    boolean have_kernel_lock;
    u64 frcount;

    /* The following fields are used rarely or only on initialization. */

    /* Stack for exceptions (which may occur in interrupt handlers) */
    void *exception_stack;

    /* Stack for interrupts */
    void *int_stack;

    /* leaky unix stuff */
    void *current_thread;
} *cpuinfo;
