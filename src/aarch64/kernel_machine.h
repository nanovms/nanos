#if !(defined(KERNEL))
#error must be in kernel build
#endif

/* XXX - carry over from pc */
#define MBR_ADDRESS 0x7c00

#include "frame.h"

#define DEVICE_BASE 0xffffffff00000000ull
#define PAGES_BASE  0xffffffffc0000000ull
#define KERNEL_BASE 0xffffffff80000000ull

#define KERNEL_PHYS 0x0000000040400000ull /* must match linker script - XXX extern? */

#include <kernel_platform.h>

#define HUGE_PAGESIZE 0x100000000ull

#define STACK_ALIGNMENT     16

#define SCTLR_EL1_UCI     U64_FROM_BIT(26) /* trap cache instructions in EL0 */
#define SCTLR_EL1_EE      U64_FROM_BIT(25) /* endianness for EL1 data / pt table */
#define SCTLR_EL1_E0E     U64_FROM_BIT(24) /* endianness for EL0 data */
#define SCTLR_EL1_WXN     U64_FROM_BIT(19) /* write implies execute never */
#define SCTLR_EL1_I       U64_FROM_BIT(12) /* instruction cacheability (no effect) */
#define SCTLR_EL1_SA0     U64_FROM_BIT(4) /* SP alignment fault enable for EL0 */
#define SCTLR_EL1_SA      U64_FROM_BIT(3) /* SP alignment fault enable */
#define SCTLR_EL1_C       U64_FROM_BIT(2) /* cacheability (no effect) */
#define SCTLR_EL1_A       U64_FROM_BIT(1) /* alignment fault check enable */
#define SCTLR_EL1_M       U64_FROM_BIT(0) /* MMU enable */

#define CPACR_EL1_TTA            U64_FROM_BIT(28)
#define CPACR_EL1_FPEN_BITS      2
#define CPACR_EL1_FPEN_SHIFT     20
#define CPACR_EL1_FPEN_EL10_TRAP 0x0
#define CPACR_EL1_FPEN_EL0_TRAP  0x1
#define CPACR_EL1_FPEN_NO_TRAP   0x3

#define ESR_EC_BITS   6
#define ESR_EC_SHIFT  26

#define ESR_EC_UNKNOWN 0x00
#define ESR_EC_ILL_EXEC 0x0e
#define ESR_EC_INST_ABRT_LEL  0x20
#define ESR_EC_INST_ABRT      0x21
#define ESR_EC_PC_ALIGN_FAULT 0x22
#define ESR_EC_DATA_ABRT_LEL  0x24
#define ESR_EC_DATA_ABRT      0x25
#define ESR_EC_SP_ALIGN_FAULT 0x26
#define ESR_EC_SERROR_INT     0x2f

#define ESR_IL        U64_FROM_BIT(25)
#define ESR_ISS_BITS  25
#define ESR_ISS_SHIFT 0

#define ESR_ISS_INST_ABRT_SET_BITS   2
#define ESR_ISS_INST_ABRT_SET_SHIFT  11
#define ESR_ISS_INST_ABRT_SET_UER    0 /* recoverable */
#define ESR_ISS_INST_ABRT_SET_UC     2 /* uncontainable */
#define ESR_ISS_INST_ABRT_SET_UEO_CE 0 /* restartable / corrected */
/* XXX ... */

#define ESR_ISS_DATA_ABRT_ISV       U64_FROM_BIT(24) /* [23:14] valid */
#define ESR_ISS_DATA_ABRT_SAS_BITS  2 /* access size */
#define ESR_ISS_DATA_ABRT_SAS_SHIFT 22
#define ESR_ISS_DATA_ABRT_SSE       U64_FROM_BIT(21) /* syndrome sign extend */
#define ESR_ISS_DATA_ABRT_SRT_BITS  5 /* syndrome reg transfer */
#define ESR_ISS_DATA_ABRT_SRT_SHIFT 16
#define ESR_ISS_DATA_ABRT_SF        U64_FROM_BIT(15) /* 64-bit register */

/* ... */

#define ESR_ISS_DATA_ABRT_FnV        U64_FROM_BIT(10) /* FAR not valid */
#define ESR_ISS_DATA_ABRT_CM         U64_FROM_BIT(8) /* cache maintenance */
#define ESR_ISS_DATA_ABRT_WnR        U64_FROM_BIT(6) /* write not read */
#define ESR_ISS_DATA_ABRT_DFSC_BITS  6 /* data fault status code */
#define ESR_ISS_DATA_ABRT_DFSC_SHIFT 0


/* XXX move to gic.h */
#define ICC_CTLR_EL1_ExtRange      U64_FROM_BIT(19)
#define ICC_CTLR_EL1_RSS           U64_FROM_BIT(18)
#define ICC_CTLR_EL1_A3V           U64_FROM_BIT(15)
#define ICC_CTLR_EL1_SEIS          U64_FROM_BIT(14)
#define ICC_CTLR_EL1_IDbits_BITS   3
#define ICC_CTLR_EL1_IDbits_SHIFT  11
#define ICC_CTLR_EL1_IDbits_16     0
#define ICC_CTLR_EL1_IDbits_24     1
#define ICC_CTLR_EL1_PRIbits_BITS  3
#define ICC_CTLR_EL1_PRIbits_SHIFT 8
#define ICC_CTLR_EL1_EOImode       U64_FROM_BIT(1)
#define ICC_CTLR_EL1_CBPR          U64_FROM_BIT(0)

#define INTID_NO_PENDING 1023

/* GIC Distributor */
#define GICD_CTLR          (*(volatile u32 *)(dev_base_pointer(GIC_DIST)))
#define GICD_CTLR_DISABLE    0
#define GICD_CTLR_ENABLEGRP0 1
#define GICD_TYPER         (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0004))
#define GICD_ITLinesNumber_BITS  5
#define GICD_ITLinesNumber_SHIFT 0
#define GICD_IIDR          (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0008))
#define GICD_TYPER2        (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x000c))
#define GICD_STATUSR       (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0010))
#define GICD_SETSPI_NSR    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0040))
#define GICD_CLRSPI_NSR    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0048))
#define GICD_SETSPI_SR     (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0050))
#define GICD_CLRSPI_SR     (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0058))
#define GICD_IGROUPR(n)    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0080 + 4 * (n)))
#define GICD_ISENABLER(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0100 + 4 * (n)))
#define GICD_ICENABLER(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0180 + 4 * (n)))
#define GICD_INTS_PER_IENABLE_REG 32
#define GICD_ISPENDR(n)    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0200 + 4 * (n)))
#define GICD_ICPENDR(n)    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0280 + 4 * (n)))
#define GICD_INTS_PER_IPEND_REG 32
#define GICD_ISACTIVER(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0300 + 4 * (n)))
#define GICD_ICACTIVER(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0380 + 4 * (n)))
#define GICD_IPRIORITYR(n) (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0400 + 4 * (n)))
#define GICD_INTS_PER_IPRIORITY_REG 4
#define GICD_ITARGETSR(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0800 + 4 * (n)))
#define GICD_INTS_PER_ITARGET_REG 4
#define GICD_ICFGR(n)      (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0c00 + 4 * (n)))
#define GICD_INTS_PER_ICFG_REG 16
#define GICD_ICFGR_LEVEL 0
#define GICD_ICFGR_EDGE  1
#define GICD_IGRPMODR(n)   (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0d00 + 4 * (n)))
#define GICD_NSACR(n)      (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0e00 + 4 * (n)))
#define GICD_SGIR          (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f00))
#define GICD_CPENDSGIR(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f10 + 4 * (n)))
#define GICD_SPENDSGIR(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f20 + 4 * (n)))


#define switch_stack(s, target) ({ \
            register u64 __s = u64_from_pointer(s);                     \
            register u64 __t = u64_from_pointer(target);                \
            asm volatile("mov sp, %0; br %1" :: "r"(__s), "r"(__t)); })

static inline void enable_interrupts(void)
{
    asm volatile("msr daifclr, #2");
}

static inline void disable_interrupts(void)
{
    asm volatile("msr daifset, #2");
}

static inline u64 irq_disable_save(void)
{
    register u32 daif;
    asm volatile("mrs %0, daif; msr daifset, #2" : "=r"(daif));
    return daif;
}

static inline void irq_restore(u64 flags)
{
    asm volatile("msr daif, %0" :: "r"(flags));
}

static inline void wait_for_interrupt(void)
{
    asm volatile("dsb sy; wfi" ::: "memory");
}

#include <lock.h>

#define read_psr(reg) ({ register u64 r; asm volatile("mrs %0, " #reg : "=r"(r)); r;})
#define write_psr(reg, v) do { asm volatile("msr " #reg ", %0" : : "r"(v)); } while (0)

/* ridiculous */
#define read_psr_s(rstr) ({ register u64 r; asm volatile("mrs %0, " rstr : "=r"(r)); r;})
#define write_psr_s(rstr, v) do { asm volatile("msr " rstr ", %0" : : "r"(v)); } while (0)

// XXX kernel addr, also should return INVALID_PHYSICAL if PAR_EL1.F is set
#define physical_from_virtual(v) ({                                     \
            register u64 __r;                                           \
            register u64 __x = u64_from_pointer(v);                     \
            asm volatile("at S1E0R, %1; mrs %0, PAR_EL1" : "=r"(__r) : "r"(__x)); \
            (__r & (MASK(47) & ~MASK(12))) | (__x & MASK(12));})

/* per-cpu info, saved contexts and stacks */
typedef u64 *context;

#define KERNEL_STACK_WORDS (KERNEL_STACK_SIZE / sizeof(u64))
typedef struct kernel_context {
    u64 stackbase[KERNEL_STACK_WORDS];
    u64 frame[0];
} *kernel_context;

typedef struct cpuinfo {
    /*** Fields accessed by low-level entry points. ***/
    /* Don't move these without updating x18-relative accesses in crt0.s ***/

    /* This points to the frame of the current, running context. +0 */
    context running_frame;

    /* Default frame and stack installed at kernel entry points (init,
       syscall) and calls to runloop. +8 */
    kernel_context kernel_context;

    /* One temporary for syscall enter to use so that we don't need to touch the user stack. +16 */
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

//extern struct cpuinfo base_cpuinfo;
extern struct cpuinfo cpuinfos[];

static inline cpuinfo cpuinfo_from_id(int cpu)
{
    assert(cpu >= 0 && cpu < MAX_CPUS);
    return &cpuinfos[cpu];
}

static inline cpuinfo current_cpu(void)
{
    register u64 r;
    asm("mov %0, x18" : "=r"(r));
    return (cpuinfo)pointer_from_u64(r);
}

static inline u64 total_frame_size(void)
{
    // TODO extended save
    return FRAME_MAX * sizeof(u64);
}
