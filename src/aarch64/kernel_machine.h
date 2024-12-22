#if !(defined(KERNEL) || defined(BOOT))
#error must be in kernel or bootloader build
#endif

#define KERNEL_LIMIT     0xfffffffffffff000ull
#define KERNEL_BASE      0xffffffff80000000ull
#define DEVICE_BASE      0x00ffffff00000000ull

#define KERNEL_PHYS 0x0000000040400000ull /* must match linker script - XXX extern? */

#include <kernel_platform.h>

#define LINEAR_BACKED_LIMIT     0x00ffff0000000000ull
#define LINEAR_BACKED_BASE      0x00ff800000000000ull
#define LINEAR_BACKED_PHYSLIMIT 0x00007f0000000000ull
#define LINEAR_BACKED_PAGELOG   30
#define HUGE_PAGESIZE           0x100000000ull
#define KMEM_LIMIT              LINEAR_BACKED_BASE

#define STACK_ALIGNMENT     16

#define VIRTUAL_ADDRESS_BITS 48

#define CNTV_CTL_EL0_ISTATUS 4
#define CNTV_CTL_EL0_MASK    2
#define CNTV_CTL_EL0_ENABLE  1

#define CPACR_EL1_TTA            U64_FROM_BIT(28)
#define CPACR_EL1_FPEN_BITS      2
#define CPACR_EL1_FPEN_SHIFT     20
#define CPACR_EL1_FPEN_EL10_TRAP 0x0
#define CPACR_EL1_FPEN_EL0_TRAP  0x1
#define CPACR_EL1_FPEN_NO_TRAP   0x3

#define ESR_EC_BITS   6
#define ESR_EC_SHIFT  26

#define ESR_EC_UNKNOWN        0x00
#define ESR_EC_ILL_EXEC       0x0e
#define ESR_EC_SVC_AARCH64    0x15
#define ESR_EC_MSR_MRS        0x18
#define ESR_EC_INST_ABRT_LEL  0x20
#define ESR_EC_INST_ABRT      0x21
#define ESR_EC_PC_ALIGN_FAULT 0x22
#define ESR_EC_DATA_ABRT_LEL  0x24
#define ESR_EC_DATA_ABRT      0x25
#define ESR_EC_SP_ALIGN_FAULT 0x26
#define ESR_EC_SERROR_INT     0x2f
#define ESR_EC_SS             0x32
#define ESR_EC_BRK            0x3c

#define ESR_IL        U64_FROM_BIT(25)
#define ESR_ISS_BITS  25
#define ESR_ISS_SHIFT 0

#define ESR_ISS_IMM16_BITS  16
#define ESR_ISS_IMM16_SHIFT 0

#define ESR_ISS_INST_ABRT_SET_BITS   2
#define ESR_ISS_INST_ABRT_SET_SHIFT  11
#define ESR_ISS_INST_ABRT_SET_UER    0 /* recoverable */
#define ESR_ISS_INST_ABRT_SET_UC     2 /* uncontainable */
#define ESR_ISS_INST_ABRT_SET_UEO_CE 0 /* restartable / corrected */

#define ESR_ISS_DATA_ABRT_ISV       U64_FROM_BIT(24) /* [23:14] valid */
#define ESR_ISS_DATA_ABRT_SAS_BITS  2 /* access size */
#define ESR_ISS_DATA_ABRT_SAS_SHIFT 22
#define ESR_ISS_DATA_ABRT_SSE       U64_FROM_BIT(21) /* syndrome sign extend */
#define ESR_ISS_DATA_ABRT_SRT_BITS  5 /* syndrome reg transfer */
#define ESR_ISS_DATA_ABRT_SRT_SHIFT 16
#define ESR_ISS_DATA_ABRT_SF        U64_FROM_BIT(15) /* 64-bit register */


#define ESR_ISS_DATA_ABRT_FnV        U64_FROM_BIT(10) /* FAR not valid */
#define ESR_ISS_DATA_ABRT_CM         U64_FROM_BIT(8) /* cache maintenance */
#define ESR_ISS_DATA_ABRT_WnR        U64_FROM_BIT(6) /* write not read */

/* fault status code - most of these line up for both instruction and
   data faults... */
#define ESR_ISS_ID_ABRT_FSC_BITS  6
#define ESR_ISS_ID_ABRT_FSC_SHIFT 0

#define ESR_ISS_ID_ABRT_FSC_ADDRSIZE_L0        0x00
#define ESR_ISS_ID_ABRT_FSC_ADDRSIZE_L1        0x01
#define ESR_ISS_ID_ABRT_FSC_ADDRSIZE_L2        0x02
#define ESR_ISS_ID_ABRT_FSC_ADDRSIZE_L3        0x03
#define ESR_ISS_ID_ABRT_FSC_TRANSLATION_L0     0x04
#define ESR_ISS_ID_ABRT_FSC_TRANSLATION_L1     0x05
#define ESR_ISS_ID_ABRT_FSC_TRANSLATION_L2     0x06
#define ESR_ISS_ID_ABRT_FSC_TRANSLATION_L3     0x07
#define ESR_ISS_ID_ABRT_FSC_ACCESS_FLAG_L1     0x09
#define ESR_ISS_ID_ABRT_FSC_ACCESS_FLAG_L2     0x0a
#define ESR_ISS_ID_ABRT_FSC_ACCESS_FLAG_L3     0x0b
#define ESR_ISS_ID_ABRT_FSC_PERMISSION_L1      0x0d
#define ESR_ISS_ID_ABRT_FSC_PERMISSION_L2      0x0e
#define ESR_ISS_ID_ABRT_FSC_PERMISSION_L3      0x0f
#define ESR_ISS_ID_ABRT_FSC_SYNC_EXT_ABRT_NT   0x10
#define ESR_ISS_ID_ABRT_FSC_SYNC_EXT_ABRT_L0   0x14
#define ESR_ISS_ID_ABRT_FSC_SYNC_EXT_ABRT_L1   0x15
#define ESR_ISS_ID_ABRT_FSC_SYNC_EXT_ABRT_L2   0x16
#define ESR_ISS_ID_ABRT_FSC_SYNC_EXT_ABRT_L3   0x17
#define ESR_ISS_ID_ABRT_FSC_SYNC_PARITY_ECC_NT 0x18
#define ESR_ISS_ID_ABRT_FSC_SYNC_PARITY_ECC_L0 0x1c
#define ESR_ISS_ID_ABRT_FSC_SYNC_PARITY_ECC_L1 0x1d
#define ESR_ISS_ID_ABRT_FSC_SYNC_PARITY_ECC_L2 0x1e
#define ESR_ISS_ID_ABRT_FSC_SYNC_PARITY_ECC_L3 0x1f
#define ESR_ISS_ID_ABRT_FSC_TLB_CONFLICT_ABORT 0x30

#define ESR_ISS_SERROR_INT_IDS        0x1000000
#define ESR_ISS_SERROR_INT_IESB       0x2000
#define ESR_ISS_SERROR_INT_AET_BITS   3
#define ESR_ISS_SERROR_INT_AET_SHIFT  10
#define ESR_ISS_SERROR_INT_AET_UC     0
#define ESR_ISS_SERROR_INT_AET_UEU    1
#define ESR_ISS_SERROR_INT_AET_UEO    2
#define ESR_ISS_SERROR_INT_AET_UER    3
#define ESR_ISS_SERROR_INT_AET_CE     6
#define ESR_ISS_SERROR_INT_EA         0x200
#define ESR_ISS_SERROR_INT_DFSC_BITS  3
#define ESR_ISS_SERROR_INT_DFSC_SHIFT 10
#define ESR_ISS_SERROR_INT_DFSC_UNCAT 0
#define ESR_ISS_SERROR_INT_DFSC_ASYNC 0x11

#define ID_AA64ISAR0_EL1_ATOMIC_BITS        4
#define ID_AA64ISAR0_EL1_ATOMIC_SHIFT       20
#define ID_AA64ISAR0_EL1_ATOMIC_IMPLEMENTED 2

#define ID_AA64ISAR0_EL1_RNDR_BITS        4
#define ID_AA64ISAR0_EL1_RNDR_SHIFT       60
#define ID_AA64ISAR0_EL1_RNDR_IMPLEMENTED 1 /* RNDR, RNDRRS MSRs */

#define ID_AA64PFR0_EL1_GIC_BITS                4
#define ID_AA64PFR0_EL1_GIC_SHIFT               24
#define ID_AA64PFR0_EL1_GIC_GICC_SYSREG_NONE    0
#define ID_AA64PFR0_EL1_GIC_GICC_SYSREG_3_0_4_0 1
#define ID_AA64PFR0_EL1_GIC_GICC_SYSREG_4_1     3

#define MPIDR_AFF3(mpidr)   (((mpidr) >> 32) & 0xff)
#define MPIDR_AFF2(mpidr)   (((mpidr) >> 16) & 0xff)
#define MPIDR_AFF1(mpidr)   (((mpidr) >> 8) & 0xff)
#define MPIDR_AFF0(mpidr)   ((mpidr) & 0xff)
#define MPIDR_AFF_MASK      0xff00ffffffull /* Aff3 | Aff2 | Aff1 | Aff0 */

#define read_mpid()    (read_psr(MPIDR_EL1) & MPIDR_AFF_MASK)

#define SCTLR_EL1_UCI     U64_FROM_BIT(26) /* trap cache instructions in EL0 */
#define SCTLR_EL1_EE      U64_FROM_BIT(25) /* endianness for EL1 data / pt table */
#define SCTLR_EL1_E0E     U64_FROM_BIT(24) /* endianness for EL0 data */
#define SCTLR_EL1_SPAN    U64_FROM_BIT(23) /* Set Privileged Access Never */
#define SCTLR_EL1_EIS     U64_FROM_BIT(22) /* exception entry is context synchronizing */
#define SCTLR_EL1_WXN     U64_FROM_BIT(19) /* write implies execute never */
#define SCTLR_EL1_nTWE    U64_FROM_BIT(18) /* no trap on WFE */
#define SCTLR_EL1_nTWI    U64_FROM_BIT(16) /* no trap on WFI */
#define SCTLR_EL1_UCT     U64_FROM_BIT(15) /* no trap on CTR_EL0 access */
#define SCTLR_EL1_I       U64_FROM_BIT(12) /* instruction cacheability (no effect) */
#define SCTLR_EL1_CP15BEN U64_FROM_BIT(5) /* memory barrier enable from EL0 */
#define SCTLR_EL1_SA0     U64_FROM_BIT(4) /* SP alignment fault enable for EL0 */
#define SCTLR_EL1_SA      U64_FROM_BIT(3) /* SP alignment fault enable */
#define SCTLR_EL1_C       U64_FROM_BIT(2) /* cacheability (no effect) */
#define SCTLR_EL1_A       U64_FROM_BIT(1) /* alignment fault check enable */
#define SCTLR_EL1_M       U64_FROM_BIT(0) /* MMU enable */

#define SPSR_I U64_FROM_BIT(7)
#define SPSR_SS  U64_FROM_BIT(21)
#define SPSR_TCO U64_FROM_BIT(25)

#define MDSCR_EL1_SS    U64_FROM_BIT(0)     /* software step enable */

#define CNTKCTL_EL1_EL0VCTEN    U64_FROM_BIT(1) /* frequency and virtual counter register access */

#ifndef __ASSEMBLY__
/* interrupt control */
static inline void enable_interrupts(void)
{
    asm volatile("msr daifclr, #2");
}

static inline void disable_interrupts(void)
{
    asm volatile("msr daifset, #2");
}

static inline u64 irq_enable_save(void)
{
    register u64 daif;
    asm volatile("mrs %0, daif; msr daifclr, #2" : "=r"(daif));
    return daif;
}

static inline u64 irq_disable_save(void)
{
    register u64 daif;
    asm volatile("mrs %0, daif; msr daifset, #2" : "=r"(daif));
    return daif;
}

static inline void irq_restore(u64 flags)
{
    asm volatile("msr daif, %0" :: "r"(flags));
}

static inline void wait_for_interrupt(void)
{
    disable_interrupts();
    asm volatile("dsb sy; wfi" ::: "memory");
    enable_interrupts();
}

#define cmdline_consume(o, h)   (void)(h)
#define boot_params_apply(t)

/* device mmio region access */
#define MK_MMIO_READ(BITS, ISUFFIX, RPREFIX) \
    static inline u##BITS mmio_read_##BITS(u64 addr)                    \
    {                                                                   \
        u##BITS val;                                                    \
        asm volatile("ldr" ISUFFIX " %" RPREFIX "0, [%1]" : "=r"(val) : "r"(addr)); \
        return val;                                                     \
    }                                                                   \

MK_MMIO_READ(8, "b", "w");
MK_MMIO_READ(16, "h", "w");
MK_MMIO_READ(32, "", "w");
MK_MMIO_READ(64, "", "x");

#define MK_MMIO_WRITE(BITS, ISUFFIX, RPREFIX)                           \
    static inline void mmio_write_##BITS(u64 addr, u##BITS val)         \
    {                                                                   \
        asm volatile("str" ISUFFIX " %" RPREFIX "0, [%1]" :: "rZ"(val), "r"(addr)); \
    }

MK_MMIO_WRITE(8, "b", "w");
MK_MMIO_WRITE(16, "h", "w");
MK_MMIO_WRITE(32, "", "w");
MK_MMIO_WRITE(64, "", "x");

/* special register access */
#define read_psr(reg) ({ register u64 r; asm volatile("mrs %0, " #reg : "=r"(r)); r;})
#define write_psr(reg, v) do { asm volatile("msr " #reg ", %0" : : "r"((u64)(v))); } while (0)
#define read_psr_s(rstr) ({ register u64 r; asm volatile("mrs %0, " rstr : "=r"(r)); r;})
#define write_psr_s(rstr, v) do { asm volatile("msr " rstr ", %0" : : "r"((u64)(v))); } while (0)

struct cpuinfo_machine {
    /*** Fields accessed by low-level entry points. ***/
    /* Don't move these without updating x18-relative accesses in crt0.s ***/

    /* This points to the currently-running context and bottom of associated frame. +0 */
    context current_context;

    /*** End of fields touched by kernel entries ***/

    /* Next kernel context to install */
    context kernel_context;

    /* Next syscall context to install */
    context syscall_context;

    u64 gic_rdist_base; /* base (virtual) address of GICv3 redistributor */
    u64 gic_rdist_rdbase;   /* GIC ITS target address of redistributor */
};

typedef struct cpuinfo *cpuinfo;

extern struct uefi_boot_params boot_params;

static inline cpuinfo current_cpu(void)
{
    register u64 r;
    asm("mov %0, x18" : "=r"(r));
    return (cpuinfo)pointer_from_u64(r);
}

extern void clone_frame_pstate(context_frame dest, context_frame src);
extern void init_extended_frame(context_frame f);

static inline boolean is_pte_error(context_frame f)
{
    // arm equivalent?
    return false;
}

static inline u64 frame_fault_pc(context_frame f)
{
    return f[FRAME_ELR];
}

static inline u64 frame_fault_address(context_frame f)
{
    return f[FRAME_FAULT_ADDRESS];
}

#define esr_from_frame(frame) (frame[FRAME_ESR_SPSR] >> 32)

/* Maybe shift decoding to entry and encode in frame as flags? */
static inline u8 fsc_from_frame(context_frame f)
{
    u64 esr = esr_from_frame(f);
    u32 ec = field_from_u64(esr, ESR_EC);
    if (ec != ESR_EC_DATA_ABRT && ec != ESR_EC_DATA_ABRT_LEL &&
        ec != ESR_EC_INST_ABRT && ec != ESR_EC_INST_ABRT_LEL)
        return 0xff;
    return field_from_u64(field_from_u64(esr, ESR_ISS), ESR_ISS_ID_ABRT_FSC);
}

static inline boolean is_protection_fault(context_frame f)
{
    u8 fsc = fsc_from_frame(f);
    return (fsc != 0xff && fsc >= ESR_ISS_ID_ABRT_FSC_PERMISSION_L1 &&
            fsc <= ESR_ISS_ID_ABRT_FSC_PERMISSION_L3);
}

static inline boolean is_page_fault(context_frame f)
{
    u8 fsc = fsc_from_frame(f);
    return (fsc != 0xff && fsc >= ESR_ISS_ID_ABRT_FSC_TRANSLATION_L0 &&
            fsc <= ESR_ISS_ID_ABRT_FSC_PERMISSION_L3);
}

static inline boolean is_usermode_fault(context_frame f)
{
    return f[FRAME_EL] == 0;
}

static inline boolean is_instruction_fault(context_frame f)
{
    u32 ec = field_from_u64(esr_from_frame(f), ESR_EC);
    return (ec == ESR_EC_INST_ABRT || ec == ESR_EC_INST_ABRT_LEL);
}

static inline boolean is_data_fault(context_frame f)
{
    u32 ec = field_from_u64(esr_from_frame(f), ESR_EC);
    return (ec == ESR_EC_DATA_ABRT || ec == ESR_EC_DATA_ABRT_LEL);
}

static inline boolean is_write_fault(context_frame f)
{
    u64 esr = esr_from_frame(f);
    u32 ec = field_from_u64(esr, ESR_EC);
    u32 iss = field_from_u64(esr, ESR_ISS);

    return (ec == ESR_EC_DATA_ABRT || ec == ESR_EC_DATA_ABRT_LEL) &&
        (iss & ESR_ISS_DATA_ABRT_WnR);
}

static inline boolean is_div_by_zero(context_frame f)
{
    return false; // XXX not on arm / fp only?
}

static inline boolean is_breakpoint(context_frame f)
{
    u64 esr = esr_from_frame(f);
    u32 ec = field_from_u64(esr, ESR_EC);
    if (ec == ESR_EC_BRK)
        return true;
    return false;
}

static inline boolean is_trap(context_frame f)
{
    u64 esr = esr_from_frame(f);
    u32 ec = field_from_u64(esr, ESR_EC);
    return (ec == ESR_EC_SS) || (ec == ESR_EC_BRK);
}

static inline boolean is_illegal_instruction(context_frame f)
{
    u64 esr = esr_from_frame(f);
    u32 ec = field_from_u64(esr, ESR_EC);
    switch (ec) {
    case ESR_EC_UNKNOWN:
    case ESR_EC_MSR_MRS:
        return true;
    }
    return false;
}

static inline boolean frame_is_full(context_frame f)
{
    return f[FRAME_FULL];
}

static inline void *frame_extended(context_frame f)
{
    return pointer_from_u64(f[FRAME_EXTENDED]);
}

static inline void frame_enable_interrupts(context_frame f)
{
    f[FRAME_ESR_SPSR] &= ~SPSR_I; /* EL0 */
}

static inline void frame_disable_interrupts(context_frame f)
{
    f[FRAME_ESR_SPSR] |= SPSR_I; /* EL0 */
}

static inline void *frame_get_stack(context_frame f)
{
    return pointer_from_u64(f[FRAME_SP]);
}

static inline void frame_set_stack(context_frame f, u64 sp)
{
    f[FRAME_SP] = sp;
}

static inline void *frame_get_stack_top(context_frame f)
{
    return pointer_from_u64(f[FRAME_STACK_TOP]);
}

static inline void frame_set_stack_top(context_frame f, void *st)
{
    f[FRAME_STACK_TOP] = u64_from_pointer(st);
}

static inline void frame_reset_stack(context_frame f)
{
    f[FRAME_SP] = f[FRAME_STACK_TOP];
}

static inline void frame_set_insn_ptr(context_frame f, u64 ip)
{
    f[FRAME_ELR] = ip;
}

static inline void frame_enable_stepping(context_frame f)
{
    f[FRAME_ESR_SPSR] |= SPSR_SS;
    write_psr(MDSCR_EL1, read_psr(MDSCR_EL1) | MDSCR_EL1_SS);
}

static inline void frame_disable_stepping(context_frame f)
{
    write_psr(MDSCR_EL1, read_psr(MDSCR_EL1) & ~MDSCR_EL1_SS);
}

static inline boolean validate_frame_ptr(u64 *fp)
{
    if (!validate_virtual(fp, sizeof(u64)) ||
        !validate_virtual(fp + 1, sizeof(u64)))
        return false;
    return true;
}

static inline u64 *get_frame_ra_ptr(u64 *fp, u64 **nfp)
{
    u64 *rap = fp + 1;
    *nfp = pointer_from_u64(fp[0]);
    return rap;
}

static inline u64 *get_current_fp(void)
{
    u64 fp;
    asm("mov %0, x29" : "=r" (fp));
    return pointer_from_u64(fp);
}

#define _switch_stack_head(s, target)                                   \
    register u64 __s = u64_from_pointer(s);                             \
    register u64 __t = u64_from_pointer(target)

#define _switch_stack_tail(...)                                         \
    asm volatile("mov sp, %0; br %1" :: "r"(__s), "r"(__t), ##__VA_ARGS__ : "memory")

#define _switch_stack_args_1(__a0)              \
    register u64 __ra0 asm("x0") = (u64)(__a0);
#define _switch_stack_args_2(__a0, __a1)                \
    _switch_stack_args_1(__a0);                         \
    register u64 __ra1 asm("x1") = (u64)(__a1);
#define _switch_stack_args_3(__a0, __a1, __a2)          \
    _switch_stack_args_2(__a0, __a1);                   \
    register u64 __ra2 asm("x2") = (u64)(__a2);
#define _switch_stack_args_4(__a0, __a1, __a2, __a3)    \
    _switch_stack_args_3(__a0, __a1, __a2);             \
    register u64 __ra3 asm("x3") = (u64)(__a3);
#define _switch_stack_args_5(__a0, __a1, __a2, __a3, __a4)     \
    _switch_stack_args_4(__a0, __a1, __a2, __a3);              \
    register u64 __ra4 asm("x4") = (u64)(__a4);

#define switch_stack(s, target) _switch_stack_head(s, target); _switch_stack_tail()
#define switch_stack_1(s, target, __a0) do {                   \
    _switch_stack_head(s, target); _switch_stack_args_1(__a0); \
    _switch_stack_tail("r"(__ra0)); } while(0)
#define switch_stack_2(s, target, __a0, __a1) do {                      \
    _switch_stack_head(s, target); _switch_stack_args_2(__a0, __a1);    \
    _switch_stack_tail("r"(__ra0), "r"(__ra1)); } while(0)
#define switch_stack_3(s, target, __a0, __a1, __a2) do {                \
    _switch_stack_head(s, target); _switch_stack_args_3(__a0, __a1, __a2); \
    _switch_stack_tail("r"(__ra0), "r"(__ra1), "r"(__ra2)); } while(0)
#define switch_stack_4(s, target, __a0, __a1, __a2, __a3) do {          \
    _switch_stack_head(s, target); _switch_stack_args_4(__a0, __a1, __a2, __a3); \
    _switch_stack_tail("r"(__ra0), "r"(__ra1), "r"(__ra2), "r"(__ra3)); } while(0)
#define switch_stack_5(s, target, __a0, __a1, __a2, __a3, __a4) do {    \
    _switch_stack_head(s, target); _switch_stack_args_5(__a0, __a1, __a2, __a3, __a4); \
    _switch_stack_tail("r"(__ra0), "r"(__ra1), "r"(__ra2), "r"(__ra3), "r"(__ra4)); } while(0)

static inline void jump_to_offset(u64 offset) {
    asm("adr x9, target\n"
        "add x9, x9, %0\n"
        "br x9\n"
        "target:":: "r"(offset) : "x9");
}

/* adds an offset to the return address of the current function */
static inline void return_offset(u64 offset) {
    asm("ldr x9, [fp, #8]\n"
        "add x9, x9, %0\n"
        "str x9, [fp, #8]" :: "r"(offset) : "x9", "memory");
}

/* syscall entry */
#define init_syscall_handler()   /* stub */

/* for vdso */
#define do_syscall(sysnr, arg0, arg1) ({                                \
            sysreturn rv;                                               \
            register u64 _v asm ("x8") = sysnr;                         \
            register u64 _x0 asm ("x0") = (u64)arg0;                    \
            register u64 _x1 asm ("x1") = (u64)arg1;                    \
            asm ("svc 0" : "=r" (_x0) : "r" (_v),                       \
                "r" (_x0), "r" (_x1) : "memory");                       \
            rv = _x0;                                                   \
            rv;                                                         \
        })

/* IPI */
static inline void machine_halt(void)
{
    extern void gic_percpu_disable(void);
    gic_percpu_disable();
    __asm__("wfi");
}

u64 allocate_msi_interrupt(void);
void deallocate_msi_interrupt(u64 v);
u64 allocate_mmio_interrupt(void);
void deallocate_mmio_interrupt(u64 v);

vector cpus_init_ids(heap h);
u64 mpid_from_cpuid(int id);

void aarch64_cpu_init(void);

struct arm_hvc_ret {
    u64 x0, x1;
    /* return values in registers x2 to x17 are not supported */
};
struct arm_hvc_full_ret {
    u64 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17;
};

/* can be used with up to 8 arguments (registers x0 to x7) */
struct arm_hvc_ret arm_hvc(u64 x0, ...);
struct arm_hvc_full_ret arm_hvc_full(u64 x0, ...);

void angel_shutdown(u64 x0);
void psci_shutdown(void);
void psci_reset(void);

void kaslr_fixup_rtc(void);

void pci_platform_set_ecam(u64 ecam_base);

#endif /* __ASSEMBLY__ */
