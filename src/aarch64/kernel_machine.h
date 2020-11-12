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

#define VIRTUAL_ADDRESS_BITS 48

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

#define ESR_EC_UNKNOWN        0x00
#define ESR_EC_ILL_EXEC       0x0e
#define ESR_EC_SVC_AARCH64    0x15
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

#define SPSR_I U64_FROM_BIT(7)

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

#define vpzero(__v, __p, __y) zero(pointer_from_u64(__v), __y)

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
            asm volatile("at S1E1R, %1; mrs %0, PAR_EL1" : "=r"(__r) : "r"(__x)); \
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
    queue thread_queue;
    timestamp last_timer_update;
    u64 frcount;

    /* The following fields are used rarely or only on initialization. */

    /* Stack for exceptions (which may occur in interrupt handlers) */
    void *exception_stack; // XXX vestige?

    /* Stack for interrupts */
    void *int_stack;

    /* Generation number for invalidates */
    word inval_gen;

#ifdef CONFIG_FTRACE
    int graph_idx;
    struct ftrace_graph_entry * graph_stack;
#endif
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

#define init_syscall_handler()   /* stub */

static inline u64 total_frame_size(void)
{
    return FRAME_EXTENDED_SAVE * sizeof(u64);
}

static inline void wait_for_interrupt(void)
{
    disable_interrupts();
    asm volatile("dsb sy; wfi" ::: "memory");
    enable_interrupts();
}

static inline boolean is_pte_error(context f)
{
    // arm equivalent?
    return false;
}

static inline u64 frame_return_address(context f)
{
    return f[FRAME_X30];
}

static inline void frame_set_sp(context f, u64 sp)
{
    f[FRAME_SP] = sp;
}

static inline u64 fault_address(context f)
{
    // store in frame?
    register u64 far;
    asm("mrs %0, FAR_EL1" : "=r"(far));
    return far;
}

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

// XXX make generic
static inline u64 xsave_frame_size(void)
{
    return 512;
}

// XXX
#define esr_from_frame(frame) (frame[FRAME_ESR_SPSR] >> 32)

/* Maybe shift decoding to entry and encode in frame as flags? */
static inline u8 fsc_from_frame(context f)
{
    u64 esr = esr_from_frame(f);
    u32 ec = field_from_u64(esr, ESR_EC);
    if (ec != ESR_EC_DATA_ABRT && ec != ESR_EC_DATA_ABRT_LEL &&
        ec != ESR_EC_INST_ABRT && ec != ESR_EC_INST_ABRT_LEL)
        return 0xff;
    return field_from_u64(field_from_u64(esr, ESR_ISS), ESR_ISS_ID_ABRT_FSC);
}

static inline boolean is_protection_fault(context f)
{
    u8 fsc = fsc_from_frame(f);
    return (fsc != 0xff && fsc >= ESR_ISS_ID_ABRT_FSC_PERMISSION_L1 &&
            fsc <= ESR_ISS_ID_ABRT_FSC_PERMISSION_L3);
}

static inline boolean is_page_fault(context f)
{
    u8 fsc = fsc_from_frame(f);
    return (fsc != 0xff && fsc >= ESR_ISS_ID_ABRT_FSC_TRANSLATION_L0 &&
            fsc <= ESR_ISS_ID_ABRT_FSC_TRANSLATION_L3);
}

static inline boolean is_usermode_fault(context f)
{
    return f[FRAME_EL] == 0;
}

static inline boolean is_instruction_fault(context f)
{
    u32 ec = field_from_u64(esr_from_frame(f), ESR_EC);
    return (ec == ESR_EC_INST_ABRT || ec == ESR_EC_INST_ABRT_LEL);
}

static inline boolean is_data_fault(context f)
{
    u32 ec = field_from_u64(esr_from_frame(f), ESR_EC);
    return (ec == ESR_EC_DATA_ABRT || ec == ESR_EC_DATA_ABRT_LEL);
}

static inline boolean is_write_fault(context f)
{
    u64 esr = esr_from_frame(f);
    u32 ec = field_from_u64(esr, ESR_EC);
    u32 iss = field_from_u64(esr, ESR_ISS);

    return (ec == ESR_EC_DATA_ABRT || ec == ESR_EC_DATA_ABRT_LEL) &&
        (iss & ESR_ISS_DATA_ABRT_WnR);
}

static inline boolean is_div_by_zero(context f)
{
    return false; // XXX not on arm / fp only?
}

static inline void frame_save_tls(context f)
{
    f[FRAME_TPIDR_EL0] = read_psr(TPIDR_EL0);
}

static inline void frame_restore_tls(context f)
{
    write_psr(TPIDR_EL0, f[FRAME_TPIDR_EL0]);
}