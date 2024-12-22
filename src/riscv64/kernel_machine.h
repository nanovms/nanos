#ifndef KERNEL
#error must be in kernel build
#endif

#define KERNEL_LIMIT     0xfffffffffffff000ull
#define KERNEL_BASE      0xffffffff80000000ull
#define DEVICE_BASE      0xffffffff00000000ull

#define KERNEL_PHYS 0x80200000ULL /* must match linker script - XXX extern? */

#include <kernel_platform.h>

#define LINEAR_BACKED_LIMIT     0xffffffff00000000ull
#define LINEAR_BACKED_BASE      0xffffc00000000000ull
#define LINEAR_BACKED_PHYSLIMIT 0x00003fff00000000ull
#define LINEAR_BACKED_PAGELOG   30
#define HUGE_PAGESIZE           0x100000000ull
#define KMEM_LIMIT              LINEAR_BACKED_BASE

#define STACK_ALIGNMENT     16

#define TRAP_STACK_SIZE     PAGESIZE

#define VIRTUAL_ADDRESS_BITS 48

#define SCAUSE_INTERRUPT_BIT 63
#define SCAUSE_INTERRUPT(x) ((x)>>SCAUSE_INTERRUPT_BIT)
#define SCAUSE_CODE(x)       ((x)&~U64_FROM_BIT(SCAUSE_INTERRUPT_BIT))

#define TRAP_E_INST_ALIGN    0
#define TRAP_E_INST_ACCESS   1
#define TRAP_E_ILLEGAL_INST  2
#define TRAP_E_BREAKPOINT    3
#define TRAP_E_LOAD_ALIGN    4
#define TRAP_E_LOAD_ACCESS   5
#define TRAP_E_STORE_ALIGN   6
#define TRAP_E_STORE_ACCESS  7
#define TRAP_E_ECALL_UMODE   8
#define TRAP_E_ECALL_SMODE   9    
#define TRAP_E_IPAGE_FAULT   12
#define TRAP_E_LPAGE_FAULT   13
#define TRAP_E_SPAGE_FAULT   15

#define TRAP_I_USOFT        0
#define TRAP_I_SSOFT        1
#define TRAP_I_MSOFT        3
#define TRAP_I_UTIMER       4
#define TRAP_I_STIMER       5
#define TRAP_I_MTIMER       7
#define TRAP_I_UEXT         8
#define TRAP_I_SEXT         9
#define TRAP_I_MEXT         11

#define STATUS_BIT_SD       63
#define STATUS_BIT_FS       13

#define STATUS_SIE          U64_FROM_BIT(1)
#define STATUS_MIE          U64_FROM_BIT(3)
#define STATUS_SPIE         U64_FROM_BIT(5)
#define STATUS_MPIE         U64_FROM_BIT(7)
#define STATUS_SPP          U64_FROM_BIT(8)
#define STATUS_MPP          U64_FROM_BIT(11)
#define STATUS_FS           U64_FROM_BIT(STATUS_BIT_FS)
#define STATUS_XS           U64_FROM_BIT(15)
#define STATUS_MPRV         U64_FROM_BIT(17)
#define STATUS_SUM          U64_FROM_BIT(18)
#define STATUS_MXR          U64_FROM_BIT(19)
#define STATUS_SD           U64_FROM_BIT(STATUS_BIT_SD)

#define FS_MASK             0x3
#define FS_OFF              0
#define FS_INITIAL          1
#define FS_CLEAN            2
#define FS_DIRTY            3

#define SSIP                1
#define MSIP                3
#define STIP                5
#define MTIP                7
#define SEIP                9
#define MEIP                11
#define SI_SSIP             U64_FROM_BIT(SSIP)
#define SI_MSIP             U64_FROM_BIT(MSIP)
#define SI_STIP             U64_FROM_BIT(STIP)
#define SI_MTIP             U64_FROM_BIT(MTIP)
#define SI_SEIP             U64_FROM_BIT(SEIP)
#define SI_MEIP             U64_FROM_BIT(MEIP)

#define SR_FS 0x00006000
#define CSR_STATUS 0x100
#define CSR_IE 0x104
#define CSR_IP 0x144

#define MSIP_BASE(hartid) (mmio_base_addr(CLINT) + ((hartid) * 0x4))

#ifndef __ASSEMBLY__
/* interrupt control */
static inline void enable_interrupts(void)
{
    u64 mask = STATUS_SIE;
    asm volatile("csrs sstatus, %0" :: "r"(mask));
}

static inline void disable_interrupts(void)
{
    u64 mask = STATUS_SIE;
    asm volatile("csrc sstatus, %0" :: "r"(mask));
}

static inline u64 irq_enable_save(void)
{
    register u64 status;
    asm volatile("csrr %0, sstatus" : "=r"(status));
    enable_interrupts();
    return status & STATUS_SIE;
}

static inline u64 irq_disable_save(void)
{
    register u64 status;
    asm volatile("csrr %0, sstatus" : "=r"(status));
    disable_interrupts();
    return status & STATUS_SIE;
}

static inline void irq_restore(u64 flags)
{
    asm volatile("csrs sstatus, %0" :: "r"(flags));
}

static inline void wait_for_interrupt(void)
{
    enable_interrupts();
    asm volatile("wfi" ::: "memory");
    disable_interrupts();
}

#define cmdline_consume(o, h)   (void)(h)
#define boot_params_apply(t)

/* device mmio region access */
#define MK_MMIO_READ(BITS, ISUFFIX) \
    static inline u##BITS mmio_read_##BITS(u64 addr)                    \
    {                                                                   \
        u##BITS val;                                                    \
        asm volatile("l" ISUFFIX " %0, (%1)" : "=r"(val) : "r"(addr)); \
        return val;                                                     \
    }                                                                   \

MK_MMIO_READ(8, "bu");
MK_MMIO_READ(16, "hu");
MK_MMIO_READ(32, "wu");
MK_MMIO_READ(64, "d");

#define MK_MMIO_WRITE(BITS, ISUFFIX) \
    static inline void mmio_write_##BITS(u64 addr, u##BITS val)         \
    {                                                                   \
        asm volatile("s" ISUFFIX " %0, (%1)" :: "r"(val), "r"(addr)); \
    }

MK_MMIO_WRITE(8, "b");
MK_MMIO_WRITE(16, "h");
MK_MMIO_WRITE(32, "w");
MK_MMIO_WRITE(64, "d");

struct cpuinfo_machine {
    /*** Fields accessed by low-level entry points. ***/
    /* Don't move these without updating tp-relative accesses in crt0.s ***/

    /* This points to the frame of the current, running context. +0 */
    context current_context;
    u64 scratch;                    /* scratch to get handler going +8 */ 
    void *tstack_top;               /* top of stack for trap handler +16 */
    u64 hartid;                     /* hardware thread ID as reported by SBI +24 */

    /*** End of fields touched by kernel entries ***/

    /* Next kernel context to install */
    context kernel_context;

    /* Next syscall context to install */
    context syscall_context;

    u64 ipi_mask;
};

typedef struct cpuinfo *cpuinfo;

static inline cpuinfo current_cpu(void)
{
    register u64 r;
    asm volatile("mv %0, tp" : "=r"(r));
    return (cpuinfo)pointer_from_u64(r);
}

extern void clone_frame_pstate(context_frame dest, context_frame src);

#define insn_emulate(f) false

static inline boolean is_pte_error(context_frame f)
{
    // riscv equivalent?
    return false;
}

static inline u64 frame_fault_pc(context_frame f)
{
    return f[FRAME_PC];
}

static inline u64 frame_fault_address(context_frame f)
{
    return f[FRAME_FAULT_ADDRESS];
}

boolean is_protection_fault(context_frame f); // requires pt walk

static inline boolean is_page_fault(context_frame f)
{
    u64 cause = SCAUSE_CODE(f[FRAME_CAUSE]); 
    return cause == TRAP_E_IPAGE_FAULT || cause == TRAP_E_LPAGE_FAULT ||
        cause == TRAP_E_SPAGE_FAULT;
}

static inline boolean is_usermode_fault(context_frame f)
{
    return (f[FRAME_STATUS]&STATUS_SPP) == 0;
}

static inline boolean is_instruction_fault(context_frame f)
{
    return SCAUSE_CODE(f[FRAME_CAUSE]) == TRAP_E_IPAGE_FAULT;
}

static inline boolean is_data_fault(context_frame f)
{
    return !is_instruction_fault(f);
}

static inline boolean is_write_fault(context_frame f)
{
    return SCAUSE_CODE(f[FRAME_CAUSE]) == TRAP_E_SPAGE_FAULT;
}

static inline boolean is_div_by_zero(context_frame f)
{
    return false; // riscv has no div by zero exception, software must check
}

static inline boolean is_breakpoint(context_frame f)
{
    return SCAUSE_CODE(f[FRAME_CAUSE]) == TRAP_E_BREAKPOINT;
}

static inline boolean is_trap(context_frame f)
{
    return is_breakpoint(f);
}

static inline boolean is_illegal_instruction(context_frame f)
{
    return SCAUSE_CODE(f[FRAME_CAUSE]) == TRAP_E_ILLEGAL_INST;
}

static inline boolean frame_is_full(context_frame f)
{
    return *(volatile u64 *)&f[FRAME_FULL];
}

static inline void *frame_extended(context_frame f)
{
    return pointer_from_u64(f[FRAME_EXTENDED]);
}

static inline void frame_enable_interrupts(context_frame f)
{
    f[FRAME_STATUS] |= STATUS_SPIE;
}

static inline void frame_disable_interrupts(context_frame f)
{
    f[FRAME_STATUS] &= ~STATUS_SPIE;
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
    f[FRAME_PC] = ip;
}

static inline void frame_enable_stepping(context_frame f)
{
}

static inline void frame_disable_stepping(context_frame f)
{
}

static inline boolean validate_frame_ptr(u64 *fp)
{
    if (!validate_virtual(fp - 1, sizeof(u64)) ||
        !validate_virtual(fp - 2, sizeof(u64)))
        return false;
    return true;
}

static inline u64 *get_frame_ra_ptr(u64 *fp, u64 **nfp)
{
    u64 *rap = fp - 1;
    *nfp = pointer_from_u64(fp[-2]);
    return rap;
}

static inline u64 *get_current_fp(void)
{
    u64 fp;
    asm("mv %0, fp" : "=r" (fp));
    return pointer_from_u64(fp);
}

#define _switch_stack_head(s, target)                                   \
    register u64 __s = u64_from_pointer(s);                             \
    register u64 __t = u64_from_pointer(target)

#define _switch_stack_tail(...)                                         \
    asm volatile("mv sp, %0; jr %1" :: "r"(__s), "r"(__t), ##__VA_ARGS__ : "memory")

#define _switch_stack_args_1(__a0)              \
    register u64 __ra0 asm("a0") = (u64)(__a0);
#define _switch_stack_args_2(__a0, __a1)                \
    _switch_stack_args_1(__a0);                         \
    register u64 __ra1 asm("a1") = (u64)(__a1);
#define _switch_stack_args_3(__a0, __a1, __a2)          \
    _switch_stack_args_2(__a0, __a1);                   \
    register u64 __ra2 asm("a2") = (u64)(__a2);
#define _switch_stack_args_4(__a0, __a1, __a2, __a3)    \
    _switch_stack_args_3(__a0, __a1, __a2);             \
    register u64 __ra3 asm("a3") = (u64)(__a3);
#define _switch_stack_args_5(__a0, __a1, __a2, __a3, __a4)     \
    _switch_stack_args_4(__a0, __a1, __a2, __a3);              \
    register u64 __ra4 asm("a4") = (u64)(__a4);

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
    asm("la t0, target\n"
        "add t0, t0, %0\n"
        "jr t0\n"
        "target:":: "r"(offset) : "t0");
}

/* adds an offset to the return address of the current function */
static inline void return_offset(u64 offset) {
    asm("ld t0, -8(fp)\n"
        "add t0, t0, %0\n"
        "sd t0, -8(fp)" :: "r"(offset) : "t0", "memory");
}

/* syscall entry */
#define init_syscall_handler()   /* stub */

/* for vdso */
#define do_syscall(sysnr, arg0, arg1) ({                                \
            sysreturn rv;                                               \
            register u64 _v asm ("a7") = sysnr;                         \
            register u64 _a0 asm ("a0") = (u64)arg0;                    \
            register u64 _a1 asm ("a1") = (u64)arg1;                    \
            asm ("ecall" : "=r" (_a0) : "r" (_v),                       \
                "r" (_a0), "r" (_a1) : "memory");                       \
            rv = _a0;                                                   \
            rv;                                                         \
        })
/* IPI */
static inline void machine_halt(void)
{
    extern void plic_set_threshold(u64 hartid, u32 thresh);
    plic_set_threshold(((struct cpuinfo_machine *)current_cpu())->hartid, 1);   /* mask all interrupts */
    enable_interrupts();    /* so that any interrupts already pending can be cleared */
    while (1)
        __asm__("wfi");
}

u64 allocate_msi_interrupt(void);
void deallocate_msi_interrupt(u64 v);
u64 allocate_mmio_interrupt(void);
void deallocate_mmio_interrupt(u64 v);

/* This is a simplified SEE ecall interface since we only use timer */
static inline void supervisor_ecall_1(int type, u64 arg)
{
    asm volatile("li a7, %0; mv a0, %1; ecall" :: "I"(type), "r"(arg) : "a0", "a7");
}

struct sbiret {
    u64 error;
    u64 value;
};

static inline struct sbiret supervisor_ecall(u64 type, u64 func, u64 arg0, u64 arg1, u64 arg2,
                                             u64 arg3, u64 arg4, u64 arg5)
{
    struct sbiret ret;
    register u64 a0 asm("a0") = arg0;
    register u64 a1 asm("a1") = arg1;
    register u64 a2 asm("a2") = arg2;
    register u64 a3 asm("a3") = arg3;
    register u64 a4 asm("a4") = arg4;
    register u64 a5 asm("a5") = arg5;
    register u64 a6 asm("a6") = func;
    register u64 a7 asm("a7") = type;
    asm volatile("ecall" : "+r"(a0), "+r"(a1) :
                 "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7) : "memory");
    ret.error = a0;
    ret.value = a1;
    return ret;
}

#endif /* !__ASSEMBLY__ */
