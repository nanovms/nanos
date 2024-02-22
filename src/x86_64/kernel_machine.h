#if !(defined(KERNEL) || defined(BOOT))
#error must be in kernel or bootloader build
#endif

#define MBR_ADDRESS 0x7c00

/*
  bit  47    - kern / user, extended for canonical
  bit  46    - set if directly-mapped (tag area must be zero)
  bits 45:38 - tag
 */

#define KERNEL_BASE             0xffffffff80000000ull
#define KERNEL_LIMIT            0xfffffffffffff000ull // XXX ? klibs
#define KMEM_LIMIT              0xffffbfff00000000ull
#define LINEAR_BACKED_LIMIT     0xffffffff00000000ull
#define LINEAR_BACKED_BASE      0xffffc00000000000ull
#define LINEAR_BACKED_PHYSLIMIT 0x00003fff00000000ull
#define LINEAR_BACKED_PAGELOG   30
#define HUGE_PAGESIZE           0x100000000ull

#define KERNEL_BASE_PHYS    0x00200000ul
#define STACK_ALIGNMENT     16

#define VIRTUAL_ADDRESS_BITS 48

#define KERNEL_CODE_SELECTOR 0x08
#define USER_CODE32_SELECTOR 0x18
#define USER_DATA_SELECTOR   0x20

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
#define TSC_AUX_MSR      0xc0000103

#define SEV_STATUS_MSR   0xc0010131
#define SEV_ENABLED      (1 << 0)

#define C0_MP   0x00000002
#define C0_EM   0x00000004
#define C0_WP   0x00010000

#define CR4_PAE         (1 << 5)
#define CR4_PGE         (1 << 7)
#define CR4_OSFXSR      (1 << 9)
#define CR4_OSXMMEXCPT  (1 << 10)
#define CR4_UMIP        (1 << 11)
#define CR4_FSGSBASE    (1 << 16)
#define CR4_OSXSAVE     (1 << 18)
#define CR4_SMEP        (1 << 20)

#define EFLAG_CARRY                     0
#define EFLAG_FIXED                     1
#define EFLAG_PARITY                    2
#define EFLAG_AUX_CARRY                 4
#define EFLAG_ZERO                      6
#define EFLAG_SIGN                      7
#define EFLAG_TRAP                      8
#define EFLAG_INTERRUPT                 9
#define EFLAG_DIRECTION                 10
#define EFLAG_OVERFLOW                  11
#define EFLAG_IOPL                      12
#define EFLAG_NESTED_TASK               14
#define EFLAG_RESUME                    16
#define EFLAG_VIRTUAL_MODE              17
#define EFLAG_ALIGN_CHECK               18
#define EFLAG_VIRTUAL_INTERRUPT         19
#define EFLAG_VIRTUAL_INTERRUPT_PENDING 20
#define EFLAG_CPUID_DETECT              21

#define SAFE_EFLAGS \
    (U64_FROM_BIT(EFLAG_ALIGN_CHECK) | \
     U64_FROM_BIT(EFLAG_OVERFLOW) | \
     U64_FROM_BIT(EFLAG_DIRECTION) | \
     U64_FROM_BIT(EFLAG_TRAP) | \
     U64_FROM_BIT(EFLAG_SIGN) | \
     U64_FROM_BIT(EFLAG_ZERO) | \
     U64_FROM_BIT(EFLAG_AUX_CARRY) | \
     U64_FROM_BIT(EFLAG_PARITY) | \
     U64_FROM_BIT(EFLAG_CARRY) | \
     U64_FROM_BIT(EFLAG_RESUME))

#define TSS_SIZE 0x68

struct cpuinfo_machine;

/* AP boot page */
#define AP_BOOT_START   0x00000000
#define AP_BOOT_END (AP_BOOT_START + PAGESIZE)

/* interrupt control */
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
    asm volatile("pushfd; popl %0" : "=r"(out) :: "memory");
    return out;
}

static inline u64 read_flags(void)
{
    u64 out;
    asm volatile("pushfq; popq %0" : "=r"(out) :: "memory");
    return out;
}

static inline u64 irq_disable_save(void)
{
    u64 flags = read_flags();
    disable_interrupts();
    return flags;
}

static inline u64 irq_enable_save(void)
{
    u64 flags = read_flags();
    enable_interrupts();
    return flags;
}

static inline void irq_restore(u64 flags)
{
    asm volatile("push %0; popf" :: "g"(flags) : "memory", "cc");
}

static inline void wait_for_interrupt(void)
{
    asm volatile("sti; hlt" ::: "memory");
}

void triple_fault(void) __attribute__((noreturn));
void start_cpu(int index);
void allocate_apboot(heap stackheap, void (*ap_entry)());
void deallocate_apboot(heap stackheap);
void install_idt(void);
void init_cpu_features();

#define IST_EXCEPTION 1
#define IST_INTERRUPT 2

void set_ist(struct cpuinfo_machine *cpu, int i, u64 sp);
void install_gdt64_and_tss(void *tss_desc, void *tss, void *gdt, void *gdt_pointer);

#ifdef KERNEL
/* locking constructs */
#include <mutex.h>

void cmdline_consume(sstring opt_name, cmdline_handler h);
void boot_params_apply(tuple t);
#endif

/* device mmio region access */
static inline u32 mmio_read_32(u64 addr)
{
    u32 val;
    asm volatile("movl %1, %0" : "=r"(val) :
                 "m"(*(volatile u32 *)pointer_from_u64(addr)));
    return val;
}

static inline u64 mmio_read_64(u64 addr)
{
    u64 val;
    asm volatile("movq %1, %0" : "=r"(val) :
                 "m"(*(volatile u64 *)pointer_from_u64(addr)));
    return val;
}

static inline void mmio_write_32(u64 addr, u32 val)
{
    asm volatile("movl %0, %1" :: "r"(val),
                 "m"(*(volatile u64 *)pointer_from_u64(addr)));
}

static inline void mmio_write_64(u64 addr, u64 val)
{
    asm volatile("movq %0, %1" :: "r"(val),
                 "m"(*(volatile u64 *)pointer_from_u64(addr)));
}

/* special register access */
extern u64 read_msr(u64);
extern void write_msr(u64, u64);
extern u64 read_xmsr(u64);
extern void write_xmsr(u64, u64);

#define mov_to_cr(__x, __y) asm volatile("mov %0,%%"__x : : "a"(__y) : "memory");
#define mov_from_cr(__x, __y) asm volatile("mov %%"__x", %0" : "=a"(__y) : : "memory");

/* CPUID level 1 (EDX) */
#define CPUID_PAT   (1 << 16)

/* CPUID level 7 (EBX) */
#define CPUID_FSGSBASE  (1 << 0)

/* Extended processor info and feature bits */
#define CPUID_FN_EXT_PROC_INFO  0x80000001
/* EDX */
#define CPUID_PDPE1GB           (1 << 26)

/* Encrypted memory capabilities */
#define CPUID_FN_ENCR_MEM   0x8000001f
/* EAX */
#define CPUID_SEV           (1 << 1)
/* EBX */
#define CPUID_SME_C_BIT(v)  ((v) & 0x3f)

static inline void cpuid(u32 fn, u32 ecx, u32 * v)
{
    asm volatile("cpuid" : "=a" (v[0]), "=b" (v[1]), "=c" (v[2]), "=d" (v[3]) : "0" (fn), "2" (ecx));
}

static inline u32 cpuid_highest_fn(boolean extended)
{
    u32 v[4];
    cpuid(extended ? 0x80000000 : 0, 0, v);
    return v[0];
}

static inline void xsetbv(u32 ecx, u32 eax, u32 edx)
{
    asm volatile("xsetbv" : : "a" (eax), "d" (edx), "c" (ecx));
}

static inline void xgetbv(u32 ecx, u32 *eax, u32 *edx)
{
    asm volatile("xgetbv" : "=a" (*eax), "=d" (*edx) : "c" (ecx));
}

/* syscall entry */

static inline void set_syscall_handler(void *syscall_entry)
{
    write_msr(LSTAR_MSR, u64_from_pointer(syscall_entry));
    u32 selectors = ((USER_CODE32_SELECTOR | 0x3) << 16) | KERNEL_CODE_SELECTOR;
    write_msr(STAR_MSR, (u64)selectors << 32);
    write_msr(SFMASK_MSR, U64_FROM_BIT(EFLAG_INTERRUPT) | U64_FROM_BIT(EFLAG_TRAP));
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
}

extern void syscall_enter(void);

static inline void init_syscall_handler()
{
    set_syscall_handler(syscall_enter);
}

static inline void set_page_write_protect(boolean enable)
{
    word cr0;
    mov_from_cr("cr0", cr0);
    cr0 = enable ? (cr0 | C0_WP) : (cr0 & ~C0_WP);
    mov_to_cr("cr0", cr0);
}

typedef struct {
    u8 data[8];
} seg_desc_t;

struct cpuinfo_machine {
    /*** Fields accessed by low-level entry points. ***/
    /* Don't move these without updating gs-relative accesses in crt0.s ***/

    /* For accessing cpuinfo via %gs:0; must be first */
    void *self;

    /* This points to the currently-running context and bottom of associated frame. +8 */
    context current_context;

    /* Next kernel context to install +16 */
    context kernel_context;

    /* Next syscall context to install +24 */
    context syscall_context;

    /* One temporary for syscall enter to use so that we don't need to touch the user stack. +32 */
    u64 tmp;

#ifdef CONFIG_FTRACE
    /* Used by mcount to determine if to enter ftrace code. +40 */
    u64 ftrace_disable_cnt;
#endif

    /*** End of fields touched by kernel entries ***/

    /* Stack for exceptions (which may occur in interrupt handlers) */
    void *exception_stack;

    /* Stack for interrupts */
    void *int_stack;

    struct gdt {
        seg_desc_t null;
        seg_desc_t code;
        seg_desc_t data;
        seg_desc_t user_code;
        seg_desc_t user_data;
        seg_desc_t user_code_64;
        u8 tss_desc[0x10];
    } gdt;

    struct gdt_pointer {
        u16 limit;
        u64 base;
    } __attribute__((packed)) gdt_pointer;
    u64 tss[TSS_SIZE / sizeof(u64)];

    /* Monotonic clock timestamp when the lapic timer is supposed to fire; used to re-arm the timer
     * when it fires too early (based on what the monotonic clock source says). */
    timestamp lapic_timer_expiry;
};

typedef struct cpuinfo *cpuinfo;

static inline cpuinfo current_cpu(void)
{
    u64 addr;
    asm volatile("movq %%gs:0, %0":"=r"(addr));
    return (cpuinfo)pointer_from_u64(addr);
}

extern u64 extended_frame_size;

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
    f[FRAME_EFLAGS] |= U64_FROM_BIT(EFLAG_INTERRUPT);
}

static inline void frame_disable_interrupts(context_frame f)
{
    f[FRAME_EFLAGS] &= ~U64_FROM_BIT(EFLAG_INTERRUPT);
}

extern void xsave(context_frame f);
extern void clone_frame_pstate(context_frame dest, context_frame src);

static inline boolean is_protection_fault(context_frame f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_P) != 0;
}

static inline boolean is_usermode_fault(context_frame f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_US) != 0;
}

static inline boolean is_instruction_fault(context_frame f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_ID) != 0;
}

static inline boolean is_data_fault(context_frame f)
{
    return !is_instruction_fault(f);
}

static inline boolean is_write_fault(context_frame f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_RW) != 0;
}

/* page table integrity check? open to interpretation for other archs... */
static inline boolean is_pte_error(context_frame f)
{
    /* XXX check sdm before merging - seems suspicious */
    return (is_protection_fault(f) && (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_RSV));
}

static inline u64 frame_fault_pc(context_frame f)
{
    return f[FRAME_RIP];
}

static inline u64 frame_fault_address(context_frame f)
{
    return f[FRAME_CR2];
}

static inline boolean is_page_fault(context_frame f)
{
    return f[FRAME_VECTOR] == 14; // XXX defined somewhere?
}

static inline boolean is_div_by_zero(context_frame f)
{
    return f[FRAME_VECTOR] == 0; // XXX defined somewhere?
}

static inline boolean is_breakpoint(context_frame f)
{
    return f[FRAME_VECTOR] == 3;
}

static inline boolean is_trap(context_frame f)
{
    return (f[FRAME_VECTOR] == 1) /* single step */ || is_breakpoint(f);
}

static inline boolean is_illegal_instruction(context_frame f)
{
    return f[FRAME_VECTOR] == 6;
}

static inline void *frame_get_stack(context_frame f)
{
    return pointer_from_u64(f[FRAME_RSP]);
}

static inline void frame_set_stack(context_frame f, u64 sp)
{
    f[FRAME_RSP] = sp;
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
    f[FRAME_RSP] = f[FRAME_STACK_TOP];
}

static inline void frame_set_insn_ptr(context_frame f, u64 ip)
{
    f[FRAME_RIP] = ip;
}

static inline void frame_enable_stepping(context_frame f)
{
    f[FRAME_EFLAGS] &= ~U64_FROM_BIT(EFLAG_RESUME);
    f[FRAME_EFLAGS] |= U64_FROM_BIT(EFLAG_TRAP);
}

static inline void frame_disable_stepping(context_frame f)
{
    f[FRAME_EFLAGS] &= ~U64_FROM_BIT(EFLAG_TRAP);
    f[FRAME_EFLAGS] |= U64_FROM_BIT(EFLAG_RESUME);
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
    u64 rbp;
    asm("movq %%rbp, %0" : "=r" (rbp));
    return pointer_from_u64(rbp);
}

#define _switch_stack_head(s, target)                                   \
    register u64 __s = u64_from_pointer(s);                             \
    register u64 __t = u64_from_pointer(target)

#define _switch_stack_tail(...)                                         \
    asm volatile("mov %0, %%rsp; jmp *%1" :: "r"(__s), "r"(__t), ##__VA_ARGS__ : "memory")

#define _switch_stack_args_1(__a0)              \
    register u64 __ra0 asm("rdi") = (u64)(__a0);
#define _switch_stack_args_2(__a0, __a1)                \
    _switch_stack_args_1(__a0);                         \
    register u64 __ra1 asm("rsi") = (u64)(__a1);
#define _switch_stack_args_3(__a0, __a1, __a2)          \
    _switch_stack_args_2(__a0, __a1);                   \
    register u64 __ra2 asm("rdx") = (u64)(__a2);
#define _switch_stack_args_4(__a0, __a1, __a2, __a3)    \
    _switch_stack_args_3(__a0, __a1, __a2);             \
    register u64 __ra3 asm("rcx") = (u64)(__a3);
#define _switch_stack_args_5(__a0, __a1, __a2, __a3, __a4)     \
    _switch_stack_args_4(__a0, __a1, __a2, __a3);              \
    register u64 __ra4 asm("r8") = (u64)(__a4);

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
    asm("lea 0x5(%%rip), %%rax\n"    /* 0x5 is the sum of the length of the next 2 instructions */
        "add %0, %%rax\n"
        "jmp *%%rax" :: "r"(offset) : "%rax");
}

/* adds an offset to the return address of the current function */
static inline void return_offset(u64 offset) {
    asm("add %0, 0x8(%%rbp)" :: "r"(offset) : "memory");
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

/* clocksource */

static inline boolean platform_has_precise_clocksource(void)
{
#if defined(KERNEL) || defined(BUILD_VDSO)
    return __vdso_dat->machine.platform_has_rdtscp;
#else
    return false;
#endif
}

static inline u64
_rdtscp(void)
{
    u32 a, d;
    asm volatile("rdtscp" : "=a" (a), "=d" (d) :: "%rcx");
    return (((u64)a) | (((u64)d) << 32));
}

static inline u64
_rdtsc(void)
{
    u32 a, d;
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

static inline u64
rdtsc(void)
{
    if (platform_has_precise_clocksource())
        return _rdtscp();
    return _rdtsc();
}

static inline u64
rdtsc_ordered(void)
{
    if (platform_has_precise_clocksource())
        return _rdtscp();

    /* Now both AMD and Intel has lfence  */
    __asm __volatile("lfence" : : : "memory");
    return _rdtsc();
}

static inline u64
rdtsc_precise(void)
{
    if (platform_has_precise_clocksource())
        return _rdtscp();

    asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx"); /* serialize execution */
    return _rdtsc();
}

/* IPI */
static inline void machine_halt(void)
{
    __asm__("cli; hlt");
}

u64 allocate_interrupt(void);
void deallocate_interrupt(u64 irq);
#define allocate_ipi_interrupt allocate_interrupt
#define deallocate_ipi_interrupt deallocate_interrupt
#define allocate_mmio_interrupt allocate_interrupt
#define deallocate_mmio_interrupt deallocate_interrupt
