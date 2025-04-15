#include <kernel.h>
#include <drivers/acpi.h>
#include <gic.h>

#define PSCI_FN_BASE    0x84000000
#define PSCI_FN(n)      (PSCI_FN_BASE + (n))
#define PSCI_64BIT      0x40000000
#define PSCI_FN64_BASE  (PSCI_FN_BASE + PSCI_64BIT)
#define PSCI_FN64(n)    (PSCI_FN64_BASE + (n))

#define PSCI_FN_SYSTEM_OFF  PSCI_FN(8)
#define PSCI_FN_RESET       PSCI_FN(9)
#define PSCI_FN64_CPU_ON    PSCI_FN64(3)

//#define TAG_HEAP_DEBUG
#ifdef TAG_HEAP_DEBUG
#define tag_debug(x, ...) do {rprintf(x, ##__VA_ARGS__);} while(0)
#else
#define tag_debug(x, ...)
#endif

struct tagheap {
    struct heap h;
    heap mh;
    u64 vtag;
};

static void tag_dealloc(heap h, u64 a, bytes s)
{
    struct tagheap *th = (struct tagheap *)h;
    tag_debug("%s: tag %d, a 0x%lx, s 0x%lx\n", func_ss, th->vtag >> VA_TAG_OFFSET, a, s);
    deallocate_u64(th->mh, a & MASK(VA_TAG_OFFSET), s);
}

static u64 tag_alloc(heap h, bytes s)
{
    struct tagheap *th = (struct tagheap *)h;
    void *p = allocate(th->mh, s);
    if (p == INVALID_ADDRESS)
        return INVALID_PHYSICAL;
    u64 a = u64_from_pointer(p);
    assert((a >> VA_TAG_OFFSET) == 0);
    a |= th->vtag;
    tag_debug("%s: tag %d, s 0x%lx, a 0x%lx\n", func_ss, th->vtag >> VA_TAG_OFFSET, s, a);
    return a;
}

heap allocate_tagged_region(kernel_heaps kh, u64 tag, bytes pagesize, boolean locking)
{
    heap h = heap_locked(kh);
    struct tagheap *th = allocate(h, sizeof(struct tagheap));
    if (th == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    assert(tag < 256);
    th->mh = h;
    th->vtag = tag << VA_TAG_OFFSET;
    th->h.alloc = tag_alloc;
    th->h.dealloc = tag_dealloc;
    th->h.destroy = 0;
    th->h.pagesize = 32; // XXX
    th->h.allocated = 0;
    th->h.total = 0;
    th->h.management = 0;
    tag_debug("%s: tag %d, bits 0x%lx, heap %p\n", func_ss, tag, th->vtag, th);
    return &th->h;
}

void cpu_init(int cpu)
{
    cpuinfo ci = cpuinfo_from_id(cpu);
    register u64 a = u64_from_pointer(ci);
    asm volatile("mov x18, %0; msr tpidr_el1, %0" ::"r"(a));
    write_psr(CNTKCTL_EL1, CNTKCTL_EL1_EL0VCTEN);
}

void init_cpuinfo_machine(cpuinfo ci, heap backed)
{
    kernel_context kc = allocate_kernel_context(ci);
    assert(kc != INVALID_ADDRESS);
    /* start off kernel context in resumed state */
    context_reserve_refcount(&kc->context);
    kc->context.active_cpu = ci->id;
    ci->m.current_context = ci->m.kernel_context = &kc->context;
}

void clone_frame_pstate(context_frame dest, context_frame src)
{
    runtime_memcpy(dest, src, sizeof(u64) * FRAME_N_PSTATE);
}

boolean insn_emulate(context_frame f)
{
#define CASE_SYSREG(id) case SYSREG_##id: val = read_psr(id); break

    u32 *insn_ptr = (u32 *)frame_fault_pc(f);
    u32 insn = *insn_ptr;
    if ((insn & 0xfff80000) == 0xd5380000) {
        /* read from non-debug system registers and special-purpose registers (op0 = 3) */
        u64 val;
        switch (insn & 0x001fffe0) {
        CASE_SYSREG(ID_AA64PFR0_EL1);
        CASE_SYSREG(ID_AA64ISAR0_EL1);
        CASE_SYSREG(ID_AA64ISAR1_EL1);
        case SYSREG_ID_AA64ZFR0_EL1:
            val = sysreg_get_id_aa64zfr0();
            break;
        default:
            return false;
        }
        u64 *dest = &f[FRAME_X0] + (insn & 0x0000001f); /* destination register */
        *dest = val;
        frame_set_insn_ptr(f, u64_from_pointer(insn_ptr + 1));  /* go to next instruction */
        return true;
    }
    return false;
}

void interrupt_exit(void)
{
    gic_eoi(gic_dispatch_int());
}

void psci_shutdown(void)
{
    u32 psci_fn = PSCI_FN_SYSTEM_OFF;
    arm_hvc(psci_fn, 0, 0, 0);
}

void psci_reset(void)
{
    arm_hvc(PSCI_FN_RESET, 0, 0, 0);
}

BSS_RO_AFTER_INIT static buffer mpid_map;
static struct spinlock ap_lock;
static void (*init_mmu_target)(void);

vector cpus_init_ids(heap h)
{
    mpid_map = allocate_vector(h, 2);
    assert(mpid_map != INVALID_ADDRESS);
    return mpid_map;
}

u64 mpid_from_cpuid(int id)
{
    if (!mpid_map)
        return id;
    return *(u64 *)buffer_ref(mpid_map, id * sizeof(u64));
}

static int cpuid_from_mpid(u64 mpid)
{
    for (int i = 0; i < present_processors; i++) {
        if (mpid == mpid_from_cpuid(i))
            return i;
    }
    return -1;
}

static void ap_start_newstack(int cpuid)
{
    total_processors++;
    spin_unlock(&ap_lock);
    cpu_init(cpuid);
    run_percpu_init();
    kernel_sleep();
}

static void ap_start(void)
{
    int cpuid = cpuid_from_mpid(read_mpid());
    assert(cpuid >= 0);
    cpuinfo ci = init_cpuinfo(heap_locked(get_kernel_heaps()), cpuid);
    assert(ci != INVALID_ADDRESS);
    context_frame f = ci->m.kernel_context->frame;
    switch_stack_1(frame_get_stack_top(f), ap_start_newstack, cpuid);
}

static void ap_start_nommu(void)
{
    asm volatile("bl aarch64_cpu_init");
    spin_lock(&ap_lock);    /* so that all APs can use the same temporary stack */
    enable_mmu(u64_from_pointer(init_mmu_target));
}

#define AP_START_TIMEOUT_MS 500
void start_secondary_cores(kernel_heaps kh)
{
    init_flush(heap_locked(kh));
    for (int i = 1; i < present_processors; i++)
        arm_hvc(PSCI_FN64_CPU_ON, mpid_from_cpuid(i),
                u64_from_pointer((void *)ap_start_nommu - kas_kern_offset + kernel_phys_offset), 0);
    for (u64 to = 0; (total_processors != present_processors) && (to < AP_START_TIMEOUT_MS); to++)
        kernel_delay(milliseconds(1));

    /* The MMU has been enabled on secondary cores: unmap the temporary identity map. */
    unmap(PHYSMEM_BASE + kernel_phys_offset, INIT_IDENTITY_SIZE);
}

closure_func_basic(madt_handler, void, count_cpus_handler,
                   u8 type, void *p)
{
    if (type == ACPI_MADT_GEN_INT) {
        acpi_gen_int agi = p;
        if (agi->flags & MADT_GENINT_ENABLED) {
            u64 mpidr = agi->mpidr;
            assert(buffer_write(mpid_map, &mpidr, sizeof(mpidr)));
            present_processors++;
        }
    }
}

void count_cpus_present(void)
{
    if (present_processors == 0)
        acpi_walk_madt(stack_closure_func(madt_handler, count_cpus_handler));
    if (present_processors > 1) {
        spin_lock_init(&ap_lock);
        init_mmu_target = ap_start;
    } else {
        deallocate_buffer(mpid_map);
        mpid_map = 0;
    }
}

#ifdef KERNEL
#define EXTENDED_FRAME_SIZE (FRAME_EXTENDED_MAX * sizeof(u64))
boolean init_context_machine(context c, u32 alloc_flags)
{
    void *e = mem_alloc((heap)heap_page_backed(get_kernel_heaps()), EXTENDED_FRAME_SIZE,
                        alloc_flags | MEM_ZERO);
    if (e == INVALID_ADDRESS)
        return false;
    c->frame[FRAME_EXTENDED] = u64_from_pointer(e);
    return true;
}

void destruct_context(context c)
{
    if (c->frame[FRAME_EXTENDED]) {
        deallocate_u64((heap)heap_page_backed(get_kernel_heaps()),
                       c->frame[FRAME_EXTENDED], EXTENDED_FRAME_SIZE);
        c->frame[FRAME_EXTENDED] = 0;
    }
}
#endif
