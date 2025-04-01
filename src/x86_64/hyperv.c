#include <kernel.h>
#include <apic.h>
#include <hyperv_internal.h>
#include <hyperv.h>
#include <hyperv_busdma.h>

#define MSR_HV_HYPERCALL            0x40000001
#define MSR_HV_HYPERCALL_ENABLE     0x0001ULL
#define MSR_HV_HYPERCALL_RSVD_MASK  0x0ffeULL
#define MSR_HV_HYPERCALL_PGSHIFT    12

#define MSR_HV_REFERENCE_TSC    0x40000021
#define MSR_HV_REFTSC_ENABLE    0x0001ULL
#define MSR_HV_REFTSC_RSVD_MASK 0x0ffeULL
#define MSR_HV_REFTSC_PGSHIFT   12

/*
 * CPUID leaves
 */

#define CPUID_LEAF_HV_MAXLEAF   0x40000000

#define CPUID_LEAF_HV_INTERFACE 0x40000001
#define CPUID_HV_IFACE_HYPERV   0x31237648  /* HV#1 */

#define CPUID_LEAF_HV_IDENTITY  0x40000002

#define CPUID_LEAF_HV_FEATURES  0x40000003
/* EAX: features include/hyperv.h CPUID_HV_MSR */
/* ECX: power management features */
#define CPUPM_HV_CSTATE_MASK    0x000f  /* deepest C-state */
#define CPUPM_HV_C3_HPET        0x0010  /* C3 requires HPET */
#define CPUPM_HV_CSTATE(f)      ((f) & CPUPM_HV_CSTATE_MASK)
/* EDX: features3 */
#define CPUID3_HV_MWAIT         0x0001  /* MWAIT */
#define CPUID3_HV_XMM_HYPERCALL 0x0010  /* Hypercall input through
                         * XMM regs */
#define CPUID3_HV_GUEST_IDLE    0x0020  /* guest idle */
#define CPUID3_HV_NUMA          0x0080  /* NUMA distance query */
#define CPUID3_HV_TIME_FREQ     0x0100  /* timer frequency query
                         * (TSC, LAPIC) */
#define CPUID3_HV_MSR_CRASH     0x0400  /* MSRs for guest crash */

#define CPUID_LEAF_HV_RECOMMENDS    0x40000004
#define CPUID_LEAF_HV_LIMITS        0x40000005
#define CPUID_LEAF_HV_HWFEATURES    0x40000006

#define CPUID_SSE2  0x04000000

struct hyperv_reftsc_ctx {
    struct hyperv_reftsc *tsc_ref;
    struct hyperv_dma tsc_ref_dma;
};

#ifdef HYPERV_DEBUG
#define hyperv_debug(x, ...) do { rprintf("HYPERV: " x "\n", ##__VA_ARGS__); } while(0)
#else
#define hyperv_debug(x, ...)
#endif

static BSS_RO_AFTER_INIT struct {
    u32 features;
    struct hyperv_reftsc_ctx hyperv_ref_tsc;
    hyperv_tc64_t hyperv_tc64;
} *hyperv_aarch_info;

static u64 hyperv_tc64_rdmsr(void)
{
    return read_msr(MSR_HV_TIME_REF_COUNT);
}

static u64 read_hyperv_timer_tsc(void)
{
    struct hyperv_reftsc *tsc_ref = hyperv_aarch_info->hyperv_ref_tsc.tsc_ref;
    u32 seq;

    while ((seq = tsc_ref->tsc_seq) != 0) {
        compiler_barrier();
        u64 disc, ret, tsc;
        u64 scale = tsc_ref->tsc_scale;
        s64 ofs = tsc_ref->tsc_ofs;

        /* rdtsc_ordered contains a load fence */
        tsc = rdtsc_ordered();

        /* ret = ((tsc * scale) >> 64) + ofs */
        __asm__ __volatile__ ("mulq %3" :
            "=d" (ret), "=a" (disc) :
            "a" (tsc), "r" (scale));
        ret += ofs;

        compiler_barrier();
        if (tsc_ref->tsc_seq == seq)
            return (ret);

        /* Sequence changed; re-sync. */
    }
    /* Fallback to the generic timecounter, i.e. rdmsr. */
    return hyperv_tc64_rdmsr();
}

static void hyperv_init_clock(kernel_heaps kh)
{
    hyperv_aarch_info->hyperv_tc64 = hyperv_tc64_rdmsr;

    u32 v[4];
    cpuid(1, 0, v);

    if ((hyperv_aarch_info->features &
         (CPUID_HV_MSR_TIME_REFCNT | CPUID_HV_MSR_REFERENCE_TSC)) !=
        (CPUID_HV_MSR_TIME_REFCNT | CPUID_HV_MSR_REFERENCE_TSC) ||
        (v[3] & CPUID_SSE2) == 0) {   /* SSE2 for mfence/lfence */
        hyperv_debug("Reference Time Stamp Counter not supported");
        return;
    }

    hyperv_debug("Enabling Reference Time Stamp Counter support");
    hyperv_aarch_info->hyperv_ref_tsc.tsc_ref = mem_alloc((heap)heap_linear_backed(kh),
                                                          sizeof(struct hyperv_reftsc),
                                                          MEM_ZERO | MEM_NOWAIT | MEM_NOFAIL);
    hyperv_aarch_info->hyperv_ref_tsc.tsc_ref_dma.hv_paddr =
        physical_from_virtual(hyperv_aarch_info->hyperv_ref_tsc.tsc_ref);
    assert(hyperv_aarch_info->hyperv_ref_tsc.tsc_ref_dma.hv_paddr != INVALID_PHYSICAL);

    u64 orig = read_msr(MSR_HV_REFERENCE_TSC);
    u64 val = MSR_HV_REFTSC_ENABLE | (orig & MSR_HV_REFTSC_RSVD_MASK) |
        ((hyperv_aarch_info->hyperv_ref_tsc.tsc_ref_dma.hv_paddr >> PAGELOG) <<
         MSR_HV_REFTSC_PGSHIFT);
    write_msr(MSR_HV_REFERENCE_TSC, val);

    hyperv_aarch_info->hyperv_tc64 = read_hyperv_timer_tsc;
}

closure_function(0, 0, timestamp, hyperv_clock_now)
{
    return nanoseconds(hyperv_aarch_info->hyperv_tc64() * HYPERV_TIMER_NS_FACTOR);
}

boolean hyperv_arch_detect(kernel_heaps kh) {
    u32 v[4];

    cpuid(CPUID_LEAF_HV_MAXLEAF, 0, v);
    u32 maxleaf = v[0];
    if (maxleaf < CPUID_LEAF_HV_LIMITS)
        return false;

    cpuid(CPUID_LEAF_HV_INTERFACE, 0, v);
    if (v[0] != CPUID_HV_IFACE_HYPERV)
        return false;

    cpuid(CPUID_LEAF_HV_FEATURES, 0, v);
    if ((v[0] & CPUID_HV_MSR_HYPERCALL) == 0) {
        /*
         * Hyper-V w/o Hypercall is impossible; someone
         * is faking Hyper-V.
         */
        return false;
    }

    heap h = heap_general(kh);
    hyperv_aarch_info = mem_alloc(h, sizeof(*hyperv_aarch_info), MEM_NOWAIT | MEM_NOFAIL);
    hyperv_aarch_info->features = v[0];

    cpuid(CPUID_LEAF_HV_IDENTITY, 0, v);
#ifdef HYPERV_DEBUG
    u32 hyperv_ver_major = v[1] >> 16;
    hyperv_debug("Hyper-V Version: %d.%d.%d [SP%d]",
        hyperv_ver_major, v[1] & 0xffff, v[0], v[2]);
#endif

    if (!(hyperv_aarch_info->features & CPUID_HV_MSR_TIME_REFCNT)) {
        halt("Hyper-V timecount not available");
    }

    hyperv_init_clock(kh);
    register_platform_clock_now(closure(h, hyperv_clock_now), 0, 0);

    clock_timer ct;
    thunk per_cpu_init;
    if (init_vmbus_et_timer(h, hyperv_aarch_info->features, hyperv_aarch_info->hyperv_tc64,
                            &ct, &per_cpu_init)) {
        hyperv_debug("VMBUS ET timer available\n");
    } else if (init_lapic_timer(&ct, &per_cpu_init)) {
        hyperv_debug("defaulting to (suboptimal) lapic timer\n");
    } else {
        halt("%s: no timer available\n", func_ss);
    }

    register_platform_clock_timer(ct, per_cpu_init);
    return true;
}

void hypercall_create(struct hypercall_ctx *hctx)
{
    extern char hypercall_page[PAGESIZE];
    hctx->hc_addr = pointer_from_u64(hypercall_page);
    assert((u64)hctx->hc_addr == pad((u64)hctx->hc_addr, PAGESIZE));
    hctx->hc_paddr = physical_from_virtual(hctx->hc_addr);

    assert(hctx->hc_paddr != INVALID_PHYSICAL);

    /* Get the 'reserved' bits, which requires preservation. */
    u64 hc_orig = read_msr(MSR_HV_HYPERCALL);

    /*
     * Setup the Hypercall page.
     *
     * NOTE: 'reserved' bits MUST be preserved.
     */
    u64 hc = ((hctx->hc_paddr >> PAGELOG) << MSR_HV_HYPERCALL_PGSHIFT) |
             (hc_orig & MSR_HV_HYPERCALL_RSVD_MASK) | MSR_HV_HYPERCALL_ENABLE;
    write_msr(MSR_HV_HYPERCALL, hc);

    /*
     * Confirm that Hypercall page did get setup.
     */
    hc = read_msr(MSR_HV_HYPERCALL);
    if ((hc & MSR_HV_HYPERCALL_ENABLE) == 0) {
        halt("hyperv: Hypercall setup failed\n");
    }
    hyperv_debug("hyperv: Hypercall created");
}

u64 hypercall_md(volatile void *hc_addr, u64 in_val, u64 in_paddr, u64 out_paddr)
{
    uint64_t status;

    __asm__ __volatile__ ("mov %0, %%r8" : : "r" (out_paddr): "r8");
    __asm__ __volatile__ ("call *%3" : "=a" (status) :
        "c" (in_val), "d" (in_paddr), "m" (hc_addr));
    return (status);
}
