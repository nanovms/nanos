#include <kernel.h>
#include <page.h>
#include <apic.h>
#include <hyperv_internal.h>
#include <hyperv.h>
#include "vmbus_reg.h"
#include "vmbus_var.h"
#include "hyperv_var.h"

//#define HYPERV_DEBUG
#ifdef HYPERV_DEBUG
#define hyperv_debug(x, ...) do { rprintf("HYPERV: " x "\n", ##__VA_ARGS__); } while(0)
#else
#define hyperv_debug(x, ...)
#endif

#define __FreeBSD_version 1100000

#define HYPERV_FREEBSD_BUILD        0ULL
#define HYPERV_FREEBSD_VERSION      ((uint64_t)__FreeBSD_version)
#define HYPERV_FREEBSD_OSID     0ULL

#define MSR_HV_GUESTID_BUILD_FREEBSD    \
    (HYPERV_FREEBSD_BUILD & MSR_HV_GUESTID_BUILD_MASK)
#define MSR_HV_GUESTID_VERSION_FREEBSD  \
    ((HYPERV_FREEBSD_VERSION << MSR_HV_GUESTID_VERSION_SHIFT) & \
     MSR_HV_GUESTID_VERSION_MASK)
#define MSR_HV_GUESTID_OSID_FREEBSD \
    ((HYPERV_FREEBSD_OSID << MSR_HV_GUESTID_OSID_SHIFT) & \
     MSR_HV_GUESTID_OSID_MASK)

#define MSR_HV_GUESTID_FREEBSD      \
    (MSR_HV_GUESTID_BUILD_FREEBSD | \
     MSR_HV_GUESTID_VERSION_FREEBSD | \
     MSR_HV_GUESTID_OSID_FREEBSD |  \
     MSR_HV_GUESTID_OSTYPE_FREEBSD)

#define CPUID_SSE2  0x04000000

struct hypercall_ctx {
    void            *hc_addr;
    u64             hc_paddr;
};

struct hyperv_reftsc_ctx {
    struct hyperv_reftsc    *tsc_ref;
    struct hyperv_dma   tsc_ref_dma;
};

typedef struct hyperv_platform_info {
    heap general;                  /* general heap for internal use */
    heap contiguous;               /* physically */

    u32 features;

    /* probed devices and registered drivers */
    struct list vmbus_list;
    struct list driver_list;

    // clock
    struct hyperv_reftsc_ctx hyperv_ref_tsc;
    hyperv_tc64_t hyperv_tc64;

    //hypercall
    struct hypercall_ctx hypercall_context;

    vmbus_dev vmbus;

    boolean initialized;
} *hyperv_platform_info;

struct hyperv_platform_info hyperv_info;

u64
hypercall_md(volatile void *hc_addr, u64 in_val,
    u64 in_paddr, u64 out_paddr)
{
    uint64_t status;

    __asm__ __volatile__ ("mov %0, %%r8" : : "r" (out_paddr): "r8");
    __asm__ __volatile__ ("call *%3" : "=a" (status) :
        "c" (in_val), "d" (in_paddr), "m" (hc_addr));
    return (status);
}

static void
hypercall_create(void)
{
    struct hypercall_ctx *hctx = &hyperv_info.hypercall_context;

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
    u64 hc = ((hctx->hc_paddr >> PAGELOG) <<
        MSR_HV_HYPERCALL_PGSHIFT) |
        (hc_orig & MSR_HV_HYPERCALL_RSVD_MASK) |
        MSR_HV_HYPERCALL_ENABLE;
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

uint64_t
hyperv_tc64_rdmsr(void)
{
    return read_msr(MSR_HV_TIME_REF_COUNT);
}

u64
hypercall_post_message(bus_addr_t msg_paddr)
{
    return hypercall_md(hyperv_info.hypercall_context.hc_addr,
        HYPERCALL_POST_MESSAGE, msg_paddr, 0);
}

u64
hypercall_signal_event(bus_addr_t monprm_paddr)
{
    return hypercall_md(hyperv_info.hypercall_context.hc_addr,
        HYPERCALL_SIGNAL_EVENT, monprm_paddr, 0);
}

static
u64 read_hyperv_timer_tsc(void)
{
    struct hyperv_reftsc *tsc_ref = hyperv_info.hyperv_ref_tsc.tsc_ref;
    u32 seq;

    while ((seq = atomic_load_acq32(&tsc_ref->tsc_seq)) != 0) {
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

        atomic_thread_fence_acq();
        if (tsc_ref->tsc_seq == seq)
            return (ret);

        /* Sequence changed; re-sync. */
    }
    /* Fallback to the generic timecounter, i.e. rdmsr. */
    return hyperv_tc64_rdmsr();
}


void
hyperv_init_clock(void)
{
    hyperv_info.hyperv_tc64 = hyperv_tc64_rdmsr;

    u32 v[4];
    cpuid(1, 0, v);

    if ((hyperv_info.features &
         (CPUID_HV_MSR_TIME_REFCNT | CPUID_HV_MSR_REFERENCE_TSC)) !=
        (CPUID_HV_MSR_TIME_REFCNT | CPUID_HV_MSR_REFERENCE_TSC) ||
        (v[3] & CPUID_SSE2) == 0) {   /* SSE2 for mfence/lfence */
        hyperv_debug("Reference Time Stamp Counter not supported");
        return;
    }

    hyperv_debug("Enabling Reference Time Stamp Counter support");
    hyperv_info.hyperv_ref_tsc.tsc_ref = allocate_zero(hyperv_info.contiguous, sizeof(struct hyperv_reftsc));
    assert(hyperv_info.hyperv_ref_tsc.tsc_ref != INVALID_ADDRESS);
    hyperv_info.hyperv_ref_tsc.tsc_ref_dma.hv_paddr =
        physical_from_virtual(hyperv_info.hyperv_ref_tsc.tsc_ref);
    assert(hyperv_info.hyperv_ref_tsc.tsc_ref_dma.hv_paddr != INVALID_PHYSICAL);

    u64 orig = read_msr(MSR_HV_REFERENCE_TSC);
    u64 val = MSR_HV_REFTSC_ENABLE | (orig & MSR_HV_REFTSC_RSVD_MASK) |
        ((hyperv_info.hyperv_ref_tsc.tsc_ref_dma.hv_paddr >> PAGELOG) <<
         MSR_HV_REFTSC_PGSHIFT);
    write_msr(MSR_HV_REFERENCE_TSC, val);

    hyperv_info.hyperv_tc64 = read_hyperv_timer_tsc;
}

closure_function(0, 0, timestamp, hyperv_clock_now)
{
    return nanoseconds(hyperv_info.hyperv_tc64() * HYPERV_TIMER_NS_FACTOR);
}

boolean
hyperv_detect(kernel_heaps kh) {
    u32 v[4];
    hyperv_info.initialized = false;
    hyperv_info.general = heap_general(kh);
    hyperv_info.contiguous = heap_backed(kh);

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

    hyperv_info.features = v[0];

    cpuid(CPUID_LEAF_HV_IDENTITY, 0, v);
#ifdef HYPERV_DEBUG
    u32 hyperv_ver_major = v[1] >> 16;
    hyperv_debug("Hyper-V Version: %d.%d.%d [SP%d]",
        hyperv_ver_major, v[1] & 0xffff, v[0], v[2]);
#endif

    /* Set guest id: othervise hypercall_create() fails */
    write_msr(MSR_HV_GUEST_OS_ID, MSR_HV_GUESTID_FREEBSD);

    if (!(hyperv_info.features & CPUID_HV_MSR_TIME_REFCNT)) {
        halt("Hyper-V timecount not available");
    }

    hyperv_init_clock();
    register_platform_clock_now(closure(hyperv_info.general, hyperv_clock_now), 0);

    clock_timer ct;
    thunk per_cpu_init;
    if ( init_vmbus_et_timer(hyperv_info.general, hyperv_info.features, hyperv_info.hyperv_tc64,
                            &ct, &per_cpu_init)) {
        hyperv_debug("VMBUS ET timer available\n");
    } else if (init_lapic_timer(&ct, &per_cpu_init)) {
        hyperv_debug("defaulting to (suboptimal) lapic timer\n");
    } else {
        halt("%s: no timer available\n", __func__);
    }

    register_platform_clock_timer(ct, per_cpu_init);
    list_init(&hyperv_info.vmbus_list);
    list_init(&hyperv_info.driver_list);
    hyperv_info.initialized = true;
    return true;
}

boolean
hyperv_detected(void)
{
    return hyperv_info.initialized;
}

void
register_vmbus_driver(const struct hyperv_guid *type, vmbus_device_probe probe)
{
    vmbus_driver vd = allocate(hyperv_info.general, sizeof(struct vmbus_driver));
    assert(vd != INVALID_ADDRESS);
    vd->type = type;
    vd->probe = probe;
    list_insert_before(&hyperv_info.driver_list, &vd->l);
}

void
init_vmbus(kernel_heaps kh)
{
    hypercall_create();

    status s = vmbus_attach(kh, &hyperv_info.vmbus);
    if (!is_ok(s)) {
        msg_err("attach failed with status %v\n", s);
        return;
    }

    init_netvsc(kh);
    init_storvsc(kh);
    init_vmbus_shutdown(kh);
}

status
hyperv_probe_devices(storage_attach a, boolean *storvsc_attached)
{
    status s = vmbus_probe_channels(hyperv_info.vmbus, &hyperv_info.driver_list, &hyperv_info.vmbus_list);
    if (!is_ok(s))
        return s;

    list_foreach(&hyperv_info.vmbus_list, nl) {
        list_foreach(&hyperv_info.driver_list, l) {
            vmbus_driver xd = struct_from_list(l, vmbus_driver, l);
            hv_device *device = struct_from_list(nl, hv_device*, l);
            if (runtime_memcmp(&device->class_id, xd->type, sizeof(*xd->type))) {
                continue;
            }
            apply(xd->probe, device, a, storvsc_attached);
        }
    }
    vmbus_set_poll_mode(hyperv_info.vmbus, false);
    return s;
}
