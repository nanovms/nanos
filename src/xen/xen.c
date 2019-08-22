#include <runtime.h>
#include <x86_64.h>
#include <page.h>

#define __XEN__
typedef s8 int8_t;
typedef u8 uint8_t;
typedef u16 uint16_t;
typedef s16 int16_t;
typedef u32 uint32_t;
typedef s32 int32_t;
typedef u64 uint64_t;
typedef s64 int64_t;

#include "xen.h"
#include "arch-x86/cpuid.h"
#include "event_channel.h"
#include "platform.h"
#include "hvm/params.h"
#include "hvm/hvm_op.h"
#include "io/xs_wire.h"

#include "hypercall.h"

#define XEN_DEBUG
#ifdef XEN_DEBUG
#define xen_init_debug(x, ...) do {rprintf(" XEN: " x "\n", __func__, ##__VA_ARGS__);} while(0)
#else
#define xen_init_debug(x, ...)
#endif

typedef struct xen_info {
    u16 xen_major;
    u16 xen_minor;
    u32 last_leaf;
    u32 msr_base;
    u64 xenstore_paddr;
    u64 xenstore_evtchn;
    struct xenstore_domain_interface *xenstore_interface;
} *xen_info;

extern u64 hypercall_page;
static struct xen_info xi;

boolean xen_detected(void)
{
    return xi.xenstore_interface != 0;
}

void xen_detect(kernel_heaps kh)
{
    u32 v[4];
    xen_init_debug("checking for xen cpuid leaves");
    cpuid(XEN_CPUID_FIRST_LEAF, 0, v);
    if (!(v[1] == XEN_CPUID_SIGNATURE_EBX &&
          v[2] == XEN_CPUID_SIGNATURE_ECX &&
          v[3] == XEN_CPUID_SIGNATURE_EDX)) {
        xen_init_debug("no signature match; xen not detected");
        return;
    }

    xi.last_leaf = v[0];

    cpuid(XEN_CPUID_LEAF(1), 0, v);
    xi.xen_major = v[0] >> 16;
    xi.xen_minor = v[0] & MASK(16);
    xen_init_debug("xen version %d.%d detected", xi.xen_major, xi.xen_minor);

    cpuid(XEN_CPUID_LEAF(2), 0, v);
    if (v[0] != 1) {
        msg_err("xen reporting %d hypercall pages; not supported", v[0]);
        return;
    }
    xi.msr_base = v[1];
    xen_init_debug("msr base 0x%x, features 1 0x%x, features 2 0x%x", xi.msr_base, v[2], v[3]);

#if 0
    cpuid(XEN_CPUID_LEAF(3), 0, v);
    xen_init_debug("leaf 4, subleaf 0: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(3), 1, v);
    xen_init_debug("leaf 4, subleaf 1: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(3), 2, v);
    xen_init_debug("leaf 4, subleaf 2: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(4), 0, v);
    xen_init_debug("leaf 5: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(5), 0, v);
    xen_init_debug("leaf 6: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
#endif

    /* install hypercall page */
    u64 hp_phys = physical_from_virtual(&hypercall_page);
    xen_init_debug("hypercall_page: v %p, p 0x%lx", &hypercall_page, hp_phys);

    /* we can assume that kernel bss is identity mapped... */
    write_msr(xi.msr_base, hp_phys);

    xen_init_debug("retrieving xenstore shared page and event channel...");
    struct xen_hvm_param xen_hvm_param;
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_PFN;
    s64 rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to get xenstore page address (rv %ld)", rv);
        return;
    }

    u64 paddr = xen_hvm_param.value << PAGELOG;
    xi.xenstore_paddr = paddr;

    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_EVTCHN;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to get xenstore event channel (rv %ld)", rv);
        return;
    }

    xi.xenstore_evtchn = xen_hvm_param.value;
    xen_init_debug("xenstore page at phys 0x%lx, event channel %ld",
              xi.xenstore_paddr, xi.xenstore_evtchn);

    xi.xenstore_interface = allocate(heap_virtual_page(kh), PAGESIZE);
    assert(xi.xenstore_interface != INVALID_ADDRESS);
    map(u64_from_pointer(xi.xenstore_interface), xi.xenstore_paddr, PAGESIZE, 0, heap_pages(kh));
    xen_init_debug("xenstore page mapped at %p", xi.xenstore_interface);
    return;
}

