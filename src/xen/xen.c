#include <runtime.h>
#include <x86_64.h>
#include <page.h>

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
#include "memory.h"

#include "hypercall.h"

#define XEN_DEBUG
#ifdef XEN_DEBUG
#define xen_init_debug(x, ...) do {rprintf(" XEN: " x "\n", ##__VA_ARGS__);} while(0)
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
    /* XXX: volatile? where? */
    struct xenstore_domain_interface *xenstore_interface;
    struct shared_info *shared_info;
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
    xen_init_debug("hypercall_page: v 0x%lx, p 0x%lx", u64_from_pointer(&hypercall_page), hp_phys);

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
    xi.xenstore_paddr = xen_hvm_param.value << PAGELOG;

    /* map xenstore interface page */
    xi.xenstore_interface = allocate(heap_virtual_page(kh), PAGESIZE);
    assert(xi.xenstore_interface != INVALID_ADDRESS);
    map(u64_from_pointer(xi.xenstore_interface), xi.xenstore_paddr, PAGESIZE, 0, heap_pages(kh));
    xen_init_debug("xenstore page mapped at %p", xi.xenstore_interface);

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

    /* shared info page - taking page from identity heap, but could be backed as well */
    xi.shared_info = allocate(heap_pages(kh), PAGESIZE);
    assert(xi.shared_info != INVALID_ADDRESS);
    xen_add_to_physmap_t xatp;
    xatp.domid = DOMID_SELF;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.idx = 0;
    xatp.gpfn = u64_from_pointer(xi.shared_info) >> PAGELOG; /* identity heap, v == p */
    xen_init_debug("shared info page: 0x%lx", u64_from_pointer(xi.shared_info));
    rv = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
    if (rv < 0) {
        msg_err("failed to add shared info map\n");
        deallocate(heap_pages(kh), xi.shared_info, PAGESIZE);
        xi.shared_info = 0;
        return;
    }
    xen_init_debug("xen initialization complete");
}

static inline void evtchn_send(evtchn_port_t port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.port = port;
    HYPERVISOR_event_channel_op(&op);
}

/* returns bytes written; doesn't block */
static u64 xenstore_write_internal(const void * data, u64 length)
{
    struct xenstore_domain_interface *xsdi = xi.xenstore_interface;
    if (length == 0)
        return 0;

    u64 written = 0;
    u64 flags = read_flags();
    disable_interrupts();

    do {
        u64 produced = xsdi->req_prod - xsdi->req_cons;
        assert(produced <= XENSTORE_RING_SIZE); /* too harsh? recoverable error? */
        u64 offset = MASK_XENSTORE_IDX(xsdi->req_prod);
        u64 navail = XENSTORE_RING_SIZE - MAX(produced, offset);
        if (navail == 0)
            goto out;
        u64 nwrite = MIN(navail, length);
        if (nwrite == 0)
            continue;
        runtime_memcpy(xsdi->req + offset, data, nwrite);
        data += nwrite;
        length -= nwrite;
        read_barrier();     /* XXX verify */
        xsdi->req_prod += nwrite;
        read_barrier();
        evtchn_send(xi.xenstore_evtchn);
        written += nwrite;
    } while (length > 0);

  out:
    irq_restore(flags);
    return written;
}

boolean xenstore_write(enum xsd_sockmsg_type type, buffer buf)
{
    struct xsd_sockmsg msg;
    msg.tx_id = 0;              /* XXX private, but only 32-bit */
    msg.req_id = 0;
    msg.type = type;
    msg.len = buffer_length(buf);

    xenstore_write_internal(&msg, sizeof(msg));
    // XXX
    return true;
}
