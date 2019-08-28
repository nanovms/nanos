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

#define __XEN_INTERFACE_VERSION__ 0x00040d00

#include "xen.h"
#include "arch-x86/cpuid.h"
#include "event_channel.h"
#include "platform.h"
#include "hvm/params.h"
#include "hvm/hvm_op.h"
#include "io/xs_wire.h"
#include "memory.h"
#include "features.h"
#include "version.h"
#include "vcpu.h"

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
    u32 features;
    u64 xenstore_paddr;
    u64 xenstore_evtchn;
    volatile struct xenstore_domain_interface *xenstore_interface;
    volatile struct shared_info *shared_info;
    boolean initialized;
} *xen_info;

static struct xen_info xi;

extern u64 hypercall_page;
extern heap interrupt_vectors;

boolean xen_detected(void)
{
    return xi.initialized;
}

static inline boolean xen_feature_supported(int feature)
{
    return (xi.features & U64_FROM_BIT(feature)) != 0;
}

static CLOSURE_0_0(xen_interrupt, void);
static void xen_interrupt(void)
{
    volatile struct shared_info *si = xi.shared_info;
    volatile struct vcpu_info *vci = &xi.shared_info->vcpu_info[0]; /* hardwired at this point */

    rprintf("in xen_interrupt\n");
    while (vci->evtchn_upcall_pending) {
        vci->evtchn_upcall_pending = 0;
        u64 l1_pending = __sync_lock_test_and_set(&vci->evtchn_pending_sel, 0); /* XXX check asm */
        /* this may not process in the right order, or it might not matter - care later */
        bitmap_word_foreach_set(l1_pending, bit1, i1, 0) {
            (void)i1;
            /* TODO: any per-cpu event mask would be also applied here... */
            u64 l2_pending = si->evtchn_pending[bit1] & ~si->evtchn_mask[bit1];
            __sync_or_and_fetch(&si->evtchn_mask[bit1], l2_pending);
            __sync_and_and_fetch(&si->evtchn_pending[bit1], ~l2_pending);
            u64 l2_offset = bit1 << 6;
            bitmap_word_foreach_set(l2_pending, bit2, i2, l2_offset) {
                (void)i2;
                rprintf("xen interrupt: %ld\n", i2);
            }
        }
    }
}

static boolean xen_unmask_evtchn(u32 evtchn)
{
    assert(evtchn > 0 && evtchn < EVTCHN_2L_NR_CHANNELS);
    rprintf("unmasking evtchn %d\n", evtchn);
    evtchn_op_t eop;
    eop.cmd = EVTCHNOP_unmask;
    eop.u.unmask.port = evtchn;
    s64 rv = HYPERVISOR_event_channel_op(&eop);
    if (rv != 0) {
        msg_err("failed to unmask evtchn %d; rv %ld\n", evtchn, rv);
        return false;
    }
    return true;
}

void xen_detect(kernel_heaps kh)
{
    u32 v[4];
    xi.initialized = false;
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
        msg_err("xen reporting %d hypercall pages; not supported\n", v[0]);
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

    /* get xen features */
    build_assert(XENFEAT_NR_SUBMAPS == 1);
    struct xen_feature_info xfi;
    xfi.submap_idx = 0;
    s64 rv = HYPERVISOR_xen_version(XENVER_get_features, &xfi);
    if (rv < 0) {
        msg_err("failed to get xen features map (rv %ld)\n", rv);
        return;
    }
    xi.features = xfi.submap;
    xen_init_debug("reported features map 0x%x", xi.features);

    /* get store page, map it, and retrieve event channel */
    xen_init_debug("retrieving xenstore shared page");
    struct xen_hvm_param xen_hvm_param;
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_PFN;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to get xenstore page address (rv %ld)\n", rv);
        return;
    }
    xi.xenstore_paddr = xen_hvm_param.value << PAGELOG;

    xen_init_debug("xenstore shared page at phys 0x%lx; allocating virtual page and mapping");
    xi.xenstore_interface = allocate(heap_virtual_page(kh), PAGESIZE);
    assert(xi.xenstore_interface != INVALID_ADDRESS);
    map(u64_from_pointer(xi.xenstore_interface), xi.xenstore_paddr, PAGESIZE, 0, heap_pages(kh));
    xen_init_debug("xenstore page mapped at %p", xi.xenstore_interface);

    xen_init_debug("retrieving store event channel");
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_EVTCHN;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to get xenstore event channel (rv %ld)\n", rv);
        return;
    }

    xi.xenstore_evtchn = xen_hvm_param.value;
    xen_init_debug("event channel %ld, allocating and mapping shared info page", xi.xenstore_evtchn);

    /* shared info page - taking page from identity heap, but could be backed as well */
    xi.shared_info = allocate(heap_pages(kh), PAGESIZE);
    assert(xi.shared_info != INVALID_ADDRESS);
    xen_add_to_physmap_t xatp;
    xatp.domid = DOMID_SELF;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.idx = 0;
    xatp.gpfn = u64_from_pointer(xi.shared_info) >> PAGELOG; /* identity heap, v == p */
    rv = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
    if (rv < 0) {
        msg_err("failed to add shared info map (rv %ld)\n", rv);
        goto out_dealloc_shared_page;
    }
    xen_init_debug("shared info page: 0x%lx", u64_from_pointer(xi.shared_info));

    if (!xen_feature_supported(XENFEAT_hvm_callback_vector)) {
        msg_err("HVM callback vector must be supported; xen setup failed (features mask 0x%x)\n",
                xi.features);
        goto out_dealloc_shared_page;
    }

    /* set up interrupt handling path */
    int irq = allocate_u64(interrupt_vectors, 1);
    xen_init_debug("interrupt vector %d; registering", irq);
    register_interrupt(irq, closure(heap_general(kh), xen_interrupt));

    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_CALLBACK_IRQ;
    xen_hvm_param.value = (2ull << 56) | irq;
    rv = HYPERVISOR_hvm_op(HVMOP_set_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to register event channel interrupt vector (rv %ld)\n", rv);
        goto out_unregister_irq;
    }

    /* NetBSD re-reads the set value; not clear why... */
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_CALLBACK_IRQ;
    xen_hvm_param.value = 0;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to retrieve event channel interrupt vector (rv %ld)\n", rv);
        goto out_unregister_irq;
    }
    xen_init_debug("returned 0x%lx", xen_hvm_param.value);

    /* register VCPU info */
    xen_init_debug("registering VCPU info");
    struct vcpu_register_vcpu_info vrvi;
    u64 vci_pa = u64_from_pointer(xi.shared_info->vcpu_info); /* identity, pa == va */
    vrvi.mfn = vci_pa >> PAGELOG;
    vrvi.offset = vci_pa & (PAGESIZE - 1);
    rv = HYPERVISOR_vcpu_op(VCPUOP_register_vcpu_info, 0 /* vcpu0 */, &vrvi);
    if (rv < 0) {
        msg_err("failed to register vcpu info (rv %ld)\n", rv);
        goto out_unregister_irq;
    }

    xen_init_debug("unmasking xenstore event channel");
    xen_unmask_evtchn(xi.xenstore_evtchn);

    xen_init_debug("xen initialization complete");
    xi.initialized = true;
    return;
  out_unregister_irq:
    register_interrupt(irq, 0);
  out_dealloc_shared_page:
    deallocate(heap_pages(kh), xi.shared_info, PAGESIZE);
    xi.shared_info = 0;
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
    volatile struct xenstore_domain_interface *xsdi = xi.xenstore_interface;
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
        runtime_memcpy((void*)(xsdi->req + offset), data, nwrite);
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

    volatile struct shared_info *si = xi.shared_info;
    volatile struct vcpu_info *vci = &xi.shared_info->vcpu_info[0]; /* hardwired at this point */

    rprintf("pending sel 0x%lx, evtchn_pending 0x%lx\n", vci->evtchn_pending_sel, si->evtchn_pending[0]);
    rprintf("evtchn_mask 0x%lx\n", si->evtchn_mask[0]);
    rprintf("evtchn_upcall_pending %d, evtchn_upcall_mask %d\n", vci->evtchn_upcall_pending, vci->evtchn_upcall_mask);

    u64 written = xenstore_write_internal(&msg, sizeof(msg));
    rprintf("written: %ld\n", written);

    rprintf("pending sel 0x%lx, evtchn_pending 0x%lx\n", vci->evtchn_pending_sel, si->evtchn_pending[0]);
    rprintf("evtchn_mask 0x%lx\n", si->evtchn_mask[0]);
    rprintf("evtchn_upcall_pending %d, evtchn_upcall_mask %d\n", vci->evtchn_upcall_pending, vci->evtchn_upcall_mask);
    return true;
}

void xenstore_directory(const char *path)
{
    buffer req = alloca_wrap_buffer(path, runtime_strlen(path));
    if (!xenstore_write(XS_DIRECTORY, req)) {
        msg_err("xenstore write failed\n");
        return;
    }
}
