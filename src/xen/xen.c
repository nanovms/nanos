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
#define xen_debug(x, ...) do {rprintf(" XEN: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define xen_debug(x, ...)
#endif

//#define XENSTORE_DEBUG
#ifdef XENSTORE_DEBUG
#define xenstore_debug xen_debug
#else
#define xenstore_debug(x, ...)
#endif

#define XEN_STO
typedef struct xen_info {
    heap    h;                  /* general heap for internal use */
    u16     xen_major;
    u16     xen_minor;
    u32     last_leaf;
    u32     msr_base;
    u32     features;
    u64     xenstore_paddr;
    u64     xenstore_evtchn;
    vector  evtchn_handlers;
    tuple   device_tree;
    boolean initialized;

    volatile struct xenstore_domain_interface *xenstore_interface;
    volatile struct shared_info *shared_info;
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

//    rprintf("in xen_interrupt ... %d\n", sizeof(si->evtchn_pending));
    while (vci->evtchn_upcall_pending) {
        vci->evtchn_upcall_pending = 0;
        u64 l1_pending = __sync_lock_test_and_set(&vci->evtchn_pending_sel, 0); /* XXX check asm */
        /* this may not process in the right order, or it might not matter - care later */
        bitmap_word_foreach_set(l1_pending, bit1, i1, 0) {
            (void)i1;
//            rprintf("bit1 %d, pending 0x%lx, mask 0x%lx\n", bit1, si->evtchn_pending[bit1], si->evtchn_mask[bit1]);
            /* TODO: any per-cpu event mask would be also applied here... */
            u64 l2_pending = si->evtchn_pending[bit1] & ~si->evtchn_mask[bit1];
            __sync_or_and_fetch(&si->evtchn_mask[bit1], l2_pending);
            __sync_and_and_fetch(&si->evtchn_pending[bit1], ~l2_pending);
            u64 l2_offset = bit1 << 6;
//            rprintf("at l2 offset 0x%lx, pending 0x%lx\n", l2_offset, l2_pending);
            bitmap_word_foreach_set(l2_pending, bit2, i2, l2_offset) {
                (void)i2;
                thunk handler = vector_get(xi.evtchn_handlers, i2);
                if (handler) {
                    rprintf("evtchn %d: applying handler %p\n", i2, handler);
                    apply(handler);
                } else {
                    /* XXX we have an issue with seemingly spurious interrupts at evtchn >= 2048... */
//                    rprintf("evtchn %d: spurious interrupt\n", i2);
                }
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
    xi.h = heap_general(kh);
    xen_debug("checking for xen cpuid leaves");
    cpuid(XEN_CPUID_FIRST_LEAF, 0, v);
    if (!(v[1] == XEN_CPUID_SIGNATURE_EBX &&
          v[2] == XEN_CPUID_SIGNATURE_ECX &&
          v[3] == XEN_CPUID_SIGNATURE_EDX)) {
        xen_debug("no signature match; xen not detected");
        return;
    }

    xi.last_leaf = v[0];

    cpuid(XEN_CPUID_LEAF(1), 0, v);
    xi.xen_major = v[0] >> 16;
    xi.xen_minor = v[0] & MASK(16);
    xen_debug("xen version %d.%d detected", xi.xen_major, xi.xen_minor);

    cpuid(XEN_CPUID_LEAF(2), 0, v);
    if (v[0] != 1) {
        msg_err("xen reporting %d hypercall pages; not supported\n", v[0]);
        return;
    }
    xi.msr_base = v[1];
    xen_debug("msr base 0x%x, features 1 0x%x, features 2 0x%x", xi.msr_base, v[2], v[3]);

#if 0
    cpuid(XEN_CPUID_LEAF(3), 0, v);
    xen_debug("leaf 4, subleaf 0: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(3), 1, v);
    xen_debug("leaf 4, subleaf 1: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(3), 2, v);
    xen_debug("leaf 4, subleaf 2: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(4), 0, v);
    xen_debug("leaf 5: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
    cpuid(XEN_CPUID_LEAF(5), 0, v);
    xen_debug("leaf 6: 0x%x 0x%x 0x%x 0x%x", v[0], v[1], v[2], v[3]);
#endif

    /* install hypercall page */
    u64 hp_phys = physical_from_virtual(&hypercall_page);
    xen_debug("hypercall_page: v 0x%lx, p 0x%lx", u64_from_pointer(&hypercall_page), hp_phys);

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
    xen_debug("reported features map 0x%x", xi.features);

    /* get store page, map it, and retrieve event channel */
    xen_debug("retrieving xenstore page");
    struct xen_hvm_param xen_hvm_param;
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_PFN;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to get xenstore page address (rv %ld)\n", rv);
        return;
    }
    xi.xenstore_paddr = xen_hvm_param.value << PAGELOG;

    xen_debug("xenstore page at phys 0x%lx; allocating virtual page and mapping");
    xi.xenstore_interface = allocate(heap_virtual_page(kh), PAGESIZE);
    assert(xi.xenstore_interface != INVALID_ADDRESS);
    map(u64_from_pointer(xi.xenstore_interface), xi.xenstore_paddr, PAGESIZE, 0, heap_pages(kh));
    xen_debug("xenstore page mapped at %p", xi.xenstore_interface);

    xen_debug("retrieving store event channel");
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_EVTCHN;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to get xenstore event channel (rv %ld)\n", rv);
        return;
    }

    xi.xenstore_evtchn = xen_hvm_param.value;
    xen_debug("event channel %ld, allocating and mapping shared info page", xi.xenstore_evtchn);

    /* shared info page - taking page from identity heap, but could be backed as well */
    xi.shared_info = allocate_zero(heap_pages(kh), PAGESIZE);
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
    xen_debug("shared info page: 0x%lx", u64_from_pointer(xi.shared_info));

    if (!xen_feature_supported(XENFEAT_hvm_callback_vector)) {
        msg_err("HVM callback vector must be supported; xen setup failed (features mask 0x%x)\n",
                xi.features);
        goto out_dealloc_shared_page;
    }

    /* set up interrupt handling path */
    int irq = allocate_u64(interrupt_vectors, 1);
    xen_debug("interrupt vector %d; registering", irq);
    register_interrupt(irq, closure(heap_general(kh), xen_interrupt));

    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_CALLBACK_IRQ;
    xen_hvm_param.value = (2ull << 56) | irq;
    rv = HYPERVISOR_hvm_op(HVMOP_set_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to register event channel interrupt vector (rv %ld)\n", rv);
        goto out_unregister_irq;
    }

#if 0
    /* NetBSD re-reads the set value; not clear why... */
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_CALLBACK_IRQ;
    xen_hvm_param.value = 0;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to retrieve event channel interrupt vector (rv %ld)\n", rv);
        goto out_unregister_irq;
    }
    xen_debug("returned 0x%lx", xen_hvm_param.value);
#endif

    /* register VCPU info */
    xen_debug("registering VCPU info");
    struct vcpu_register_vcpu_info vrvi;
    u64 vci_pa = u64_from_pointer(xi.shared_info->vcpu_info); /* identity, pa == va */
    vrvi.mfn = vci_pa >> PAGELOG;
    vrvi.offset = vci_pa & (PAGESIZE - 1);
    rv = HYPERVISOR_vcpu_op(VCPUOP_register_vcpu_info, 0 /* vcpu0 */, &vrvi);
    if (rv < 0) {
        msg_err("failed to register vcpu info (rv %ld)\n", rv);
        goto out_unregister_irq;
    }

    xen_debug("unmasking xenstore event channel");
    xen_unmask_evtchn(xi.xenstore_evtchn);

    xi.evtchn_handlers = allocate_vector(heap_general(kh), 1);
    assert(xi.evtchn_handlers != INVALID_ADDRESS);

    xen_debug("xen initialization complete");
    xi.initialized = true;
    return;
  out_unregister_irq:
    register_interrupt(irq, 0);
  out_dealloc_shared_page:
    deallocate(heap_pages(kh), xi.shared_info, PAGESIZE);
    xi.shared_info = 0;
}

static inline int evtchn_send(evtchn_port_t port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.port = port;
    return HYPERVISOR_event_channel_op(&op);
}

/* returns bytes written; doesn't block */
static s64 xenstore_write_internal(const void * data, s64 length)
{
    volatile struct xenstore_domain_interface *xsdi = xi.xenstore_interface;
    if (length == 0)
        return 0;
    assert(length > 0);

    s64 result = 0;
    u64 flags = irq_disable_save();

    do {
        u64 produced = xsdi->req_prod - xsdi->req_cons;
        assert(produced <= XENSTORE_RING_SIZE); /* too harsh? recoverable error? */
        u64 offset = MASK_XENSTORE_IDX(xsdi->req_prod);
        u64 navail = XENSTORE_RING_SIZE - MAX(produced, offset);
        if (navail == 0)        /* XXX actually should loop around if truncated at end of ring... */
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
        int rv = evtchn_send(xi.xenstore_evtchn);
        if (rv < 0) {
            result = rv;
            goto out;
        }
        result += nwrite;
    } while (length > 0);

  out:
    irq_restore(flags);
    return result;
}

static s64 xenstore_read_internal(buffer b, s64 length)
{
    volatile struct xenstore_domain_interface *xsdi = xi.xenstore_interface;
    if (length == 0)
        return 0;
    assert(length > 0);

    s64 result = 0;
    u64 flags = irq_disable_save();

    do {
        u64 produced = xsdi->rsp_prod - xsdi->rsp_cons;
        assert(produced <= XENSTORE_RING_SIZE); /* too harsh? recoverable error? */
        u64 offset = MASK_XENSTORE_IDX(xsdi->rsp_cons);
        u64 navail = MIN(produced, XENSTORE_RING_SIZE - offset);
        if (navail == 0) /* XXX actually should loop around if truncated at end of ring... */
            goto out;
        u64 nread = MIN(navail, length);
        if (nread == 0)
            continue;
        read_barrier();     /* XXX verify */
        buffer_write(b, (void*)(xsdi->rsp + offset), nread);
        length -= nread;
        read_barrier();     /* XXX verify */
        xsdi->rsp_cons += nread;
        read_barrier();
        int rv = evtchn_send(xi.xenstore_evtchn);
        if (rv < 0) {
            result = rv;
            goto out;
        }
        result += nread;
    } while (length > 0);

  out:
    irq_restore(flags);
    return result;
}

/*
   xenstore_transaction - Take a buffer of data to write to the
      xenstore as well as a buffer to fill with the response
      data. Call the status handler with the status of the operation.

   xenstore_sync_transaction - same as xenstore_transaction but
      without asynchronous blocking; returns status

*/

static inline status xenstore_sync_write(const void *data, s64 length)
{
    if (length > 0) {
        do {
            s64 r = xenstore_write_internal(data, length);
            if (r < 0)
                return timm("result", "xenstore write failed: rv %ld", r);
            length -= r;
            data += r;
            assert(length >= 0);
            kern_pause();
        } while (length > 0);
    }
    return STATUS_OK;
}

static inline status xenstore_sync_read(buffer b, s64 length)
{
    if (length > 0) {
        do {
            s64 r = xenstore_read_internal(b, length);
            if (r < 0)
                return timm("result", "xenstore read failed: rv %ld", r);
            length -= r;
            assert(length >= 0);
            kern_pause();
        } while (length > 0);
    }
    return STATUS_OK;
}

status xenstore_sync_transaction(enum xsd_sockmsg_type type, buffer request, buffer response)
{
    status s = STATUS_OK;
    struct xsd_sockmsg msg;
    buffer rbuf = allocate_buffer(xi.h, PAGESIZE); // XXX
    assert(rbuf != INVALID_ADDRESS);

    xenstore_debug("%s: type %d, request %p, response %p", __func__, type, request, response);
    msg.tx_id = 0;              /* XXX private, but only 32-bit */
    msg.req_id = 0;
    msg.type = type;
    msg.len = buffer_length(request);

    /* send request */
    s = xenstore_sync_write(&msg, sizeof(msg));
    if (!is_ok(s))
        goto out_dealloc;
    s = xenstore_sync_write(buffer_ref(request, 0), buffer_length(request));
    if (!is_ok(s))
        goto out_dealloc;

    /* receive response */
    s = xenstore_sync_read(rbuf, sizeof(msg));
    if (!is_ok(s))
        goto out_dealloc;

    struct xsd_sockmsg *rmsg = (struct xsd_sockmsg *)buffer_ref(rbuf, 0);
    if (rmsg->type == XS_ERROR) {
        s = timm("result", "xen store error response: \"%s\"", buffer_ref(response, 0));
        goto out_dealloc;
    }

    xenstore_debug("  response header: type %d, req_id %d, tx_id %d, len %d",
                   rmsg->type, rmsg->req_id, rmsg->tx_id, rmsg->len);

    if (rmsg->len > 0) {
        s = xenstore_sync_read(response, rmsg->len);
        if (!is_ok(s))
            goto out_dealloc;
    }
  out_dealloc:
    deallocate_buffer(rbuf);
    return s;
}

status xenstore_request(enum xsd_sockmsg_type type, const char *path, buffer response)
{
    xenstore_debug("%s: type %d, path \"%s\"", __func__, type, path);
//    buffer req = alloca_wrap_buffer(path, runtime_strlen(path) + 1);
    buffer req = wrap_buffer(xi.h, (void*)path, runtime_strlen(path) + 1);
    status s = xenstore_sync_transaction(type, req, response);
    if (!is_ok(s))
        goto out_dealloc;
  out_dealloc:
    unwrap_buffer(xi.h, req);
    return s;
}

static status traverse_directory(heap h, const char * path, tuple node)
{
    xenstore_debug("%s: path \"%s\", node %v", __func__, path, node);
    buffer response = allocate_buffer(h, PAGESIZE);
    status s = xenstore_request(XS_DIRECTORY, path, response);
    if (!is_ok(s))
        goto out; /* XXX should add context */

    /* check for leaf node */
    if (buffer_length(response) == 0) {
        s = xenstore_request(XS_READ, path, response);
        if (!is_ok(s))
            goto out;
        if (buffer_length(response) > 0)
            table_set(node, sym(value), response); /* don't free response */
        else
            deallocate_buffer(response);
        return STATUS_OK;
    }

    char splice[256];
    int path_len = runtime_strlen(path);
    runtime_memcpy(splice, path, path_len);
    splice[path_len++] = '/';

    do {
        char * child = buffer_ref(response, 0);
        int child_len = runtime_strlen(child);
        tuple child_node = allocate_tuple();
        runtime_memcpy(splice + path_len, child, child_len);
        splice[path_len + child_len] = '\0';

        table_set(node, sym_this(child), child_node);
        s = traverse_directory(h, splice, child_node);
        if (!is_ok(s))
            goto out;
        buffer_consume(response, child_len + 1);
    } while (buffer_length(response) > 0 && *(u8 *)buffer_ref(response, 0) != '\0');

  out:
    deallocate_buffer(response);
    return s;
}

status xen_probe_devices(void)
{
    xen_debug("probing xen device tree from xenstored");
    assert(xi.device_tree == 0);
    tuple node = allocate_tuple();
    xi.device_tree = node;

    status s = traverse_directory(xi.h, "device", node);
    if (!is_ok(s))
        return s;
    xen_debug("success; result: %v\n", node);
    return s;
}
