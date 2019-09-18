#include <runtime.h>
#include <x86_64.h>
#include <page.h>

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

#include "xen_internal.h"

typedef struct xen_platform_info {
    heap    h;                  /* general heap for internal use */

    /* version and features */
    u16     xen_major;
    u16     xen_minor;
    u32     last_leaf;
    u32     msr_base;
    u32     features;

    /* event channel interface / PV interrupts */
    volatile struct shared_info *shared_info;

    /* xenstore page and event channel */
    volatile struct xenstore_domain_interface *xenstore_interface;
    u64    xenstore_paddr;
    u64    xenstore_evtchn;
    vector evtchn_handlers;

    /* grant table */
    struct gtab {
        vector pages;
        u32 n_entries;
        u16 max_pages;
        grant_entry_v2_t *table;
        heap entry_heap;
    } gtab;

    /* probed devices and registered drivers */
    tuple       device_tree;
    struct list xenbus_list;
    struct list driver_list;

    /* XXX could make generalized status */
    boolean initialized;
} *xen_platform_info;

#define XEN_DRIVER_NAME_MAX 16
typedef struct xen_driver {
    struct list l;
    const char name[XEN_DRIVER_NAME_MAX + 1]; /* XXX make symbol? */
    xen_device_probe probe;
} *xen_driver;

#if 0
typedef struct xenbus_device {
    struct list l;
    char *
} *xenbus_device;
#endif

struct xen_platform_info xen_info;

boolean xen_feature_supported(int feature)
{
    return (xen_info.features & U64_FROM_BIT(feature)) != 0;
}

boolean xen_detected(void)
{
    return xen_info.initialized;
}

extern u64 hypercall_page;

static CLOSURE_0_0(xen_interrupt, void);
static void xen_interrupt(void)
{
    volatile struct shared_info *si = xen_info.shared_info;
    volatile struct vcpu_info *vci = &xen_info.shared_info->vcpu_info[0]; /* hardwired at this point */

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
                thunk handler = vector_get(xen_info.evtchn_handlers, i2);
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
    evtchn_op_t eop;
    eop.cmd = EVTCHNOP_unmask;
    eop.u.unmask.port = evtchn;
    int rv = HYPERVISOR_event_channel_op(&eop);
    if (rv != 0) {
        msg_err("failed to unmask evtchn %d; rv %ld\n", evtchn, rv);
        return false;
    }
    return true;
}

#define GTAB_RESERVED_ENTRIES 8

static boolean xen_grant_init(kernel_heaps kh)
{
    struct gtab *gt = &xen_info.gtab;
    struct gnttab_query_size qs;
    qs.dom = DOMID_SELF;
    int rv = HYPERVISOR_grant_table_op(GNTTABOP_query_size, &qs, 1);
    if (rv < 0) {
        msg_err("failed to query grant table size (rv %d)\n", rv);
        return false;
    }
    if (qs.status != GNTST_okay) {
        msg_err("grant table query returned error status %d\n", qs.status);
        return false;
    }
    gt->n_entries = qs.max_nr_frames * (PAGESIZE / sizeof(grant_entry_v2_t));

    /* On our current platforms, this is typically 32 pages / 128kB. */
    gt->table = allocate(heap_backed(kh), qs.max_nr_frames * PAGESIZE);
    if (gt->table == INVALID_ADDRESS) {
        msg_err("failed to allocate grant table\n");
        return false;
    }

    /* Allocate grant entry allocator. */
    gt->entry_heap = create_id_heap(heap_general(kh), GTAB_RESERVED_ENTRIES,
                                    gt->n_entries - GTAB_RESERVED_ENTRIES, 1);
    if (gt->entry_heap == INVALID_ADDRESS) {
        msg_err("failed to allocate grant table occupancy heap\n");
        goto fail_dealloc_table;
    }

    /* We have this feature on the platforms we care about now, but we
       can add support for the other case if need be. */
    if (!xen_feature_supported(XENFEAT_auto_translated_physmap)) {
        msg_err("auto translated physmap feature required\n");
        goto fail_dealloc_heap;
    }

    /* Other implementations add a page at a time as required. For
       simplicity, we're going to add them all on initialization. */
    for (int p = 0; p < qs.max_nr_frames; p++) {
        /* We know at the moment that backed is physically contiguous,
           but best not to not assume in case this changes. */
        u64 phys = physical_from_virtual(((void *)gt->table) + p * PAGESIZE);
        struct xen_add_to_physmap xatp;
        xatp.domid = DOMID_SELF;
        xatp.space = XENMAPSPACE_grant_table;
        xatp.idx = p;
        xatp.gpfn = phys >> PAGELOG;
        rv = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
        if (rv < 0) {
            msg_err("failed to add grant table page (rv %ld)\n", rv);
            goto fail_dealloc_heap;
        }
    }
    return true;
  fail_dealloc_heap:
    destroy_heap(gt->entry_heap);
  fail_dealloc_table:
    deallocate(heap_backed(kh), gt->table, qs.max_nr_frames * PAGESIZE);
    return false;
}

/* returns 0 on alloc fail */
grant_ref_t xen_grant_access(u16 domid, u64 phys, boolean readonly)
{
    struct gtab *gt = &xen_info.gtab;
    grant_ref_t ref = allocate_u64(gt->entry_heap, 1);
    if (ref == INVALID_PHYSICAL)
        return 0;
    gt->table[ref].hdr.domid = domid;
    gt->table[ref].full_page.frame = phys >> PAGELOG;
    write_barrier();
    gt->table[ref].hdr.flags = GTF_permit_access | (readonly ? GTF_readonly : 0);
    return ref;
}

void xen_detect(kernel_heaps kh)
{
    u32 v[4];
    xen_info.initialized = false;
    xen_info.h = heap_general(kh);
    xen_debug("checking for xen cpuid leaves");
    cpuid(XEN_CPUID_FIRST_LEAF, 0, v);
    if (!(v[1] == XEN_CPUID_SIGNATURE_EBX &&
          v[2] == XEN_CPUID_SIGNATURE_ECX &&
          v[3] == XEN_CPUID_SIGNATURE_EDX)) {
        xen_debug("no signature match; xen not detected");
        return;
    }

    xen_info.last_leaf = v[0];

    cpuid(XEN_CPUID_LEAF(1), 0, v);
    xen_info.xen_major = v[0] >> 16;
    xen_info.xen_minor = v[0] & MASK(16);
    xen_debug("xen version %d.%d detected", xen_info.xen_major, xen_info.xen_minor);

    cpuid(XEN_CPUID_LEAF(2), 0, v);
    if (v[0] != 1) {
        msg_err("xen reporting %d hypercall pages; not supported\n", v[0]);
        return;
    }
    xen_info.msr_base = v[1];
    xen_debug("msr base 0x%x, features 1 0x%x, features 2 0x%x", xen_info.msr_base, v[2], v[3]);

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
    write_msr(xen_info.msr_base, hp_phys);

    /* get xen features */
    build_assert(XENFEAT_NR_SUBMAPS == 1);
    struct xen_feature_info xfi;
    xfi.submap_idx = 0;
    int rv = HYPERVISOR_xen_version(XENVER_get_features, &xfi);
    if (rv < 0) {
        msg_err("failed to get xen features map (rv %ld)\n", rv);
        return;
    }
    xen_info.features = xfi.submap;
    xen_debug("reported features map 0x%x", xen_info.features);

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
    xen_info.xenstore_paddr = xen_hvm_param.value << PAGELOG;

    xen_debug("xenstore page at phys 0x%lx; allocating virtual page and mapping");
    xen_info.xenstore_interface = allocate(heap_virtual_page(kh), PAGESIZE);
    assert(xen_info.xenstore_interface != INVALID_ADDRESS);
    map(u64_from_pointer(xen_info.xenstore_interface), xen_info.xenstore_paddr, PAGESIZE, 0, heap_pages(kh));
    xen_debug("xenstore page mapped at %p", xen_info.xenstore_interface);

    xen_debug("retrieving store event channel");
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_EVTCHN;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("failed to get xenstore event channel (rv %ld)\n", rv);
        return;
    }

    xen_info.xenstore_evtchn = xen_hvm_param.value;
    xen_debug("event channel %ld, allocating and mapping shared info page", xen_info.xenstore_evtchn);

    /* shared info page - taking page from identity heap, but could be backed as well */
    xen_info.shared_info = allocate_zero(heap_pages(kh), PAGESIZE);
    assert(xen_info.shared_info != INVALID_ADDRESS);
    xen_add_to_physmap_t xatp;
    xatp.domid = DOMID_SELF;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.idx = 0;
    xatp.gpfn = u64_from_pointer(xen_info.shared_info) >> PAGELOG; /* identity heap, v == p */
    rv = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
    if (rv < 0) {
        msg_err("failed to add shared info map (rv %ld)\n", rv);
        goto out_dealloc_shared_page;
    }
    xen_debug("shared info page: 0x%lx", u64_from_pointer(xen_info.shared_info));

    if (!xen_feature_supported(XENFEAT_hvm_callback_vector)) {
        msg_err("HVM callback vector must be supported; xen setup failed (features mask 0x%x)\n",
                xen_info.features);
        goto out_dealloc_shared_page;
    }

    /* set up interrupt handling path */
    int irq = allocate_interrupt();
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
    u64 vci_pa = u64_from_pointer(xen_info.shared_info->vcpu_info); /* identity, pa == va */
    vrvi.mfn = vci_pa >> PAGELOG;
    vrvi.offset = vci_pa & (PAGESIZE - 1);
    rv = HYPERVISOR_vcpu_op(VCPUOP_register_vcpu_info, 0 /* vcpu0 */, &vrvi);
    if (rv < 0) {
        msg_err("failed to register vcpu info (rv %ld)\n", rv);
        goto out_unregister_irq;
    }

    xen_debug("unmasking xenstore event channel");
    xen_unmask_evtchn(xen_info.xenstore_evtchn);

    xen_info.evtchn_handlers = allocate_vector(heap_general(kh), 1);
    assert(xen_info.evtchn_handlers != INVALID_ADDRESS);

    if (!xen_grant_init(kh)) {
        msg_err("failed to set up grant tables\n");
        goto out_unregister_irq;
    }

    xen_debug("xen initialization complete");
    list_init(&xen_info.driver_list);
    xen_info.initialized = true;
    return;
  out_unregister_irq:
    register_interrupt(irq, 0);
  out_dealloc_shared_page:
    deallocate(heap_pages(kh), xen_info.shared_info, PAGESIZE);
    xen_info.shared_info = 0;
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
    volatile struct xenstore_domain_interface *xsdi = xen_info.xenstore_interface;
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
        write_barrier();
        xsdi->req_prod += nwrite;
        write_barrier();
        int rv = evtchn_send(xen_info.xenstore_evtchn);
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
    volatile struct xenstore_domain_interface *xsdi = xen_info.xenstore_interface;
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
        read_barrier();
        buffer_write(b, (void*)(xsdi->rsp + offset), nread);
        length -= nread;
        write_barrier();
        xsdi->rsp_cons += nread;
        write_barrier();
        int rv = evtchn_send(xen_info.xenstore_evtchn);
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

/* Note that both request and response buffers enclose a zero terminator. */
status xenstore_sync_request(enum xsd_sockmsg_type type, buffer request, buffer response)
{
    status s = STATUS_OK;
    struct xsd_sockmsg msg;
    buffer rbuf = allocate_buffer(xen_info.h, PAGESIZE); // XXX
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
    xenstore_debug("  response header: type %d, req_id %d, tx_id %d, len %d",
                   rmsg->type, rmsg->req_id, rmsg->tx_id, rmsg->len);

    if (rmsg->len > 0) {
        s = xenstore_sync_read(response, rmsg->len);
        if (!is_ok(s))
            goto out_dealloc;
    }

    if (rmsg->type == XS_ERROR) {
        s = timm("result", "xen store error response: \"%s\"", buffer_ref(response, 0));
        goto out_dealloc;
    }
  out_dealloc:
    deallocate_buffer(rbuf);
    return s;
}

static status traverse_directory_internal(heap h, buffer path, tuple *parent)
{
    xenstore_debug("%s: path \"%s\"", __func__, path);
    buffer response = allocate_buffer(h, PAGESIZE);

    status s = xenstore_sync_request(XS_DIRECTORY, path, response);
    if (!is_ok(s))
        goto out; /* XXX should add context to status */

    if (buffer_length(response) == 0) {
        *parent = 0;            /* indicate zero response; leaf node */
        goto out;
    }

    *parent = allocate_tuple();

    buffer splice = allocate_buffer(h, buffer_length(path) + 16);
    buffer_write(splice, buffer_ref(path, 0), buffer_length(path) - 1);
    push_u8(splice, '/');
    bytes splice_saved_end = splice->end;    /* XXX kind of a violation; add to buffer interface here */

    do {
        char * child = buffer_ref(response, 0);
        int child_len = runtime_strlen(child) + 1;
        buffer_write(splice, child, child_len);

        value child_node = 0;
        s = traverse_directory_internal(h, splice, (tuple *)&child_node);
        if (!is_ok(s))
            goto out;

        if (!child_node) {
            /* leaf node, read content */
            buffer leaf_value = allocate_buffer(h, 8);
            assert(leaf_value != INVALID_ADDRESS); /* XXX iron out inconsistencies */
            s = xenstore_sync_request(XS_READ, splice, leaf_value);
            if (!is_ok(s)) {
                deallocate_buffer(leaf_value);
                goto out_slice;
            }
            child_node = (value)leaf_value;
        }
        table_set(*parent, sym_this(child), child_node);
        buffer_consume(response, child_len);
        splice->end = splice_saved_end; /* XXX see above */
    } while (buffer_length(response) > 0 && *(u8 *)buffer_ref(response, 0) != '\0');
  out_slice:
    deallocate_buffer(splice);
  out:
    deallocate_buffer(response);
    return s;
}

static inline status traverse_directory(heap h, const char * path, tuple *node)
{
    return traverse_directory_internal(h, alloca_wrap_buffer(path, runtime_strlen(path) + 1), node);
}

status xen_probe_devices(void)
{
    xen_debug("probing xen device tree from xenstored");
    assert(xen_info.device_tree == 0);
    tuple node = 0;
    status s = traverse_directory(xen_info.h, "device", &node);
    if (!is_ok(s))
        return s;
    if (!node)
        return timm("result", "failed to parse directory");

    xen_info.device_tree = node;
    xen_debug("success; result: %v\n", node);

#if 0
    buffer buf = allocate_buffer(xen_info.h, PAGESIZE);
    char * path = "/local/domain/0/backend/vif/306/0/state";
    s = xenstore_sync_request(XS_READ, alloca_wrap_buffer(path, runtime_strlen(path) + 1), buf);
    if (!is_ok(s)) {
        rprintf("backed read failed: %v\n", s);
    } else {
        rprintf("succeeded: %b\n", buf);
    }
#endif

    table_foreach(node, k, v) {
        if (tagof(v) != tag_tuple)
            continue;
        list_foreach(&xen_info.driver_list, l) {
            xen_driver xd = struct_from_list(l, xen_driver, l);
            /* XXX must be a cleaner way to compare symbols? */
            string s = symbol_string(k);
            if (runtime_memcmp(buffer_ref(s, 0), xd->name, MIN(buffer_length(s), XEN_DRIVER_NAME_MAX)))
                continue;
            table_foreach(v, k2, v2) {
                u64 id;
                if (!u64_from_value(symbol_string(k2), &id)) {
                    return timm("result", "failed to parse device id \"%v\"", symbol_string(k2));
                }
                xen_debug("driver match, id %d, value %v\n", id, v2);
                apply(xd->probe, (int)id, v2);
            }
        }
    }
    return s;
}

void register_xen_driver(const char *name, xen_device_probe probe)
{
    xen_driver xd = allocate(xen_info.h, sizeof(struct xen_driver));
    assert(xd != INVALID_ADDRESS);
    int namelen = runtime_strlen(name);
    assert(namelen <= XEN_DRIVER_NAME_MAX);
    runtime_memcpy((void*)xd->name, name, namelen);
    xd->probe = probe;
    list_insert_before(&xen_info.driver_list, &xd->l);
}

