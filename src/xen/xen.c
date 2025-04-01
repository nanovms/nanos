#include <kernel.h>
#include <pvclock.h>

//#define XEN_DEBUG
#ifdef XEN_DEBUG
#define xen_debug(x, ...) do {tprintf(sym(xen), 0, ss(x "\n"), ##__VA_ARGS__);} while(0)
#else
#define xen_debug(x, ...)
#endif

//#define XENSTORE_DEBUG
#if defined(XENSTORE_DEBUG) && defined(XEN_DEBUG)
#define xenstore_debug xen_debug
#else
#define xenstore_debug(x, ...)
#endif

//#define XEN_INT_DEBUG
#if defined(XEN_INT_DEBUG) && defined(XEN_DEBUG)
#define xenint_debug xen_debug
#else
#define xenint_debug(x, ...)
#endif

#include "xen_internal.h"

declare_closure_struct(1, 0, void, xen_shutdown_handler,
                       buffer, b);

status xenstore_watch(buffer path, xenstore_watch_handler handler, boolean watch);

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
    u64           xenstore_paddr;
    evtchn_port_t xenstore_evtchn;
    struct spinlock xenstore_lock;
    vector        evtchn_handlers;

    closure_struct(xenstore_watch_handler, watch_handler);
    closure_struct(thunk, scan_service);
    closure_struct(xenstore_watch_handler, shutdown_watcher);
    closure_struct(xen_shutdown_handler, shutdown_handler);
    u64 scanning;

    /* grant table */
    struct gtab {
        vector pages;
        u32 n_entries;
        u16 max_pages;
        grant_entry_v1_t *table;
        heap entry_heap;
    } gtab;

    /* probed devices and registered drivers */
    tuple       device_tree;
    struct list xenbus_list;
    struct list driver_list;

    /* XXX could make generalized status */
    boolean initialized;
} *xen_platform_info;

typedef struct xen_driver {
    struct list l;
    sstring name;
    xen_device_probe probe;
} *xen_driver;

struct xen_platform_info xen_info;

#define xenstore_lock()     u64 _irqflags = spin_lock_irq(&xen_info.xenstore_lock)
#define xenstore_unlock()   spin_unlock_irq(&xen_info.xenstore_lock, _irqflags)

boolean xen_feature_supported(int feature)
{
    return (xen_info.features & U64_FROM_BIT(feature)) != 0;
}

boolean xen_detected(void)
{
    return xen_info.initialized;
}

extern u64 hypercall_page;

closure_function(0, 0, void, xen_interrupt)
{
    int vcpu = current_cpu()->id;
    volatile struct shared_info *si = xen_info.shared_info;
    volatile struct vcpu_info *vci = &xen_info.shared_info->vcpu_info[vcpu];

    xenint_debug("xen_interrupt enter");
    assert(vci->evtchn_upcall_pending);
    while (vci->evtchn_upcall_pending) {
        vci->evtchn_upcall_mask = 1;
        vci->evtchn_upcall_pending = 0;
        u64 l1_pending = __sync_lock_test_and_set(&vci->evtchn_pending_sel, 0); /* XXX check asm */
        /* this may not process in the right order, or it might not matter - care later */
        bitmap_word_foreach_set(l1_pending, bit1, i1, 0) {
            (void)i1;
            /* TODO: any per-cpu event mask would be also applied here... */
            u64 l2_pending = si->evtchn_pending[bit1] & ~si->evtchn_mask[bit1];
            xenint_debug("pending 0x%lx, mask 0x%lx, masked 0x%lx",
                         si->evtchn_pending[bit1], si->evtchn_mask[bit1], l2_pending);
            __sync_and_and_fetch(&si->evtchn_pending[bit1], ~l2_pending);
            u64 l2_offset = bit1 << 6;
            bitmap_word_foreach_set(l2_pending, bit2, i2, l2_offset) {
                (void)i2;
                xenint_debug("  int %d pending", i2);
                thunk handler = vector_get(xen_info.evtchn_handlers, i2);
                if (handler) {
                    xenint_debug("  evtchn %d: applying handler %p", i2, handler);
                    apply(handler);
                } else {
                    /* XXX we have an issue with seemingly spurious interrupts at evtchn >= 2048... */
                    xenint_debug("  evtchn %d: spurious interrupt", i2);
                    si->evtchn_mask[bit1] |= U64_FROM_BIT(bit2);
                }
            }
        }
        vci->evtchn_upcall_mask = 0;
    }
    xenint_debug("xen_interrupt exit");
}

void xen_register_evtchn_handler(evtchn_port_t evtchn, thunk handler)
{
    assert(vector_set(xen_info.evtchn_handlers, evtchn, handler));
}

int xen_unmask_evtchn(evtchn_port_t evtchn)
{
    assert(evtchn > 0 && evtchn < EVTCHN_2L_NR_CHANNELS);
    evtchn_op_t eop;
    eop.cmd = EVTCHNOP_unmask;
    eop.u.unmask.port = evtchn;
    return HYPERVISOR_event_channel_op(&eop);
}

int xen_close_evtchn(evtchn_port_t evtchn)
{
    vector_set(xen_info.evtchn_handlers, evtchn, 0);
    evtchn_op_t eop;
    eop.cmd = EVTCHNOP_close;
    eop.u.close.port = evtchn;
    return HYPERVISOR_event_channel_op(&eop);
}

#define GTAB_RESERVED_ENTRIES 8

static boolean xen_grant_init(kernel_heaps kh)
{
    struct gtab *gt = &xen_info.gtab;
    struct gnttab_query_size qs;
    qs.dom = DOMID_SELF;
    int rv = HYPERVISOR_grant_table_op(GNTTABOP_query_size, &qs, 1);
    if (rv < 0) {
        msg_err("xen: failed to query grant table size (rv %d)", rv);
        return false;
    }
    if (qs.status != GNTST_okay) {
        msg_err("xen: grant table query returned error status %d", qs.status);
        return false;
    }
    gt->n_entries = qs.max_nr_frames * (PAGESIZE / sizeof(grant_entry_v2_t));

    /* On our current platforms, this is typically 32 pages / 128kB. */
    heap table_heap = (heap)heap_linear_backed(kh);
    gt->table = allocate_zero(table_heap, qs.max_nr_frames * PAGESIZE);
    if (gt->table == INVALID_ADDRESS) {
        msg_err("xen: failed to allocate grant table");
        return false;
    }
    xen_debug("%s: table v 0x%lx, p 0x%lx", func_ss, gt->table, physical_from_virtual(gt->table));

    /* Allocate grant entry allocator. */
    heap h = heap_locked(kh);
    gt->entry_heap = (heap)create_id_heap(h, h, GTAB_RESERVED_ENTRIES + 1,
                                          gt->n_entries - GTAB_RESERVED_ENTRIES, 1, true);
    if (gt->entry_heap == INVALID_ADDRESS) {
        msg_err("xen: failed to allocate grant table occupancy heap");
        goto fail_dealloc_table;
    }

    /* We have this feature on the platforms we care about now, but we
       can add support for the other case if need be. */
    if (!xen_feature_supported(XENFEAT_auto_translated_physmap)) {
        msg_err("%s error: auto translated physmap feature required", func_ss);
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
        xen_debug("grant page %d, gpfn %x", xatp.idx, xatp.gpfn);
        rv = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
        if (rv < 0) {
            msg_err("xen: failed to add grant table page (rv %d)", rv);
            goto fail_dealloc_heap;
        }
    }
    return true;
  fail_dealloc_heap:
    destroy_heap(gt->entry_heap);
  fail_dealloc_table:
    deallocate(table_heap, gt->table, qs.max_nr_frames * PAGESIZE);
    return false;
}

/* returns 0 on alloc fail */
/* optimization: create a gntref free list / fifo of sorts */
grant_ref_t xen_grant_page_access(u16 domid, u64 phys, boolean readonly)
{
    struct gtab *gt = &xen_info.gtab;
    u64 ref = allocate_u64(gt->entry_heap, 1);
    if (ref == INVALID_PHYSICAL)
        return 0;
    gt->table[ref].domid = domid;
    gt->table[ref].frame = phys >> PAGELOG;
    write_barrier();
    gt->table[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);
    return (grant_ref_t)ref;
}

void xen_revoke_page_access(grant_ref_t ref)
{
    assert(ref > 8 && ref != -1);
    xen_info.gtab.table[ref].flags = 0;
    memory_barrier();
    deallocate_u64(xen_info.gtab.entry_heap, ref, 1);
}

/* Reportedly, Xen timers can fire up to 100us early. */
#define XEN_TIMER_SLOP_NS 100000
closure_func_basic(clock_timer, void, xen_runloop_timer,
                   timestamp duration)
{
    u64 n = pvclock_now_ns();
    u64 expiry = n + MAX(nsec_from_timestamp(duration), XEN_TIMER_SLOP_NS);
    int vcpu = current_cpu()->id;

    xen_debug("%s: cpu %d now %T, expiry %T", func_ss, vcpu, nanoseconds(n), nanoseconds(expiry));
    struct vcpu_set_singleshot_timer sst;
    sst.timeout_abs_ns = expiry;
    sst.flags = 0;
    int rv = HYPERVISOR_vcpu_op(VCPUOP_set_singleshot_timer, vcpu, &sst);
    if (rv != 0) {
        msg_err("%s failed on cpu %d; rv %d", func_ss, vcpu, rv);
    }
}

closure_func_basic(thunk, void, xen_runloop_timer_handler)
{
    xen_debug("%s: cpu %d now %T", func_ss, current_cpu()->id, nanoseconds(pvclock_now_ns()));
    schedule_timer_service();
}

static s64 xenstore_read_internal(buffer b, s64 length);

static void xenstore_watch_event(struct xsd_sockmsg *msg)
{
    /* read message data (xenstore path followed by watch token) */
    u64 length = msg->len;
    buffer b = little_stack_buffer(length);
    do {
        s64 r = xenstore_read_internal(b, length);
        if (r < 0) {
            msg_err("%s: failed to read", func_ss);
            return;
        }
        length -= r;
        kern_pause();
    } while (length > 0);
    sstring path = sstring_from_cstring(buffer_ref(b, 0), msg->len);
    bytes path_len = path.len;
    if (path_len == msg->len) {
        msg_err("%s: no string terminator for xenstore path", func_ss);
        return;
    }
    buffer_consume(b, path_len + 1);
    u64 token;
    if (!parse_int(b, 16, &token)) {
        msg_err("%s: failed to parse token", func_ss);
        return;
    }

    xenstore_watch_handler handler = pointer_from_u64(token);
    xenstore_debug("%s: path %s, handler %F", func_ss, path, handler);
    apply(handler, path);
}

closure_func_basic(thunk, void, xenstore_evtchn_handler)
{
    xenstore_debug("%s", func_ss);
    xenstore_lock();
    struct xsd_sockmsg *msg;
    buffer msgbuf = little_stack_buffer(sizeof(*msg));
    if (xenstore_read_internal(msgbuf, sizeof(*msg)) != sizeof(*msg))
        goto out;
    msg = buffer_ref(msgbuf, 0);
    xenstore_debug("  msg type %d, msg len %d", msg->type, msg->len);
    if (msg->type == XS_WATCH_EVENT) {
        xenstore_watch_event(msg);
    } else {
        /* unexpected message type: discard message data */
        volatile struct xenstore_domain_interface *xsdi = xen_info.xenstore_interface;
        xsdi->rsp_cons += msg->len;
        write_barrier();
        xen_notify_evtchn(xen_info.xenstore_evtchn);
    }
  out:
    xenstore_unlock();
}

static int xen_setup_vcpu(int vcpu, u64 shared_info_phys)
{
    assert(vcpu < XEN_LEGACY_MAX_VCPUS);
    /* register VCPU info */
    xen_debug("registering VCPU info for cpu %d", vcpu);
    struct vcpu_register_vcpu_info vrvi;
    u64 vci_pa = shared_info_phys + offsetof(struct shared_info *, vcpu_info) +
        sizeof(struct vcpu_info) * vcpu;
    vrvi.mfn = vci_pa >> PAGELOG;
    vrvi.offset = vci_pa & (PAGESIZE - 1);
    int rv = HYPERVISOR_vcpu_op(VCPUOP_register_vcpu_info, vcpu, &vrvi);
    if (rv < 0) {
        msg_err("xen: failed to register vcpu info for cpu %d (rv %d)", vcpu, rv);
        return rv;
    }

    /* timer setup */
    /* attempt to disable periodic (tick) timer; won't work in older Xens... */
    xen_debug("stopping periodic tick timer on cpu %d...", vcpu);
    rv = HYPERVISOR_vcpu_op(VCPUOP_stop_periodic_timer, vcpu, 0);
    if (rv < 0) {
        msg_err("xen: unable to stop periodic timer on cpu %d (rv %d)", vcpu, rv);
        return rv;
    }

    evtchn_op_t eop;
    eop.cmd = EVTCHNOP_bind_virq;
    eop.u.bind_virq.virq = VIRQ_TIMER;
    eop.u.bind_virq.vcpu = vcpu;
    rv = HYPERVISOR_event_channel_op(&eop);
    if (rv < 0) {
        msg_err("xen: failed to bind virtual timer IRQ for cpu %d (rv %d)", vcpu, rv);
        return rv;
    }
    evtchn_port_t timer_evtchn = eop.u.bind_virq.port;
    xen_debug("cpu %d timer event channel %d", vcpu, timer_evtchn);
    xen_register_evtchn_handler(timer_evtchn,
                                closure_func(xen_info.h, thunk, xen_runloop_timer_handler));
    assert(xen_unmask_evtchn(timer_evtchn) == 0);
    return 0;
}

closure_function(1, 0, void, xen_per_cpu_init,
                 u64, shared_info_phys)
{
    xen_setup_vcpu(current_cpu()->id, bound(shared_info_phys));
}

define_closure_function(1, 0, void, xen_shutdown_handler,
                 buffer, b)
{
    buffer rsp = bound(b);
    buffer_clear(rsp);
    u32 txid = 0;
    status s = xenstore_transaction_start(&txid);
    if (!is_ok(s))
        return;
    sstring node = ss("shutdown");
    s = xenstore_read_string(txid, alloca_wrap_cstring("control"), node, rsp);
    if (!is_ok(s) || buffer_length(rsp) == 0)
        goto out;
    s = xenstore_sync_printf(txid, alloca_wrap_cstring("control"), node, sstring_empty());
out:
    xenstore_transaction_end(txid, is_ok(s) ? false : true);
    if (!buffer_strcmp(rsp, "poweroff") || !buffer_strcmp(rsp, "halt"))
        kernel_powerdown();
}

closure_func_basic(xenstore_watch_handler, void, xen_shutdown_watcher,
                   sstring path)
{
    async_apply_bh((thunk)&xen_info.shutdown_handler);
}

boolean xen_detect(kernel_heaps kh)
{
    u32 v[4];
    xen_info.initialized = false;
    xen_info.h = heap_locked(kh);
    xen_debug("checking for xen cpuid leaves");
    cpuid(XEN_CPUID_FIRST_LEAF, 0, v);
    if (!(v[1] == XEN_CPUID_SIGNATURE_EBX &&
          v[2] == XEN_CPUID_SIGNATURE_ECX &&
          v[3] == XEN_CPUID_SIGNATURE_EDX)) {
        xen_debug("no signature match; xen not detected");
        return false;
    }

    xen_info.last_leaf = v[0];

    cpuid(XEN_CPUID_LEAF(1), 0, v);
    xen_info.xen_major = v[0] >> 16;
    xen_info.xen_minor = v[0] & MASK(16);
    xen_debug("xen version %d.%d detected", xen_info.xen_major, xen_info.xen_minor);

    cpuid(XEN_CPUID_LEAF(2), 0, v);
    if (v[0] != 1) {
        msg_err("xen reporting %d hypercall pages; not supported", v[0]);
        return false;
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
    write_msr(xen_info.msr_base, hp_phys);

    /* get xen features */
    build_assert(XENFEAT_NR_SUBMAPS == 1);
    struct xen_feature_info xfi;
    xfi.submap_idx = 0;
    int rv = HYPERVISOR_xen_version(XENVER_get_features, &xfi);
    if (rv < 0) {
        msg_err("xen: failed to get features map (rv %d)", rv);
        return false;
    }
    xen_info.features = xfi.submap;
    xen_debug("reported features map 0x%x", xen_info.features);

    if (!xen_feature_supported(XENFEAT_hvm_safe_pvclock)) {
        msg_err("xen failed to init; XENFEAT_hvm_safe_pvclock required");
        return false;
    }

    /* get store page, map it, and retrieve event channel */
    xen_debug("retrieving xenstore page");
    struct xen_hvm_param xen_hvm_param;
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_PFN;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("xen: failed to get xenstore page address (rv %d)", rv);
        return false;
    }
    xen_info.xenstore_paddr = xen_hvm_param.value << PAGELOG;

    xen_debug("xenstore page at phys 0x%lx; allocating virtual page and mapping", xen_info.xenstore_paddr);
    xen_info.xenstore_interface = mem_alloc((heap)heap_virtual_page(kh), PAGESIZE,
                                            MEM_NOWAIT | MEM_NOFAIL);
    map(u64_from_pointer(xen_info.xenstore_interface), xen_info.xenstore_paddr, PAGESIZE,
        pageflags_writable(pageflags_memory()));
    xen_debug("xenstore page mapped at %p", xen_info.xenstore_interface);

    xen_debug("retrieving store event channel");
    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_STORE_EVTCHN;
    rv = HYPERVISOR_hvm_op(HVMOP_get_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("xen: failed to get xenstore event channel (rv %d)", rv);
        return false;
    }

    xen_info.xenstore_evtchn = xen_hvm_param.value;
    xen_debug("event channel %ld, allocating and mapping shared info page", xen_info.xenstore_evtchn);

    heap shared_info_heap = (heap)heap_linear_backed(kh);
    void *shared_info = mem_alloc(shared_info_heap, PAGESIZE, MEM_ZERO | MEM_NOWAIT | MEM_NOFAIL);
    u64 shared_info_phys = physical_from_virtual(shared_info);
    assert(shared_info_phys != INVALID_PHYSICAL);
    xen_info.shared_info = shared_info;
    xen_add_to_physmap_t xatp;
    xatp.domid = DOMID_SELF;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.idx = 0;
    xatp.gpfn = shared_info_phys >> PAGELOG;
    rv = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
    if (rv < 0) {
        msg_err("xen: failed to add shared info map (rv %d)", rv);
        goto out_dealloc_shared_page;
    }
    xen_debug("shared info page: %p, phys 0x%lx", shared_info, shared_info_phys);

    if (!xen_feature_supported(XENFEAT_hvm_callback_vector)) {
        msg_err("xen setup failed: HVM callback vector must be supported (features mask 0x%x)",
                xen_info.features);
        goto out_dealloc_shared_page;
    }

    /* set up interrupt handling path */
    int irq = allocate_interrupt();
    xen_debug("interrupt vector %d; registering", irq);
    register_interrupt(irq, closure(xen_info.h, xen_interrupt), ss("xen"));

    xen_hvm_param.domid = DOMID_SELF;
    xen_hvm_param.index = HVM_PARAM_CALLBACK_IRQ;
    xen_hvm_param.value = (2ull << 56) | irq;
    rv = HYPERVISOR_hvm_op(HVMOP_set_param, &xen_hvm_param);
    if (rv < 0) {
        msg_err("xen: failed to register event channel interrupt vector (rv %d)", rv);
        goto out_unregister_irq;
    }

    xen_info.evtchn_handlers = allocate_vector(xen_info.h, 1);
    assert(xen_info.evtchn_handlers != INVALID_ADDRESS);

    if (xen_setup_vcpu(0, shared_info_phys) < 0)
        goto out_unregister_irq;

    register_platform_clock_timer(closure_func(xen_info.h, clock_timer, xen_runloop_timer),
                                  closure(xen_info.h, xen_per_cpu_init, shared_info_phys));

    /* register pvclock (feature verified above) */
    init_pvclock(xen_info.h, (struct pvclock_vcpu_time_info *)&xen_info.shared_info->vcpu_info[0].time,
                 (struct pvclock_wall_clock *)&xen_info.shared_info->wc_version);

    xen_debug("unmasking xenstore event channel");
    spin_lock_init(&xen_info.xenstore_lock);
    xen_register_evtchn_handler(xen_info.xenstore_evtchn,
                                closure_func(xen_info.h, thunk, xenstore_evtchn_handler));
    assert(xen_unmask_evtchn(xen_info.xenstore_evtchn) == 0);

    if (!xen_grant_init(kh)) {
        msg_err("xen: failed to set up grant tables");
        goto out_unregister_irq;
    }

    init_closure(&xen_info.shutdown_handler, xen_shutdown_handler, allocate_buffer(xen_info.h, 16));
    if (!is_ok(xenstore_watch(alloca_wrap_cstring("control/shutdown"),
                              init_closure_func(&xen_info.shutdown_watcher, xenstore_watch_handler,
                                                xen_shutdown_watcher),
                              true)))
        msg_err("xen: failed to register shutdown handler");

    xen_debug("xen initialization complete");
    list_init(&xen_info.driver_list);
    xen_info.initialized = true;
    return true;
  out_unregister_irq:
    unregister_interrupt(irq);
  out_dealloc_shared_page:
    deallocate(shared_info_heap, xen_info.shared_info, PAGESIZE);
    xen_info.shared_info = 0;
    return false;
}

status xen_allocate_evtchn(domid_t other_id, evtchn_port_t *evtchn)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_alloc_unbound;
    op.u.alloc_unbound.dom = DOMID_SELF;
    op.u.alloc_unbound.remote_dom = other_id;
    op.u.alloc_unbound.port = 0;
    int rv = HYPERVISOR_event_channel_op(&op);
    if (rv == 0) {
        *evtchn = op.u.alloc_unbound.port;
        return STATUS_OK;
    } else {
        return timm("result", "allocate evtchn failed (%d)", rv);
    }
}

int xen_notify_evtchn(evtchn_port_t evtchn)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.port = evtchn;
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

    do {
        u64 produced = xsdi->req_prod - xsdi->req_cons;
        assert(produced <= XENSTORE_RING_SIZE); /* too harsh? recoverable error? */
        u64 offset = MASK_XENSTORE_IDX(xsdi->req_prod);
        u64 navail = XENSTORE_RING_SIZE - MAX(produced, offset);
        if (navail == 0)        /* XXX actually should loop around if truncated at end of ring... */
            break;
        u64 nwrite = MIN(navail, length);
        if (nwrite == 0)
            continue;
        runtime_memcpy((void*)(xsdi->req + offset), data, nwrite);
        data += nwrite;
        length -= nwrite;
        write_barrier();
        xsdi->req_prod += nwrite;
        write_barrier();
        int rv = xen_notify_evtchn(xen_info.xenstore_evtchn);
        if (rv < 0) {
            result = rv;
            break;
        }
        result += nwrite;
    } while (length > 0);

    return result;
}

static s64 xenstore_read_internal(buffer b, s64 length)
{
    volatile struct xenstore_domain_interface *xsdi = xen_info.xenstore_interface;
    if (length == 0)
        return 0;
    assert(length > 0);

    s64 result = 0;

    do {
        u64 produced = xsdi->rsp_prod - xsdi->rsp_cons;
        assert(produced <= XENSTORE_RING_SIZE); /* too harsh? recoverable error? */
        u64 offset = MASK_XENSTORE_IDX(xsdi->rsp_cons);
        u64 navail = MIN(produced, XENSTORE_RING_SIZE - offset);
        if (navail == 0) /* XXX actually should loop around if truncated at end of ring... */
            break;
        u64 nread = MIN(navail, length);
        if (nread == 0)
            continue;
        read_barrier();
        assert(buffer_write(b, (void*)(xsdi->rsp + offset), nread));
        length -= nread;
        write_barrier();
        xsdi->rsp_cons += nread;
        write_barrier();
        int rv = xen_notify_evtchn(xen_info.xenstore_evtchn);
        if (rv < 0) {
            result = rv;
            break;
        }
        result += nread;
    } while (length > 0);

    return result;
}

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
status xenstore_sync_request(u32 tx_id, enum xsd_sockmsg_type type, buffer request, buffer response)
{
    status s = STATUS_OK;
    struct xsd_sockmsg msg;
    buffer rbuf = allocate_buffer(xen_info.h, PAGESIZE); // XXX
    assert(rbuf != INVALID_ADDRESS);
    u32 len = request ? buffer_length(request) : 1;
    void * data = request ? buffer_ref(request, 0) : "";

    xenstore_debug("%s: tx_id %d, type %d, request %p, response %p", func_ss, tx_id, type, request, response);
    msg.tx_id = tx_id;
    msg.req_id = 0;
    msg.type = type;
    msg.len = len;
    xenstore_lock();

    /* send request */
    s = xenstore_sync_write(&msg, sizeof(msg));
    if (!is_ok(s))
        goto out_dealloc;
    s = xenstore_sync_write(data, len);
    if (!is_ok(s))
        goto out_dealloc;

    /* receive response */
    struct xsd_sockmsg *rmsg = (struct xsd_sockmsg *)buffer_ref(rbuf, 0);
    while (true) {
        s = xenstore_sync_read(rbuf, sizeof(msg));
        if (!is_ok(s))
            goto out_dealloc;
        if (rmsg->type == XS_WATCH_EVENT) {
            xenstore_watch_event(rmsg);
            buffer_clear(rbuf);
        } else {
            break;
        }
    }
    xenstore_debug("  response header: type %d, req_id %d, tx_id %d, len %d",
                   rmsg->type, rmsg->req_id, rmsg->tx_id, rmsg->len);

    if (rmsg->len > 0) {
        s = xenstore_sync_read(response, rmsg->len);
        if (!is_ok(s))
            goto out_dealloc;
    }

    if (rmsg->type == XS_ERROR) {
        s = timm("result", "xen store error");
        s = timm_append(s, "errno", "%b", response);
        goto out_dealloc;
    }
  out_dealloc:
    xenstore_unlock();
    deallocate_buffer(rbuf);
    return s;
}

status xenstore_transaction_start(u32 *tx_id)
{
    buffer response = allocate_buffer(xen_info.h, 16);
    status s = xenstore_sync_request(0, XS_TRANSACTION_START, 0, response);
    if (!is_ok(s))
        goto out;
    u64 val;
    if (!u64_from_value(response, &val)) {
        s = timm("result", "%s: failed to parse response \"%b\"", func_ss, response);
        goto out;
    }
    *tx_id = val;
  out:
    deallocate_buffer(response);
    return s;
}

status xenstore_transaction_end(u32 tx_id, boolean abort)
{
    buffer request = alloca_wrap_buffer(abort ? "F" : "T", 2);
    buffer response = allocate_buffer(xen_info.h, 8); /* for error capture */
    status s = xenstore_sync_request(tx_id, XS_TRANSACTION_END, request, response);
    deallocate_buffer(response);
    return s;
}

status xenstore_sync_printf(u32 tx_id, buffer path, sstring node, sstring format, ...)
{
    buffer request = allocate_buffer(xen_info.h, PAGESIZE);
    assert(push_buffer(request, path));
    push_u8(request, '/');
    assert(buffer_write_sstring(request, node));
    push_u8(request, 0);
    vlist a;
    vstart(a, format);
    vbprintf(request, format, &a);
    xenstore_debug("%s: request: \"%b\"", func_ss, request);

    buffer response = allocate_buffer(xen_info.h, 8); /* for error capture */
    status s = xenstore_sync_request(tx_id, XS_WRITE, request, response);
    deallocate_buffer(request);
    deallocate_buffer(response);
    return s;
}

status xenstore_read_u64(u32 tx_id, buffer path, sstring node, u64 *result)
{
    buffer response = allocate_buffer(xen_info.h, 16);
    status s = xenstore_read_string(tx_id, path, node, response);
    if (!is_ok(s))
        goto out;
    u64 val;
    if (!u64_from_value(response, &val)) {
        s = timm("result", "%s: unable to parse int from response \"%b\"", func_ss, response);
        goto out;
    }
    *result = val;
out:
    deallocate_buffer(response);
    return s;
}

status xenstore_read_string(u32 tx_id, buffer path, sstring node, buffer response)
{
    buffer request = allocate_buffer(xen_info.h, 64);
    assert(push_buffer(request, path));
    push_u8(request, '/');
    assert(buffer_write_sstring(request, node));
    push_u8(request, 0);

    status s = xenstore_sync_request(tx_id, XS_READ, request, response);
    if (!is_ok(s))
        goto out;
  out:
    deallocate_buffer(request);
    return s;
}

status xenstore_watch(buffer path, xenstore_watch_handler handler, boolean watch)
{
    buffer request = little_stack_buffer(buffer_length(path) + 18);
    buffer response = allocate_buffer(xen_info.h, 8);
    if (response == INVALID_ADDRESS)
        return timm("result", "failed to allocate memory");
    push_buffer(request, path);
    push_u8(request, 0);
    xenstore_debug("%swatching %b", watch ? sstring_empty() : ss("un"), path);
    bprintf(request, "%lx", handler);   /* the handler address is used as watch token */
    push_u8(request, 0);
    status s = xenstore_sync_request(0, watch ? XS_WATCH : XS_UNWATCH, request, response);
    deallocate_buffer(response);
    return s;
}

status xenbus_get_state(buffer path, XenbusState *state)
{
    assert(path);
    u64 val = 0;
    status s = xenstore_read_u64(0, path, ss("state"), &val);
    if (!is_ok(s))
        *state = XenbusStateUnknown;
    else
        *state = val;
    return s;
}

status xenbus_set_state(u32 tx_id, buffer path, XenbusState newstate)
{
    XenbusState oldstate;
    status s = xenbus_get_state(path, &oldstate);
    if (!is_ok(s))
        return s;
    xen_debug("%s: old %d, new %d", func_ss, oldstate, newstate);
    if (oldstate == newstate)
        return STATUS_OK;
    return xenstore_sync_printf(tx_id, path, ss("state"), ss("%d"), newstate);
}

status xenbus_watch_state(buffer path, xenstore_watch_handler handler, boolean watch)
{
    buffer state_path = little_stack_buffer(buffer_length(path) + 6);
    push_buffer(state_path, path);
    buffer_write_cstring(state_path, "/state");
    return xenstore_watch(state_path, handler, watch);
}

status xendev_attach(xen_dev xd, int id, buffer frontend, tuple meta)
{
    xd->if_id = id;
    xd->frontend = frontend;
    u64 val;
    if (!get_u64(meta, sym(backend-id), &val))
        return timm("result", "unable to find backend-id");
    xd->backend_id = val;
    string b = get_string(meta, sym(backend));
    if (!b)
        return timm("result", "unable to find backend path");
    xd->backend = b;

    /* check if the backend is ready for us
       XXX This should poll or, better yet, set up an asynchronous xenstore watch...
     */
    XenbusState state;
    status s = xenbus_get_state(xd->backend, &state);
    if (!is_ok(s))
        return s;
    if (state != XenbusStateInitWait)
        return timm("result", "xennet %d backend not ready yet (state %d)", id, state);

    return STATUS_OK;
}

static status traverse_directory_internal(heap h, buffer path, tuple *parent)
{
    xenstore_debug("%s: path \"%b\"", func_ss, path);
    buffer response = allocate_buffer(h, PAGESIZE);

    status s = xenstore_sync_request(0, XS_DIRECTORY, path, response);
    if (!is_ok(s))
        goto out; /* XXX should add context to status */

    if (buffer_length(response) == 0) {
        *parent = 0;            /* indicate zero response; leaf node */
        goto out;
    }

    if (!*parent)
        *parent = allocate_tuple();

    buffer splice = allocate_buffer(h, buffer_length(path) + 16);
    assert(buffer_write(splice, buffer_ref(path, 0), buffer_length(path) - 1));
    push_u8(splice, '/');
    bytes splice_saved_end = splice->end;    /* XXX violation; amend buffer interface */

    do {
        sstring child = sstring_from_cstring(buffer_ref(response, 0), buffer_length(response));
        int child_len = child.len + 1;
        assert(buffer_write(splice, child.ptr, child_len));

        value child_node = get(*parent, sym_sstring(child));
        tuple t = child_node;
        s = traverse_directory_internal(h, splice, &t);
        if (!is_ok(s))
            goto out;

        if (!t) {
            /* leaf node, read content */
            buffer leaf_value;
            if (!child_node) {
                leaf_value = allocate_buffer(h, 8);
                if (leaf_value == INVALID_ADDRESS) {
                    s = timm("result", "failed to allocate memory");
                    goto out_slice;
                }
            } else {
                buffer_clear(child_node);
                leaf_value = child_node;
            }
            s = xenstore_sync_request(0, XS_READ, splice, leaf_value);
            if (!is_ok(s)) {
                if (!child_node)
                    deallocate_buffer(leaf_value);
                goto out_slice;
            }
            child_node = (value)leaf_value;
        } else {
            child_node = t;
        }
        set(*parent, sym_sstring(child), child_node);
        buffer_consume(response, child_len);
        splice->end = splice_saved_end; /* XXX see above */
    } while (buffer_length(response) > 0 && *(u8 *)buffer_ref(response, 0) != '\0');
  out_slice:
    deallocate_buffer(splice);
  out:
    deallocate_buffer(response);
    return s;
}

#define traverse_directory(h, path, node)   ({                                      \
    assert_string_literal(path);                                                    \
    traverse_directory_internal(h, alloca_wrap_buffer(path, sizeof(path)), node);   \
})

void xen_driver_unbind(tuple meta)
{
    set(meta, sym(bound), 0);
}

closure_function(4, 2, boolean, xen_probe_id_each,
                 xen_driver, xd, string, name, tuple, parent, status *, s,
                 value k, value v)
{
    assert(is_symbol(k));
    if (get(v, sym(bound)))
        return true;
    string backend = get_string(v, sym(backend));
    XenbusState state = XenbusStateUnknown;
    if (backend) {
        status s = xenbus_get_state(backend, &state);
        if (!is_ok(s))
            timm_dealloc(s);
    }
    if ((state == XenbusStateUnknown) || (state == XenbusStateClosed)) {
        xen_debug("removing device/%b/%b", bound(name), symbol_string(k));
        set(bound(parent), k, 0);
        destruct_value(v, true);
        return true;
    }
    u64 id;
    if (!u64_from_value(symbol_string(k), &id)) {
        *bound(s) = timm("result", "failed to parse device id \"%v\"", symbol_string(k));
        return false;
    }
    xen_debug("driver match, id %d, value %v", id, v);
    buffer frontend = allocate_buffer(xen_info.h, buffer_length(bound(name)) + 10);
    bprintf(frontend, "device/%b/%d", bound(name), id);
    boolean bound = apply(bound(xd)->probe, (int)id, frontend, v);
    if (bound)
        set(v, sym(bound), null_value);
    else
        deallocate_buffer(frontend);
    return true;
}

closure_function(1, 2, boolean, xen_probe_devices_each,
                 status *, s,
                 value k, value v)
{
    assert(is_symbol(k));
    if (!is_tuple(v))
        return true;
    list_foreach(&xen_info.driver_list, l) {
        xen_driver xd = struct_from_list(l, xen_driver, l);
        /* XXX must be a cleaner way to compare symbols? */
        string name = symbol_string(k);
        if (buffer_compare_with_sstring(name, xd->name))
            continue;
        iterate(v, stack_closure(xen_probe_id_each, xd, name, v, bound(s)));
        if (*bound(s) != STATUS_OK)
            return false;
    }
    return true;
}

static status xen_scan(void)
{
    status s = traverse_directory(xen_info.h, "device", &xen_info.device_tree);
    if (!is_ok(s))
        return s;
    if (!xen_info.device_tree)
        return timm("result", "failed to parse directory");
    xen_debug("scan result: %v", xen_info.device_tree);
    iterate(xen_info.device_tree, stack_closure(xen_probe_devices_each, &s));
    return s;
}

closure_func_basic(xenstore_watch_handler, void, xen_watch_handler,
                   sstring path)
{
    xenstore_debug("%s: path %s", func_ss, path);

    /* Trigger a rescan if the path has format 'device/<type>/<node>'. */
    int depth = 0;
    for (bytes offset = sizeof("device/"); offset < path.len; offset++) {
        if ((path.ptr[offset] == '/') && (++depth > 1))
            return;
    }
    if (depth == 0)
        return;
    async_apply_bh((thunk)&xen_info.scan_service);
}

closure_func_basic(thunk, void, xen_scan_service)
{
    xenstore_debug("%s", func_ss);

    /* Avoid concurrent scans. */
    if (atomic_test_and_set_bit(&xen_info.scanning, 0)) {
        async_apply((thunk)&xen_info.scan_service);
        return;
    }

    status s = xen_scan();
    atomic_clear_bit(&xen_info.scanning, 0);
    if (!is_ok(s)) {
        msg_warn("xen: cannot scan devices: %v", s);
        timm_dealloc(s);
    }
}

status xen_probe_devices(void)
{
    xen_debug("probing xen device tree from xenstored");
    assert(xen_info.device_tree == 0);
    status s = xen_scan();
    if (is_ok(s)) {
        init_closure_func(&xen_info.scan_service, thunk, xen_scan_service);
        s = xenstore_watch(alloca_wrap_cstring("device"),
                           init_closure_func(&xen_info.watch_handler, xenstore_watch_handler,
                                             xen_watch_handler),
                           true);
        if (!is_ok(s)) {
            msg_warn("xen: cannot watch devices: %v", s);
            timm_dealloc(s);
            s = STATUS_OK;
        }
    }
    return s;
}

void register_xen_driver(sstring name, xen_device_probe probe)
{
    xen_driver xd = mem_alloc(xen_info.h, sizeof(struct xen_driver), MEM_NOWAIT | MEM_NOFAIL);
    xd->name = name;
    xd->probe = probe;
    list_insert_before(&xen_info.driver_list, &xd->l);
}
