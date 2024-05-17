#include <kernel.h>
#include <plic.h>
#include <devicetree.h>

//#define TAG_HEAP_DEBUG
#ifdef TAG_HEAP_DEBUG
#define tag_debug(x, ...) do {rprintf(x, ##__VA_ARGS__);} while(0)
#else
#define tag_debug(x, ...)
#endif

heap allocate_tagged_region(kernel_heaps kh, u64 tag, bytes pagesize, boolean locking)
{
    heap h = heap_locked(kh);
    heap p = (heap)heap_physical(kh);
    assert(tag < U64_FROM_BIT(VA_TAG_WIDTH));
    u64 tag_base = KMEM_BASE | (tag << VA_TAG_OFFSET);
    u64 tag_length = U64_FROM_BIT(VA_TAG_OFFSET);
    heap v = (heap)create_id_heap(h, h, tag_base, tag_length, p->pagesize, false);
    assert(v != INVALID_ADDRESS);
    heap backed = (heap)allocate_page_backed_heap(h, v, p, p->pagesize, false);
    if (backed == INVALID_ADDRESS)
        return backed;

    /* reserve area in virtual_huge */
    assert(id_heap_set_area(heap_virtual_huge(kh), tag_base, tag_length, true, true));

    heap mc = allocate_mcache(h, backed, 5, find_order(pagesize) - 1, pagesize, false);
    assert(mc != INVALID_ADDRESS);
    return locking ? locking_heap_wrapper(h, mc) : mc;
}

extern void *trap_handler;
BSS_RO_AFTER_INIT u64 boot_hartid;

void cpu_init(int cpu)
{
    cpuinfo ci = cpuinfo_from_id(cpu);
    register u64 a = u64_from_pointer(ci);
    asm volatile("mv tp, %0; csrw sscratch, %0" ::"r"(a));
    asm volatile("csrr %0, sstatus" : "=r"(a));
    a |= STATUS_SIE|(FS_INITIAL<<STATUS_BIT_FS); // XXX
    asm volatile("csrw sstatus, %0" :: "r"(a));
    asm volatile("csrw stvec, %0" :: "r"(&trap_handler));
    asm volatile("csrw sie, %0" :: "r"(SI_SEIP | SI_STIP | SI_SSIP));
}

void init_cpuinfo_machine(cpuinfo ci, heap backed)
{
    kernel_context kc = allocate_kernel_context(ci);
    assert(kc != INVALID_ADDRESS);
    /* start off kernel context in resumed state */
    context_reserve_refcount(&kc->context);
    kc->context.active_cpu = ci->id;
    void *p = allocate(backed, TRAP_STACK_SIZE);
    assert(p != INVALID_ADDRESS);
    ci->m.tstack_top = p + TRAP_STACK_SIZE;
    ci->m.current_context = ci->m.kernel_context = &kc->context;
    ci->m.hartid = ci->id == 0 ? boot_hartid : -1ull;
    ci->m.ipi_mask = 0;
}

void clone_frame_pstate(context_frame dest, context_frame src)
{
    runtime_memcpy(dest, src, sizeof(u64) * FRAME_N_PSTATE);
}

void interrupt_exit(void)
{
    plic_eoi(plic_dispatch_int());
}

static struct spinlock ap_lock;

static void ap_start_newstack(int cpuid)
{
    int cpu;
    for (cpu = 1; cpu < present_processors; cpu++)
        if (!cpuinfo_from_id(cpu))
            break;
    total_processors = cpu;
    spin_unlock(&ap_lock);
    cpu_init(cpuid);
    run_percpu_init();
    disable_interrupts();
    kernel_sleep();
}

BSS_RO_AFTER_INIT static vector hartids_by_cpuid;

static inline u64 cpuid_from_hartid(u64 hartid)
{
    for (u64 cpuid = 0; cpuid < vector_length(hartids_by_cpuid); cpuid++) {
        if ((u64)vector_get(hartids_by_cpuid, cpuid) == hartid)
            return cpuid;
    }
    return INVALID_PHYSICAL;
}

void ap_start(u64 hartid)
{
    spin_lock(&ap_lock);
    memory_barrier();
    u64 cpuid = cpuid_from_hartid(hartid);
    assert(cpuid != INVALID_PHYSICAL);
    assert(cpuid > 0);
    cpuinfo ci = init_cpuinfo(heap_locked(get_kernel_heaps()), cpuid);
    assert(ci != INVALID_ADDRESS);
    ci->m.hartid = hartid;
    plic_set_threshold(hartid, 0);
    context_frame f = ci->m.kernel_context->frame;
    switch_stack_1(frame_get_stack_top(f), ap_start_newstack, cpuid);
}

extern void secondary_core_start_from_sbi(void);
void *ap_stack;

void start_secondary_cores(kernel_heaps kh)
{
    spin_lock_init(&ap_lock);
    ap_stack = allocate_stack((heap)heap_page_backed(kh), 4 * PAGESIZE);
    assert(ap_stack != INVALID_ADDRESS);
    init_flush(heap_locked(kh));
    u64 target = physical_from_virtual(secondary_core_start_from_sbi);
    for (int cpuid = 1; cpuid < present_processors; cpuid++) {
        struct sbiret r;
        u64 hartid = (u64)vector_get(hartids_by_cpuid, cpuid);
        r = supervisor_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START, hartid, target,
                             u64_from_pointer(ap_stack), 0, 0, 0);
        if (r.error) {
            halt("failed to start cpu %d (hartid %d): error 0x%lx, value 0x%lx\n",
                 cpuid, hartid, r.error, r.value);
        }
    }
}

closure_function(1, 2, boolean, cpu_dtb_handler,
                 u64 *, proc_count,
                 dt_node n, sstring name)
{
    dt_prop device_type = dtb_get_prop(DEVICETREE, n, ss("device_type"));
    if (device_type == INVALID_ADDRESS)
        return true;
    dt_value dtval = dtb_read_value(DEVICETREE, n, device_type);
    if (dtval.type != DT_VALUE_STRING ||
        runtime_strcmp(sstring_from_cstring(dtval.u.string, dtval.dlen), ss("cpu")))
        return true;

    dt_prop reg = dtb_get_prop(DEVICETREE, n, ss("reg"));
    if (reg == INVALID_ADDRESS)
        halt("unable to find \"reg\" property for cpu\n");
    dt_value reg_val = dtb_read_value(DEVICETREE, n, reg);
    if (reg_val.type != DT_VALUE_REG)
        halt("invalid dt_value type %d for cpu reg property\n", reg_val.type);
    range r;
    assert(dtb_reg_iterate(&reg_val.u.ri, &r));
    if (r.start != boot_hartid) {
        u64 cpuid = (*bound(proc_count))++;
        vector_set(hartids_by_cpuid, cpuid, (void*)r.start);
    }
    return true;
}

void count_cpus_present(void)
{
    hartids_by_cpuid = allocate_vector(heap_general(get_kernel_heaps()), 8);
    assert(hartids_by_cpuid != INVALID_ADDRESS);
    vector_set(hartids_by_cpuid, 0, (void*)boot_hartid);
    dt_node n = dtb_find_node_by_path(DEVICETREE, ss("/cpus"));
    if (n == INVALID_ADDRESS) {
        msg_err("unable to find \"/cpus/cpu-map/cluster0\" in device tree; resorting to single cpu\n");
        return;
    }

    u64 proc_count = 1;
    dtb_walk_node_children(DEVICETREE, n, sstring_null(),
                           stack_closure(cpu_dtb_handler, &proc_count));
    present_processors = proc_count;
}

#ifdef KERNEL
#define EXTENDED_FRAME_SIZE (FRAME_EXTENDED_MAX * sizeof(u64))
void init_context_machine(context c)
{
    void *e = allocate_zero((heap)heap_page_backed(get_kernel_heaps()),
                            EXTENDED_FRAME_SIZE);
    assert(e != INVALID_ADDRESS);
    c->frame[FRAME_EXTENDED] = u64_from_pointer(e);
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

