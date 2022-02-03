#include <kernel.h>
#include <plic.h>

//#define TAG_HEAP_DEBUG
#ifdef TAG_HEAP_DEBUG
#define tag_debug(x, ...) do {rprintf(x, ##__VA_ARGS__);} while(0)
#else
#define tag_debug(x, ...)
#endif

heap allocate_tagged_region(kernel_heaps kh, u64 tag, bytes pagesize)
{
    heap h = heap_locked(kh);
    heap p = (heap)heap_physical(kh);
    assert(tag < U64_FROM_BIT(VA_TAG_WIDTH));
    u64 tag_base = KMEM_BASE | (tag << VA_TAG_OFFSET);
    u64 tag_length = U64_FROM_BIT(VA_TAG_OFFSET);
    heap v = (heap)create_id_heap(h, (heap)heap_linear_backed(kh), tag_base, tag_length, p->pagesize, false);
    assert(v != INVALID_ADDRESS);
    heap backed = (heap)allocate_page_backed_heap(h, v, p, p->pagesize, false);
    if (backed == INVALID_ADDRESS)
        return backed;

    /* reserve area in virtual_huge */
    assert(id_heap_set_area(heap_virtual_huge(kh), tag_base, tag_length, true, true));

    return allocate_mcache(h, backed, 5, find_order(pagesize) - 1, pagesize);
}

void cpu_init(int cpu)
{
    cpuinfo ci = cpuinfo_from_id(cpu);
    register u64 a = u64_from_pointer(ci);
    asm volatile("mv tp, %0; csrw sscratch, %0" ::"r"(a));
    asm volatile("csrr %0, sstatus" : "=r"(a));
    a |= STATUS_SIE|(FS_INITIAL<<STATUS_BIT_FS); // XXX
    asm volatile("csrw sstatus, %0" :: "r"(a));
    a = 0x666;
    asm volatile("csrw sie, %0" :: "r"(a));
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
}

void clone_frame_pstate(context_frame dest, context_frame src)
{
    runtime_memcpy(dest, src, sizeof(u64) * FRAME_N_PSTATE);
}

void interrupt_exit(void)
{
    plic_eoi(plic_dispatch_int());
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

