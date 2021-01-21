#include <kernel.h>
#include <apic.h>

/* stub placeholder, short of a real generic interface */
void send_ipi(u64 cpu, u8 vector)
{
    apic_ipi(cpu, 0, vector);
}

heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    heap h = heap_general(kh);
    heap p = (heap)heap_physical(kh);
    assert(tag < U64_FROM_BIT(VA_TAG_WIDTH));
    u64 tag_base = KMEM_BASE | (tag << VA_TAG_OFFSET);
    u64 tag_length = U64_FROM_BIT(VA_TAG_OFFSET);
    heap v = (heap)create_id_heap(h, heap_backed(kh), tag_base, tag_length, p->pagesize, false);
    assert(v != INVALID_ADDRESS);
    heap backed = (heap)physically_backed(h, v, p, p->pagesize, false);
    if (backed == INVALID_ADDRESS)
        return backed;

    /* reserve area in virtual_huge */
    assert(id_heap_set_area(heap_virtual_huge(kh), tag_base, tag_length, true, true));

    /* tagged mcache range of 32 to 1M bytes (131072 table buckets) */
    build_assert(TABLE_MAX_BUCKETS * sizeof(void *) <= 1 << 20);
    return allocate_mcache(h, backed, 5, 20, PAGESIZE_2M);
}

void clone_context_pstate(context dest, context src)
{
    runtime_memcpy(dest, src, sizeof(u64) * (FRAME_N_PSTATE + 1));
    runtime_memcpy(dest + FRAME_EXTENDED_SAVE, src + FRAME_EXTENDED_SAVE, extended_frame_size());
}
