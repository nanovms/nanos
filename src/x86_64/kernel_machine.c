#include <kernel.h>
#include <apic.h>

#define SEG_DESC_G          (1 << 15)   /* Granularity */
#define SEG_DESC_DB         (1 << 14)   /* Code: default size, Data: big */
#define SEG_DESC_L          (1 << 13)   /* Code: Long (64-bit) */
#define SEG_DESC_AVL        (1 << 12)   /* Available */
#define SEG_DESC_P          (1 << 7)    /* Present */
#define SEG_DESC_DPL_SHIFT  5           /* Privilege level */
#define SEG_DESC_S          (1 << 4)    /* Code/data (vs sys) */
#define SEG_DESC_CODE       (1 << 3)    /* Code descriptor type (vs data) */
#define SEG_DESC_C          (1 << 2)    /* Conforming */
#define SEG_DESC_RW         (1 << 1)    /* Code: readable, Data: writable */
#define SEG_DESC_A          (1 << 0)    /* Accessed */

#define KERN_CODE_SEG_DESC  (SEG_DESC_L | SEG_DESC_P | SEG_DESC_S | SEG_DESC_CODE | SEG_DESC_RW)
#define KERN_DATA_SEG_DESC  (SEG_DESC_P | SEG_DESC_S | SEG_DESC_RW)
#define USER_CODE_SEG_DESC  (SEG_DESC_L | SEG_DESC_P | (3 << SEG_DESC_DPL_SHIFT) | SEG_DESC_S | SEG_DESC_CODE | SEG_DESC_RW)
#define USER_DATA_SEG_DESC  (SEG_DESC_S | (3 << SEG_DESC_DPL_SHIFT) | SEG_DESC_P | SEG_DESC_RW)

#ifdef SPIN_LOCK_DEBUG_NOSMP
u64 get_program_counter(void)
{
    return u64_from_pointer(__builtin_return_address(0));
}
#endif

/* stub placeholder, short of a real generic interface */
void send_ipi(u64 cpu, u8 vector)
{
    apic_ipi(cpu, ICR_ASSERT, vector);
}

void interrupt_exit(void)
{
    lapic_eoi();
}

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

void clone_frame_pstate(context dest, context src)
{
    runtime_memcpy(dest, src, sizeof(u64) * (FRAME_N_PSTATE + 1));
    runtime_memcpy(dest + FRAME_EXTENDED_SAVE, src + FRAME_EXTENDED_SAVE, extended_frame_size);
}

static void seg_desc_set(seg_desc_t *d, u32 base, u16 limit, u16 flags)
{
    d->data[0] = limit & 0xff;
    d->data[1] = (limit >> 8) & 0xff;
    d->data[2] = base & 0xff;
    d->data[3] = (base >> 8) & 0xff;
    d->data[4] = (base >> 16) & 0xff;
    d->data[5] = flags & 0xff;
    d->data[6] = (flags >> 8) & 0xff;
    d->data[7] = (base >> 24) & 0xff;
}

void init_cpuinfo_machine(cpuinfo ci, heap backed)
{
    ci->m.self = &ci->m;
    ci->m.exception_stack = allocate_stack(backed, EXCEPT_STACK_SIZE);
    ci->m.int_stack = allocate_stack(backed, INT_STACK_SIZE);

    /* Separate stack to keep exceptions in interrupt handlers from
       trashing the interrupt stack */
    set_ist(&ci->m, IST_EXCEPTION, u64_from_pointer(ci->m.exception_stack));

    /* External interrupts (> 31) */
    set_ist(&ci->m, IST_INTERRUPT, u64_from_pointer(ci->m.int_stack));

    struct gdt *gdt = &ci->m.gdt;
    seg_desc_set(&gdt->null, 0, 0, 0);
    seg_desc_set(&gdt->code, 0, 0, KERN_CODE_SEG_DESC);
    seg_desc_set(&gdt->data, 0, 0, KERN_DATA_SEG_DESC);
    seg_desc_set(&gdt->user_code, 0, 0, 0);
    seg_desc_set(&gdt->user_data, 0, 0, USER_DATA_SEG_DESC);
    seg_desc_set(&gdt->user_code_64, 0, 0, USER_CODE_SEG_DESC);
    ci->m.gdt_pointer.limit = sizeof(struct gdt) - 1;
    u64 gdt_base = u64_from_pointer(gdt);
    runtime_memcpy(&ci->m.gdt_pointer.base, &gdt_base, sizeof(gdt_base));
    install_gdt64_and_tss(&ci->m.gdt.tss_desc, &ci->m.tss, gdt, &ci->m.gdt_pointer);
}

void init_frame(context f)
{
    assert((u64_from_pointer(f) & 63) == 0);
    xsave(f);
}
