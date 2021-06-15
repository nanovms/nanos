#include <kernel.h>

/* Would be nice to have one debug output with a mux to console for early init (i.e. before formatters enabled) */
//#define PAGE_DEBUG
//#define PAGE_UPDATE_DEBUG
//#define PTE_DEBUG

//#define PAGE_INIT_DEBUG
#ifdef PAGE_INIT_DEBUG
#define page_init_debug(x) rputs(x)
#define page_init_debug_u64(x) print_u64(x)
#else
#define page_init_debug(x)
#define page_init_debug_u64(x)
#endif

// XXX deprecate
#if defined(PAGE_DEBUG) && !defined(BOOT)
#define page_debug(x, ...) do {log_printf("PAGE", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define page_debug(x, ...)
#endif

u64 pagebase;

/* assumes page table is consistent when called */
void flush_tlb()
{
    u64 *base;
    mov_from_cr("cr3", base);
    mov_to_cr("cr3", base);
}

#ifdef BOOT
void page_invalidate(flush_entry f, u64 address)
{
    flush_tlb();
}

void page_invalidate_sync(flush_entry f, status_handler completion)
{
    if (completion)
        apply(completion, STATUS_OK);
}

void page_invalidate_flush(void)
{

}

flush_entry get_page_flush_entry(void)
{
    return 0;
}
#endif

#ifndef BOOT
void dump_ptes(void *x)
{
    // XXX TODO
#if 0
    pagetable_lock();
    u64 xt = u64_from_pointer(x);

    rprintf("dump_ptes 0x%lx\n", x);
    u64 l1 = *pte_lookup_ptr(pagebase, xt, PT_SHIFT_L1);
    rprintf("  l1: 0x%lx\n", l1);
    if (l1 & 1) {
        u64 l2 = *pte_lookup_ptr(l1, xt, PT_SHIFT_L2);
        rprintf("  l2: 0x%lx\n", l2);
        if (l2 & 1) {
            u64 l3 = *pte_lookup_ptr(l2, xt, PT_SHIFT_L3);
            rprintf("  l3: 0x%lx\n", l3);
            if ((l3 & 1) && (l3 & _PAGE_2M_SIZE) == 0) {
                u64 l4 = *pte_lookup_ptr(l3, xt, PT_SHIFT_L4);
                rprintf("  l4: 0x%lx\n", l4);
            }
        }
    }
    pagetable_unlock();
#endif
}
#endif
//#define TRAVERSE_PTES_DEBUG

/* Bootloader page tables come from a small, identity-mapped area. */
void *bootstrap_page_tables(heap initial)
{
    /* page table setup */
    init_page_tables(initial, 0);
    void *pgdir = allocate_zero(initial, PAGESIZE);
    assert(pgdir != INVALID_ADDRESS);
    pagebase = u64_from_pointer(pgdir);
    return pgdir;
}

#ifdef KERNEL
void map_setup_2mbpages(u64 v, physical p, int pages, pageflags flags,
                        u64 *pdpt, u64 *pdt)
{
    assert(!(v & PAGEMASK_2M));
    assert(!(p & PAGEMASK_2M));
    u64 *pml4;
    mov_from_cr("cr3", pml4);
    flags.w |= _PAGE_PRESENT;
    pml4[(v >> PT_SHIFT_L1) & MASK(9)] = u64_from_pointer(pdpt) | flags.w;
    v &= MASK(PT_SHIFT_L1);
    pdpt[v >> PT_SHIFT_L2] = u64_from_pointer(pdt) | flags.w;
    v &= MASK(PT_SHIFT_L2);
    assert(v + pages <= 512);
    for (int i = 0; i < pages; i++)
        pdt[v + i] = (p + (i << PAGELOG_2M)) | flags.w | _PAGE_PS;
    memory_barrier();
}

void init_mmu(void)
{
    u32 v[4];
    cpuid(0x80000001, 0, v);
    // XXX we could switch off 1GB mappings...
    assert(v[3] & U64_FROM_BIT(26)); /* 1GB page support */
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_NXE);
    mov_from_cr("cr3", pagebase);
}

#else

/* stage2 */
void init_mmu(heap initial)
{
    void *vmbase = bootstrap_page_tables(initial);
    pagebase = u64_from_pointer(vmbase);
    mov_to_cr("cr3", vmbase);
}

#endif
