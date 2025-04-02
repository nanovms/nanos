#include <kernel.h>

BSS_RO_AFTER_INIT u64 pagebase;

/* Mask applied to page table entries to enable memory encryption, if supported and enabled */
BSS_RO_AFTER_INIT u64 page_encr_mask;

void invalidate(u64 page)
{
    asm volatile("invlpg (%0)" :: "r" ((word)page) : "memory");
}

/* assumes page table is consistent when called */
void flush_tlb(boolean full_flush)
{
    if (full_flush) {
        u64 *base;
        mov_from_cr("cr3", base);
        mov_to_cr("cr3", base);
    }
}

#ifdef BOOT
void page_invalidate(flush_entry f, u64 address)
{
    flush_tlb(true);
}

void page_invalidate_sync(flush_entry f, thunk completion, boolean wait)
{
}

void page_invalidate_flush(void)
{

}

flush_entry get_page_flush_entry(void)
{
    return 0;
}
#endif

/* Bootloader page tables come from a small, identity-mapped area. */
void *bootstrap_page_tables(heap initial)
{
    /* page table setup */
    init_page_tables(initial, irange(LINEAR_BACKED_BASE, LINEAR_BACKED_LIMIT));
    void *pgdir = mem_alloc(initial, PAGESIZE, MEM_ZERO | MEM_NOFAIL);
    pagebase = u64_from_pointer(pgdir);
    return pgdir;
}

#if defined(KERNEL) || defined(UEFI)

#include <region.h>

void map_setup_2mbpages(u64 v, physical p, int pages, pageflags flags,
                        region r)
{
    assert(!(v & PAGEMASK_2M));
    assert(!(p & PAGEMASK_2M));
    u64 *pml4;
    u64 *pdpt, *pdt;
    mov_from_cr("cr3", pml4);
    flags.w |= PAGE_PRESENT;
    u64 table_index = (v >> PT_SHIFT_L1) & MASK(9);
    if (pml4[table_index] & PAGE_PRESENT)
        pdpt = pointer_from_u64(pml4[table_index] & ~PAGE_FLAGS_MASK);
    else {
        assert(r->length >= PAGESIZE);
        pdpt = pointer_from_u64(r->base);
        region_resize(r, -PAGESIZE);
        pml4[table_index] = new_level_pte(u64_from_pointer(pdpt)) | flags.w;
    }
    v &= MASK(PT_SHIFT_L1);
    table_index = v >> PT_SHIFT_L2;
    if (pdpt[table_index] & PAGE_PRESENT)
        pdt = pointer_from_u64(pdpt[table_index] & ~PAGE_FLAGS_MASK);
    else {
        assert(r->length >= PAGESIZE);
        pdt = pointer_from_u64(r->base);
        region_resize(r, -PAGESIZE);
        pdpt[table_index] = new_level_pte(u64_from_pointer(pdt)) | flags.w;
    }
    v &= MASK(PT_SHIFT_L2);
    table_index = v >> PT_SHIFT_L3;
    assert(table_index + pages <= 512);
    for (int i = 0; i < pages; i++)
        pdt[table_index + i] = (p + (i << PAGELOG_2M)) | flags.w | PAGE_PS;
    memory_barrier();
}

void init_mmu(void)
{
    u32 cpuid_max = cpuid_highest_fn(true);
    u32 v[4];
    u64 levelmask = 0x18;        /* levels 3 and 4 always supported */
    if (cpuid_max >= CPUID_FN_EXT_PROC_INFO) {
        cpuid(CPUID_FN_EXT_PROC_INFO, 0, v);
        if (v[3] & CPUID_PDPE1GB) /* 1GB page support */
            levelmask |= 0x4;
    }
    page_set_allowed_levels(levelmask);

    /* Use Secure Encrypted Virtualization (VM memory encryption) if supported and enabled by the
     * hypervisor. */
    if (cpuid_max >= CPUID_FN_ENCR_MEM) {
        cpuid(CPUID_FN_ENCR_MEM, 0, v);
        if ((v[0] & CPUID_SEV) && (read_msr(SEV_STATUS_MSR) & SEV_ENABLED))
            page_encr_mask = U64_FROM_BIT(CPUID_SME_C_BIT(v[1]));
    }

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
