#include <kernel.h>

//#define PAGE_INIT_DEBUG

#ifdef PAGE_INIT_DEBUG
#define page_init_debug(x) early_debug(x)
#define page_init_debug_u64(x) early_debug_u64(x)
#define page_init_dump(p, len) early_dump(p, len)
#else
#define page_init_debug(x)
#define page_init_debug_u64(x)
#define page_init_dump(p, len)
#endif

BSS_RO_AFTER_INIT u64 kernel_tablebase;
BSS_RO_AFTER_INIT u64 user_tablebase;

void invalidate(u64 page)
{
    /* no final sync here; need "dsb ish" at end of operation */
    register u64 a = (page >> PAGELOG) & MASK(56 - PAGELOG);    /* no asid */
    asm volatile("dsb ishst;"
                 "tlbi vale1is, %0" :: "r"(a) : "memory");
}

void flush_tlb(boolean full_flush)
{
    asm volatile("dsb ish" ::: "memory");
    if (full_flush)
        asm volatile("tlbi vmalle1is");
}

extern void *START, *READONLY_END, *END;
extern void *LOAD_OFFSET;

/* init_pt is a 2M block to use for inital ptes */
void init_mmu(range init_pt, u64 vtarget)
{
    page_init_debug("START ");
    page_init_debug_u64(u64_from_pointer(&START));
    page_init_debug("LOAD_OFFSET ");
    page_init_debug_u64(u64_from_pointer(&LOAD_OFFSET));
    page_init_debug_u64(init_pt.start);
    page_init_debug(", ");
    page_init_debug_u64(init_pt.end);
    page_init_debug("\n");

    assert(range_span(init_pt) == PAGESIZE_2M);
    assert((init_pt.start & MASK(PAGELOG_2M)) == 0);

    /* check capabilities */
    u64 mmfr0 = read_psr(ID_AA64MMFR0_EL1);
    page_init_debug("MMFR0 ");
    page_init_debug_u64(mmfr0);
    page_init_debug("\n");

    if (field_from_u64(mmfr0, ID_AA64MMFR0_EL1_TGran4) != 0)
        halt("%s: 4KB granule not supported\n", __func__);

    page_set_allowed_levels(0xe); /* mapping at levels 1-3 always allowed */
    init_page_initial_map(pointer_from_u64(init_pt.start), init_pt);
    
    assert(allocate_table_page(&user_tablebase));
    assert(allocate_table_page(&kernel_tablebase));
    
#if 0
    /* XXX: something about splitting the mapping into two pieces
       causes some accesses to go off the rails ... even if both are made writable */
    pageflags ro_flags = pageflags_exec(pageflags_memory());
    u64 start = u64_from_pointer(&START);
    u64 readonly_end = u64_from_pointer(&READONLY_END);
    u64 end = u64_from_pointer(&END);
    assert((start & PAGEMASK) == 0);
    assert((readonly_end & PAGEMASK) == 0);
    assert((end & PAGEMASK) == 0);

    u64 ro_size = readonly_end - start;
    u64 rw_size = end - readonly_end;
    page_init_debug("ro_size ");
    page_init_debug_u64(ro_size);
    page_init_debug("\nrw_size ");
    page_init_debug_u64(rw_size);
    page_init_debug("\n");
    map(KERNEL_BASE, KERNEL_PHYS, ro_size, ro_flags);
    map(KERNEL_BASE + ro_size, KERNEL_PHYS + ro_size, rw_size, pageflags_writable(ro_flags));
#else
    /* XXX: kernel is writable here, replace with ro/rw mapping above when fixed */
    u64 kernel_size = pad(u64_from_pointer(&END) - u64_from_pointer(&START), PAGESIZE);
    page_init_debug("kernel_size ");
    page_init_debug_u64(kernel_size);
    page_init_debug("\n");
    map(KERNEL_BASE, KERNEL_PHYS, kernel_size, pageflags_writable(pageflags_exec(pageflags_memory())));
#endif

    page_init_debug("map devices\n");
    map(DEVICE_BASE, 0, DEV_MAP_SIZE, pageflags_writable(pageflags_device()));

    page_init_debug("map temporary identity mapping\n");
    map(PHYSMEM_BASE, PHYSMEM_BASE, INIT_IDENTITY_SIZE, pageflags_writable(pageflags_memory()));

    enable_mmu(vtarget);
}

void enable_mmu(u64 vtarget)
{
    /* memory attributes */
    write_psr(MAIR_EL1, MAIR_EL1_INIT);

    write_psr(TTBR0_EL1, user_tablebase);
    write_psr(TTBR1_EL1, kernel_tablebase);

    u64 tcr_el1 =
        /* for TTBR1_EL1 (kernel) */
        TCR_EL1_TBI1 | TCR_EL1_TBI0 | /* enable user and kernel tags */
        u64_from_field(TCR_EL1_T1SZ, 64 - VIRTUAL_ADDRESS_BITS) |
        u64_from_field(TCR_EL1_TG1, TCR_EL1_TG1_4KB) |
        u64_from_field(TCR_EL1_ORGN1, TCR_EL1_xRGN_WB) |
        u64_from_field(TCR_EL1_IRGN1, TCR_EL1_xRGN_WB) |

        /* for TTBR0_EL1 (user) */
        u64_from_field(TCR_EL1_T0SZ, 64 - VIRTUAL_ADDRESS_BITS) |
        u64_from_field(TCR_EL1_TG0, TCR_EL1_TG0_4KB) |
        u64_from_field(TCR_EL1_ORGN0, TCR_EL1_xRGN_WB) |
        u64_from_field(TCR_EL1_IRGN0, TCR_EL1_xRGN_WB);

    page_init_debug("tcr_el1: ");
    page_init_debug_u64(tcr_el1);
    page_init_debug("\n");

    write_psr(TCR_EL1, tcr_el1);
    write_psr(MDSCR_EL1, 0);

    page_init_debug("\nEnabling MMU and caches...\n");

    /* Not clear if we should enforce the stack alignment checks...probably,
       after debugging user faults when running with them under KVM.

       SCTLR_EL1_SA0 |
       SCTLR_EL1_SA |
    */

    u64 sctlr = (SCTLR_EL1_SPAN |
                 SCTLR_EL1_nTWE |
                 SCTLR_EL1_nTWI |
                 SCTLR_EL1_I |
                 SCTLR_EL1_C |
                 SCTLR_EL1_M);
    asm volatile ("dsb sy;"
                  "tlbi vmalle1is;"
                  "msr SCTLR_EL1, %0;"
                  "isb;"
                  "br %1" :: "r" (sctlr), "r" (vtarget));
}
