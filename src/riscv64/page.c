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

u64 tablebase;

extern void *START, *END;

boolean is_protection_fault(context_frame f)
{
    /* XXX is there no hw distinction between writing to a valid
       readonly page versus writing to a non-existant page? */
    pte e;
    // XXX this lookup is not locked but will need to be for smp
    if (physical_and_pte_from_virtual(frame_fault_address(f), &e) == INVALID_PHYSICAL)
        return false;
    u64 cause = SCAUSE_CODE(f[FRAME_CAUSE]);
    return (e & PAGE_VALID) && (cause == TRAP_E_SPAGE_FAULT);
}

void invalidate(u64 page)
{
    asm volatile("sfence.vma %0, x0" :: "r"(page) : "memory");
}

void flush_tlb(boolean full_flush)
{
    if (full_flush)
        asm volatile("sfence.vma" ::: "memory");
}

void init_mmu(range init_pt, u64 vtarget)
{
    /* XXX init_pt doesn't have to be a 2m page right? */
//  assert(range_span(init_pt) == PAGESIZE_2M);
//  assert((init_pt.start & MASK(PAGELOG_2M)) == 0);

    /* set supervisor user memory access */
    register u64 sum = STATUS_SUM;
    asm volatile("csrs sstatus, %0" ::"r"(sum) : "memory");

    page_set_allowed_levels(0xe); // 1-3
    init_page_initial_map(pointer_from_u64(init_pt.start), init_pt);
    assert(allocate_table_page(&tablebase));
    u64 kernel_size = pad(u64_from_pointer(&END) - u64_from_pointer(&START), PAGESIZE);
    page_init_debug("kernel_size ");
    page_init_debug_u64(kernel_size);
    page_init_debug("\n");
    map(KERNEL_BASE, KERNEL_PHYS, kernel_size, pageflags_writable(pageflags_exec(pageflags_memory())));
    page_init_debug("map devices\n");
    map(DEVICE_BASE, 0, DEV_MAP_SIZE, pageflags_writable(pageflags_device()));

    page_init_debug("map temporary identity mapping\n");
    map(PHYSMEM_BASE, PHYSMEM_BASE, INIT_IDENTITY_SIZE, pageflags_writable(pageflags_memory()));
    u64 satp = Sv48 | (u64_from_pointer(tablebase) >> 12);
    asm volatile ("csrw satp, %0; sfence.vma; jr %1" :: "r"(satp), "r"(vtarget) : "memory");
}

