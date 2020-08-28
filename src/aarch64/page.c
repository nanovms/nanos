#include <kernel.h>
#include <page.h>

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

#ifdef PAGE_DEBUG
#define page_debug(x, ...) do { if (runtime_initialized) \
            log_printf("PAGE", "%s: " x, __func__, ##__VA_ARGS__); } while(0)
#else
#define page_debug(x, ...)
#endif

/* unallocated portion of initial page table map */
//static range init_pt_map;
//static range pt_initial_phys;

static range init_identity;
static table pt_p2v;
static range pt_virt_remain;
static u64 pt_phys_next;

//static heap pageheap;
//static u64 pt_2m_next;

static u64 *kernel_tablebase;
static u64 *user_tablebase;

#define PAGE_ATTRS (PAGE_ATTR_UXN_XN | PAGE_ATTR_PXN) /* AP[2:1] == 0 */
#define NLEVELS 4
#define LEVEL_MASK_4K MASK(9)   /* would be array for certain granule sizes? */
static const int level_shifts_4K[NLEVELS] = { 39, 30, 21, 12 };
//static const u64 block_masks_4K[NLEVELS - 1] = { 0, MASK(48) & ~MASK(30), MASK(48) & ~MASK(21) };

static id_heap phys_internal;

static inline u64 *pointer_from_pteaddr(u64 pa)
{
    if (!pt_p2v)
        return pointer_from_u64(pa);
    u64 offset = pa & MASK(PAGELOG_2M);
    u64 p = pa & ~MASK(PAGELOG_2M);
    u64 v = (u64)table_find(pt_p2v, (void *)p);
    assert(v);
    return pointer_from_u64(v + offset);
}

#if 0
static physical physical_from_virtual_locked(void *x);
static inline u64 pteaddr_from_pointer(u64 *p)
{
    return physical_from_virtual_locked(p);
}
#endif

static boolean map_area(range v, u64 p, u64 flags);

/* pt_lock should already be held here */
static boolean get_table_page(u64 **table_ptr, u64 *phys)
{
    if (range_span(pt_virt_remain) == 0) {
        page_init_debug_u64(pt_virt_remain.start);
        page_init_debug(", \n");
        page_init_debug_u64(pt_virt_remain.end);
        page_init_debug(", \n");
        page_init_debug_u64(range_span(pt_virt_remain));
        assert(range_span(pt_virt_remain) > 0);
        assert(0); // XXX not yet
        pt_virt_remain.end += PAGESIZE_2M;
        u64 pa = allocate_u64((heap)phys_internal, PAGESIZE_2M);
        if (pa == INVALID_PHYSICAL) {
            msg_err("failed to allocate 2M physical page\n");
            return false;
        }
        /* we depend the pmd already being installed to avoid an alloc here */
        map_area(pt_virt_remain, pa, PAGE_ATTRS);
        table_set(pt_p2v, (void *)pa, (void *)pt_virt_remain.start);
        pt_phys_next = pa;
    }

    *table_ptr = pointer_from_u64(pt_virt_remain.start);
    *phys = pt_phys_next;
    pt_virt_remain.start += PAGESIZE;
    pt_phys_next += PAGESIZE;
    page_init_debug("doofus\n");
    page_init_debug_u64(pt_virt_remain.start);
    page_init_debug(", ");
    page_init_debug_u64(pt_virt_remain.end);
//    zero(table_ptr, PAGESIZE);
    
    page_init_debug(", table_ptr ");
    page_init_debug_u64(u64_from_pointer(table_ptr));
    for (int i = 0; i < PAGESIZE >> 3; i += 4) {
        (*table_ptr)[i] = 0;
        (*table_ptr)[i + 1] = 0;
        (*table_ptr)[i + 2] = 0;
        (*table_ptr)[i + 3] = 0;
    }
    page_init_debug("done\n");
    return true;
}

#if 0
static void put_table_page(u64 v, u64 p)
{
    // XXX add to free list
}
#endif

#define next_addr(a, mask) (a = (a + (mask) + 1) & ~(mask))
static boolean map_level(u64 *table_ptr, int level, range v, u64 p, u64 flags)
{
    int shift = level_shifts_4K[level];
    u64 mask = MASK(shift);
    int first_index = (v.start >> shift) & LEVEL_MASK_4K;
    int last_index = ((v.end - 1) >> shift) & LEVEL_MASK_4K;

    page_init_debug("\nmap_level: ");
    page_init_debug_u64(u64_from_pointer(table_ptr));
    page_init_debug(", level ");
    page_init_debug_u64(level);
    page_init_debug(", shift ");
    page_init_debug_u64(shift);
    page_init_debug(", v ");
    page_init_debug_u64(v.start);
    page_init_debug(" - ");
    page_init_debug_u64(v.end);
    page_init_debug(", p ");
    page_init_debug_u64(p);
    page_init_debug(" first ");
    page_init_debug_u64(first_index);
    page_init_debug(" last ");
    page_init_debug_u64(last_index);
    page_init_debug("\n");

    page_debug("%s: level %d, v %R, p 0x%lx, flags 0x%lx, table_ptr %p\n",
               __func__, level, v, p, flags, table_ptr);
    assert(table_ptr && table_ptr != INVALID_ADDRESS);

    for (int i = first_index; i <= last_index;
         i++, next_addr(v.start, mask), next_addr(p, mask)) {
        page_init_debug("index ");
        page_init_debug_u64(i);
        page_init_debug(", v.start ");
        page_init_debug_u64(v.start);
        page_init_debug(", p ");
        page_init_debug_u64(p);
        page_init_debug("\n");
        u64 pte = table_ptr[i];
        if ((pte & PAGE_L0_3_DESC_VALID) == 0) {
            if (level == 3) {
                /* page */
                page_init_debug(" -page- ");
                pte = flags | (p & PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK) |
                    PAGE_L3_DESC_PAGE | PAGE_ATTR_AF | PAGE_L0_3_DESC_VALID;
            } else if (level > 0 && (v.start & mask) == 0 &&
                       range_span(v) >= U64_FROM_BIT(shift)) {
                page_init_debug(" -block- ");
                page_init_debug_u64(v.start);
                page_init_debug(" span ");
                page_init_debug_u64(range_span(v));
                page_init_debug(" p ");
                page_init_debug_u64(p);
                page_init_debug("\n");
                /* block */
                pte = flags | (p & PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK) |
                    PAGE_ATTR_AF | PAGE_L0_3_DESC_VALID;
            } else {
                page_init_debug(" -new level- ");
                u64 *newtable_ptr;
                u64 newtable;
                if (!get_table_page(&newtable_ptr, &newtable)) {
                    msg_err("failed to allocate page table memory\n");
                    return false;
                }
                assert((newtable & ~PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK) == 0);
                pte = newtable | PAGE_ATTR_AF | PAGE_L0_2_DESC_TABLE | PAGE_L0_3_DESC_VALID;
                page_init_debug("xxx ");
                u64 end = ((u64)(i + 1)) << shift;
                page_init_debug_u64(end);
                /* length instead of end to avoid overflow at end of space */
                u64 len = MIN(range_span(v), end - v.start);
                page_init_debug("len ");
                page_init_debug_u64(len);
                page_init_debug("\n");
                /* XXX install mapping here */
                if (!map_level(newtable_ptr, level + 1, irangel(v.start, len),
                               p, flags))
                    return false;
            }
            page_init_debug("installing pte, level ");
            page_init_debug_u64(level);
            page_init_debug(" @ ");
            page_init_debug_u64(u64_from_pointer(&table_ptr[i]));
            page_init_debug(", pte ");
            page_init_debug_u64(pte);
            page_init_debug("\n");
            table_ptr[i] = pte;
            // XXX INVALIDATES
            // asm volatile("tlbi ...
        } else {
            /* fail if page or block already installed */
            if (level == 3 || (pte & PAGE_L0_2_DESC_TABLE) == 0) {
                 msg_err("would overwrite entry: level %d, v %R, pa 0x%lx, "
                        "flags 0x%lx, index %d, entry 0x%lx\n", level, v, p,
                        flags, i, pte);
                return false;
            }
            u64 nexttable = pte & PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK;
            u64 *nexttable_ptr = pointer_from_pteaddr(nexttable);
            u64 len = MIN(range_span(v), ((i + 1) << shift) - v.start);
            page_init_debug("len 2 ");
            page_init_debug_u64(len);
            page_init_debug("\n");
            if (!map_level(nexttable_ptr, level + 1, irangel(v.start, len), p, flags))
                return false;
        }
    }
    return true;
}
        
static boolean map_area(range v, u64 p, u64 flags)
{
    assert((v.start & PAGEMASK) == 0);
    assert((p & PAGEMASK) == 0);
    v.end = pad(v.end, PAGESIZE);

    page_init_debug("map_area ");
    page_init_debug_u64(v.start);
    page_init_debug(", len ");
    page_init_debug_u64(range_span(v));
    page_init_debug(", p ");
    page_init_debug_u64(p);
    page_init_debug("\n");
    
    /* select table based on v[55] */
    u64 *table_ptr = (v.start & U64_FROM_BIT(55)) ? kernel_tablebase : user_tablebase;
//    rprintf("table 0x%lx, p %p\n", table, pointer_from_pteaddr(table));
    page_init_debug_u64(u64_from_pointer(table_ptr));
    page_init_debug("\n");
    page_init_debug_u64(v.start & U64_FROM_BIT(55));
    page_init_debug("\n");
    return map_level(table_ptr, 0, v, p, flags);
}

void map(u64 v, physical p, u64 length, u64 flags)
{
    if (!map_area(irangel(v, length), p, flags | PAGE_ATTR_AF))
        halt("map failed for v 0x%lx, p 0x%lx, len 0x%lx, flags 0x%lx\n",
             v, p, length, flags);
}

void unmap(u64 virtual, u64 length)
{
    // XXX TODO
}

// XXX
extern void *START, *END;
extern void *LOAD_OFFSET;

#define VA_BITS 48 // XXX verify

/* TODO

   - helpers to compose page flags
   - verify attribute selections
   - table dump (use p2v)
   - basic exception handling
*/

/* init_pt is a 2M block to use for inital ptes */
void page_init_mmu(range init_pt, u64 vtarget)
{
    page_init_debug("START ");
    page_init_debug_u64(u64_from_pointer(&START));
    page_init_debug("LOAD_OFFSET ");
    page_init_debug_u64(u64_from_pointer(&LOAD_OFFSET));
    page_init_debug(" sodifj\n");
    page_init_debug_u64(init_pt.start);
    page_init_debug(", ");
    page_init_debug_u64(init_pt.end);
    page_init_debug("\n");

    assert(range_span(init_pt) == PAGESIZE_2M);
    assert((init_pt.start & MASK(PAGELOG_2M)) == 0);

    /* check capabilities */
    if (field_from_u64(read_psr(ID_AA64MMFR0_EL1),
                       ID_AA64MMFR0_EL1_TGran4) != 0)
        halt("%s: 4KB granule not supported\n", __func__);

    page_init_debug("sodifj\n");
    pt_p2v = 0;
    init_identity = pt_virt_remain = init_pt;
    pt_phys_next = init_pt.start;

    page_init_debug("sodifj\n");
    /* store initial boundaries for p->v lookup */
    // pt_initial_phys = initial_phys;
    // pt_2m_next = PAGES_BASE + pad(range_span(initial_phys), PAGESIZE_2M);

    /* memory attributes */
    write_psr(MAIR_EL1, MAIR_EL1_INIT);
    
    u64 phys;
    assert(get_table_page(&user_tablebase, &phys));
    write_psr(TTBR0_EL1, phys);
    assert(get_table_page(&kernel_tablebase, &phys));
    write_psr(TTBR1_EL1, phys);
    
    page_init_debug("sodifj\n");
    u64 tcr_el1 =
        /* for TTBR1_EL1 (kernel) */
        TCR_EL1_TBI1 | TCR_EL1_TBI0 | /* enable user and kernel tags */
        u64_from_field(TCR_EL1_T1SZ, 64 - VA_BITS) |
        u64_from_field(TCR_EL1_TG1, TCR_EL1_TG1_4KB) |
        u64_from_field(TCR_EL1_ORGN1, TCR_EL1_xRGN_WB) | /* XXX verify */
        u64_from_field(TCR_EL1_IRGN1, TCR_EL1_xRGN_WB) | /* XXX verify */

        /* for TTBR0_EL1 (user) */
        u64_from_field(TCR_EL1_T0SZ, 64 - VA_BITS) |
        u64_from_field(TCR_EL1_TG0, TCR_EL1_TG0_4KB) |
        u64_from_field(TCR_EL1_ORGN0, TCR_EL1_xRGN_WB) | /* XXX verify */
        u64_from_field(TCR_EL1_IRGN0, TCR_EL1_xRGN_WB);  /* XXX verify */

    page_init_debug("tcr_el1: ");
    page_init_debug_u64(tcr_el1);
    page_init_debug("\n");

    write_psr(TCR_EL1, tcr_el1);

//    write_psr(CONTEXTIDR_EL12, 0);
    write_psr(MDSCR_EL1, 0);

    u64 kernel_size = pad(u64_from_pointer(&END) -
                          u64_from_pointer(&START), PAGESIZE);
    page_init_debug("kernel_size ");
    page_init_debug_u64(kernel_size);
    page_init_debug("\n");
    map(KERNEL_BASE, KERNEL_PHYS, kernel_size, 0);
    page_init_debug("map devices\n");
    map(DEVICE_BASE, 0, DEV_MAP_SIZE, 0);
//    map(DEVICE_BASE, 0, 0x20000000, 0);
//    map(DEVICE_BASE + 0x20000000, 0x20000000, 0x20000000, 0);

    // temp identity in low addr space
    map(0x40000000, 0x40000000, 0x1000000, 0); // XXX arb size now

    page_init_debug("SCTLR_EL1: ");
    u64 sctlr = read_psr(SCTLR_EL1);
    page_init_debug_u64(sctlr);
    page_init_debug("\nEnabling MMU...\n");
    sctlr &= ~(SCTLR_EL1_EE |
               SCTLR_EL1_E0E |
               SCTLR_EL1_WXN |
               SCTLR_EL1_I |
               SCTLR_EL1_SA0 |
               SCTLR_EL1_SA |
               SCTLR_EL1_C |
               SCTLR_EL1_A);
    sctlr |= SCTLR_EL1_M;
    asm volatile ("dsb sy;"
                  "tlbi vmalle1is;"
                  "msr SCTLR_EL1, %0;"
                  "isb;"
                  "br %1" :: "r" (sctlr), "r" (vtarget));
}

void page_heap_init(heap h, heap physical)
{
    pt_p2v = allocate_table(h, identity_key, pointer_equal);
    assert(pt_p2v != INVALID_ADDRESS);

    /* create new mapping for previously identity-mapped init region */
    pt_virt_remain = irangel(PAGES_BASE, PAGESIZE_2M);
    map_area(pt_virt_remain, init_identity.start, PAGE_ATTRS);
    table_set(pt_p2v, (void *)init_identity.start, (void *)PAGES_BASE);
}
