#include <kernel.h>
#include <page.h>

//#define PAGE_INIT_DEBUG
//#define TRAVERSE_PTES_DEBUG

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

#ifdef KERNEL
static struct spinlock pt_lock;
#define pagetable_lock() u64 _savedflags = spin_lock_irq(&pt_lock)
#define pagetable_unlock() spin_unlock_irq(&pt_lock, _savedflags)
#else
#define pagetable_lock()
#define pagetable_unlock()
#endif

/* unallocated portion of initial page table map */
//static range init_pt_map;
//static range pt_initial_phys;

static range init_identity;
static table pt_p2v;
static range pt_virt_remain;
static u64 pt_phys_next;
static id_heap physheap;

//static heap pageheap;
//static u64 pt_2m_next;

static u64 *kernel_tablebase;
static u64 *user_tablebase;

const int page_level_shifts_4K[PAGE_NLEVELS] = { 39, 30, 21, 12 };

static inline void leaf_invalidate(u64 address)
{
    /* no final sync here; need "dsb ish" at end of operation */
    register u64 a = (address >> PAGELOG) & MASK(55 - PAGELOG); /* no asid */
    asm volatile("dsb ishst;"
                 "tlbi vale1is, %0" :: "r"(a) : "memory");
}

static inline void post_sync(void)
{
    asm volatile("dsb ish" ::: "memory");
}

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

void dump_ptes(void *vaddr)
{
    // XXX TODO
}

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
#if 0
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
#endif
    }

    *table_ptr = pointer_from_u64(pt_virt_remain.start);
    *phys = pt_phys_next;
    pt_virt_remain.start += PAGESIZE;
    pt_phys_next += PAGESIZE;
    page_init_debug("pt_virt_remain.start ");
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
static boolean map_level(u64 *table_ptr, int level, range v, u64 *p, u64 flags)
{
    int shift = page_level_shifts_4K[level];
    u64 mask = MASK(shift);
    u64 vlbase = level > 1 ? v.start & ~MASK(page_level_shifts_4K[level - 1]) : 0;
    int first_index = (v.start >> shift) & LEVEL_MASK_4K;
    int last_index = ((v.end - 1) >> shift) & LEVEL_MASK_4K;

    page_init_debug("\nmap_level: table_ptr ");
    page_init_debug_u64(u64_from_pointer(table_ptr));
    page_init_debug(", level ");
    page_init_debug_u64(level);
    page_init_debug(", shift ");
    page_init_debug_u64(shift);
    page_init_debug("\n   v ");
    page_init_debug_u64(v.start);
    page_init_debug(" - ");
    page_init_debug_u64(v.end);
    page_init_debug(", p ");
    page_init_debug_u64(*p);
    page_init_debug(" first ");
    page_init_debug_u64(first_index);
    page_init_debug(" last ");
    page_init_debug_u64(last_index);
    page_init_debug("\n");
    assert(first_index <= last_index);

    page_debug("%s: level %d, v %R, p 0x%lx, flags 0x%lx, table_ptr %p\n",
               __func__, level, v, *p, flags, table_ptr);
    assert(table_ptr && table_ptr != INVALID_ADDRESS);

    for (int i = first_index; i <= last_index; i++, next_addr(v.start, mask)) {
        page_init_debug("   index ");
        page_init_debug_u64(i);
        page_init_debug(", v.start ");
        page_init_debug_u64(v.start);
        page_init_debug(", p ");
        page_init_debug_u64(*p);
        page_init_debug("\n");
        u64 pte = table_ptr[i];
        if ((pte & PAGE_L0_3_DESC_VALID) == 0) {
            if (level == 3) {
                page_init_debug("   -page- ");
                pte = flags | (*p & PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK) |
                    PAGE_L3_DESC_PAGE | PAGE_ATTR_AF | PAGE_L0_3_DESC_VALID;
                next_addr(*p, mask);
            } else if (level > 0 &&
                       (v.start & mask) == 0 &&
                       (*p & mask) == 0 &&
                       range_span(v) >= U64_FROM_BIT(shift)) {
                page_init_debug("   -block- ");
                page_init_debug_u64(v.start);
                page_init_debug(" span ");
                page_init_debug_u64(range_span(v));
                page_init_debug(" p ");
                page_init_debug_u64(*p);
                page_init_debug("\n");
                pte = flags | (*p & PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK) |
                    PAGE_ATTR_AF | PAGE_L0_3_DESC_VALID;
                next_addr(*p, mask);
            } else {
                page_init_debug("   -new level- ");
                u64 *newtable_ptr;
                u64 newtable;
                if (!get_table_page(&newtable_ptr, &newtable)) {
                    msg_err("failed to allocate page table memory\n");
                    return false;
                }
                assert((newtable & ~PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK) == 0);
                pte = newtable | PAGE_ATTR_AF | PAGE_L0_2_DESC_TABLE | PAGE_L0_3_DESC_VALID;
                u64 end = vlbase | (((u64)(i + 1)) << shift);
                /* length instead of end to avoid overflow at end of space */
                u64 len = MIN(range_span(v), end - v.start);
                page_init_debug("   end ");
                page_init_debug_u64(end);
                page_init_debug(", len ");
                page_init_debug_u64(len);
                page_init_debug("\n");
                /* XXX install mapping here - ??? */
                if (!map_level(newtable_ptr, level + 1, irangel(v.start, len),
                               p, flags))
                    return false;
            }
            page_init_debug("   installing pte, level ");
            page_init_debug_u64(level);
            page_init_debug(" @ ");
            page_init_debug_u64(u64_from_pointer(&table_ptr[i]));
            page_init_debug(", pte ");
            page_init_debug_u64(pte);
            page_init_debug("\n");
            table_ptr[i] = pte;

            /* XXX for debug - may not be necessary */
            leaf_invalidate(v.start);
        } else {
#if 1
            /* fail if page or block already installed */
            if (level == 3 || (pte & PAGE_L0_2_DESC_TABLE) == 0) {
                msg_err("would overwrite entry: level %d, v %R, pa 0x%lx, "
                        "flags 0x%lx, index %d, entry 0x%lx\n", level, v, *p,
                        flags, i, pte);
                return false;
            }
#endif
            u64 nexttable = page_from_pte(pte);
            u64 *nexttable_ptr = pointer_from_pteaddr(nexttable);
            u64 len = MIN(range_span(v), ((i + 1) << shift) - v.start);
            page_init_debug("   len 2 ");
            page_init_debug_u64(len);
            page_init_debug("\n");
            if (!map_level(nexttable_ptr, level + 1, irangel(v.start, len), p, flags))
                return false;
        }
    }
    return true;
}

static inline u64 *table_from_vaddr(u64 vaddr)
{
    return (vaddr & U64_FROM_BIT(55)) ? kernel_tablebase : user_tablebase;
}

static boolean map_area(range v, u64 p, u64 flags)
{
    assert((v.start & PAGEMASK) == 0);
    assert((p & PAGEMASK) == 0);
    v.end = pad(v.end, PAGESIZE);

    page_init_debug("map_area, v ");
    page_init_debug_u64(v.start);
    page_init_debug(", len ");
    page_init_debug_u64(range_span(v));
    page_init_debug(", p ");
    page_init_debug_u64(p);
    page_init_debug(", flags");
    page_init_debug_u64(flags);
    page_init_debug("\n");
    
    /* select table based on v[55] */
    u64 *table_ptr = table_from_vaddr(v.start);
//    rprintf("table 0x%lx, p %p\n", table, pointer_from_pteaddr(table));
    page_init_debug_u64(u64_from_pointer(table_ptr));
    page_init_debug("\n");
    page_init_debug_u64(v.start & U64_FROM_BIT(55));
    page_init_debug("\n");
    boolean r = map_level(table_ptr, 0, v, &p, flags);
    post_sync();
    return r;
}

void map(u64 v, physical p, u64 length, u64 flags)
{
//    rprintf("map: v 0x%lx, p 0x%lx, length 0x%lx, flags 0x%lx\n",
//            v, p, length, flags);
#if 0
    console("map: v ");
    print_u64(v);
    console(", p ");
    print_u64(p);
    console(", length ");
    print_u64(length);
    console(", flags ");
    print_u64(flags);
    console("\n");
#endif
    page_init_debug("map_area from ");
    page_init_debug_u64(u64_from_pointer(__builtin_return_address(0)));

    if (!map_area(irangel(v, length), p, flags | PAGE_ATTR_AF)) {
        rprintf("ra %p\n", __builtin_return_address(0));
        halt("map failed for v 0x%lx, p 0x%lx, len 0x%lx, flags 0x%lx\n",
             v, p, length, flags);
    }
}

flush_entry get_page_flush_entry(void)
{
    return 0;
}

void page_invalidate_flush(void)
{
}

void page_invalidate_sync(flush_entry f, thunk completion)
{
    post_sync();
    if (completion)
        apply(completion);
}

void page_invalidate(flush_entry f, u64 address)
{
    leaf_invalidate(address);
}

/* called with lock held */
closure_function(1, 3, boolean, unmap_page,
                 range_handler, rh,
                 int, level, u64, vaddr, u64 *, entry)
{
    range_handler rh = bound(rh);
    u64 old_entry = *entry;
    if (pt_entry_is_present(old_entry) && pt_entry_is_pte(level, old_entry)) {
#ifdef PAGE_UPDATE_DEBUG
        page_debug("rh %p, level %d, vaddr 0x%lx, entry %p, *entry 0x%lx\n",
                   rh, level, vaddr, entry, *entry);
#endif
        /* break before make */
        *entry = 0;
        leaf_invalidate(vaddr);
        if (rh) {
            u64 size = pt_entry_size(level, old_entry);
            assert(size);
            apply(rh, irangel(page_from_pte(old_entry), size));
        }
    }
    return true;
}

void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh)
{
    assert(!((virtual & PAGEMASK) || (length & PAGEMASK)));
    traverse_ptes(virtual, length, stack_closure(unmap_page, rh));
    post_sync();
}

void unmap(u64 virtual, u64 length)
{
#ifdef PAGE_DEBUG
    console("unmap v: ");
    print_u64(virtual);
    console(", length: ");
    print_u64(length);
    console("\n");
#endif
    unmap_pages(virtual, length);
}

closure_function(0, 1, void, dealloc_phys_page,
                 range, r)
{
    if (!id_heap_set_area(physheap, r.start, range_span(r), true, false))
        msg_err("some of physical range %R not allocated in heap\n", r);
}

void unmap_and_free_phys(u64 virtual, u64 length)
{
    unmap_pages_with_handler(virtual, length, stack_closure(dealloc_phys_page));
}

// XXX
extern void *START, *END;
extern void *LOAD_OFFSET;


#define PTE_ENTRIES U64_FROM_BIT(9)
static boolean recurse_ptes(u64 *table_ptr, int level, u64 vstart, u64 len, u64 laddr, entry_handler ph)
{
    int shift = page_level_shifts_4K[level];
    u64 lsize = U64_FROM_BIT(shift);
    u64 start_idx = vstart > laddr ? ((vstart - laddr) >> shift) : 0;
    u64 x = vstart + len - laddr;
    u64 end_idx = MIN(pad(x, lsize) >> shift, PTE_ENTRIES);
    u64 offset = start_idx << shift;

#ifdef TRAVERSE_PTES_DEBUG
    rprintf("   pbase 0x%lx, level %d, shift %d, lsize 0x%lx, laddr 0x%lx,\n"
            "      start_idx %ld, end_idx %ld, offset 0x%lx\n",
            pbase, level, shift, lsize, laddr, start_idx, end_idx, offset);
#endif

    assert(start_idx <= PTE_ENTRIES);
    assert(end_idx <= PTE_ENTRIES);

    for (u64 i = start_idx; i < end_idx; i++, offset += lsize) {
        u64 addr = laddr + (i << shift);
//        u64 pteaddr = pbase + (i * sizeof(u64));
//        u64 *pte = pointer_from_pteaddr(pteaddr);
        u64 *pte = table_ptr + i;
#ifdef TRAVERSE_PTES_DEBUG
        rprintf("   idx %d, offset 0x%lx, addr 0x%lx, pteaddr 0x%lx, *pte %p\n",
                i, offset, addr, pteaddr, *pte);
#endif
        if (!apply(ph, level, addr, pte))
            return false;
        if (!pt_entry_is_present(*pte))
            continue;
        if ((level == 1 || level == 2) && (*pte & PAGE_L0_2_DESC_TABLE) == 0)
            continue;
        if (level < 3) {
            u64 *nexttable_ptr = pointer_from_pteaddr(table_from_pte(*pte));
            if (!recurse_ptes(nexttable_ptr, level + 1, vstart, len,
                              laddr + offset, ph))
                return false;
        }
    }
    return true;
}

boolean traverse_ptes(u64 vaddr, u64 length, entry_handler ph)
{
#ifdef TRAVERSE_PTES_DEBUG
    rprintf("traverse_ptes vaddr 0x%lx, length 0x%lx\n", vaddr, length);
#endif
    pagetable_lock();
    boolean result = recurse_ptes(table_from_vaddr(vaddr), 0,
                                  vaddr & MASK(VIRTUAL_ADDRESS_BITS),
                                  length, 0, ph);
    if (!result)
        rprintf("fail\n");
    pagetable_unlock();
    return result;
}

/* Update access protection flags for any pages mapped within a given area */
void update_map_flags(u64 vaddr, u64 length, u64 flags)
{
#if 0
    flags &= ~PAGE_NO_FAT;
    page_debug("vaddr 0x%lx, length 0x%lx, flags 0x%lx\n", vaddr, length, flags);
    traverse_ptes(vaddr, length, stack_closure(update_pte_flags, flags));
#endif
}

/* called with lock held */
closure_function(2, 3, boolean, remap_entry,
                 u64, new, u64, old,
                 int, level, u64, curr, u64 *, entry)
{
    u64 offset = curr - bound(old);
    u64 oldentry = *entry;
    u64 new_curr = bound(new) + offset;
    u64 phys = page_from_pte(oldentry);
    u64 flags = flags_from_pte(oldentry);
#ifdef PAGE_UPDATE_DEBUG
    page_debug("%s: level %d, old curr 0x%lx, phys 0x%lx, new curr 0x%lx\n"
               "   entry 0x%lx, *entry 0x%lx, flags 0x%lx\n",
               level, curr, phys, new_curr, entry, *entry, flags);
#endif

    int map_order = pt_entry_order(level, oldentry);

    /* valid leaves only */
    if (map_order == 0)
        return true;

    /* transpose mapped page */
    assert(map_area(irangel(new_curr, U64_FROM_BIT(map_order)), phys, flags));

    /* reset old entry */
    *entry = 0;

    /* invalidate old mapping */
    leaf_invalidate(curr);
    return true;
}

/* We're just going to do forward traversal, for we don't yet need to
   support overlapping moves. Should the latter become necessary
   (e.g. to support MREMAP_FIXED in mremap(2) without depending on
   MREMAP_MAYMOVE), write a "traverse_ptes_reverse" to walk pages
   from high address to low (like memcpy).
*/
void remap_pages(u64 vaddr_new, u64 vaddr_old, u64 length)
{
    page_debug("vaddr_new 0x%lx, vaddr_old 0x%lx, length 0x%lx\n", vaddr_new, vaddr_old, length);
    if (vaddr_new == vaddr_old)
        return;
    assert(range_empty(range_intersection(irangel(vaddr_new, length),
                                          irangel(vaddr_old, length))));
    traverse_ptes(vaddr_old, length, stack_closure(remap_entry, vaddr_new, vaddr_old));
    post_sync();
}


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
        u64_from_field(TCR_EL1_T1SZ, 64 - VIRTUAL_ADDRESS_BITS) |
        u64_from_field(TCR_EL1_TG1, TCR_EL1_TG1_4KB) |
        u64_from_field(TCR_EL1_ORGN1, TCR_EL1_xRGN_WB) | /* XXX verify */
        u64_from_field(TCR_EL1_IRGN1, TCR_EL1_xRGN_WB) | /* XXX verify */

        /* for TTBR0_EL1 (user) */
        u64_from_field(TCR_EL1_T0SZ, 64 - VIRTUAL_ADDRESS_BITS) |
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

void page_heap_init(heap locked, id_heap physical)
{
    physheap = physical;
    /* XXX clear up with identity */
#if 0
    pt_p2v = allocate_table(h, identity_key, pointer_equal);
    assert(pt_p2v != INVALID_ADDRESS);

    /* create new mapping for previously identity-mapped init region */
    pt_virt_remain = irangel(PAGES_BASE, PAGESIZE_2M);
    map_area(pt_virt_remain, init_identity.start, PAGE_ATTRS);
    table_set(pt_p2v, (void *)init_identity.start, (void *)PAGES_BASE);
#endif
}
