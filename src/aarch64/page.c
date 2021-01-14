#include <kernel.h>
#include <page.h>

//#define PAGE_DEBUG
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

/* direct map heap - prob move to generic */

typedef struct direct_map {
    struct heap h;
    heap meta;
    heap physical;
    u64 map_offset;
    struct spinlock lock;
    bitmap mapped;
} *direct_map;

#define DIRECT_MAP_IDX_LIMIT ((DIRECT_MAP_LIMIT - DIRECT_MAP_BASE) >> DIRECT_MAP_PAGELOG)

static inline int direct_get_index(direct_map dm, u64 paddr)
{
    return (paddr >> DIRECT_MAP_PAGELOG) - dm->map_offset;
}

static inline u64 direct_base_from_index(direct_map dm, int index)
{
    return DIRECT_MAP_BASE + ((u64)index << DIRECT_MAP_PAGELOG);
}

static inline u64 direct_map_add_physical(direct_map dm, u64 p)
{
    int index = direct_get_index(dm, p);
    assert(index < DIRECT_MAP_IDX_LIMIT);
    boolean mapped = bitmap_get(dm->mapped, index);
    u64 offset = p & MASK(DIRECT_MAP_PAGELOG);
    u64 vbase = direct_base_from_index(dm, index);
    u64 pbase = p & ~MASK(DIRECT_MAP_PAGELOG);
    if (!mapped) {
        map(vbase, pbase, U64_FROM_BIT(DIRECT_MAP_PAGELOG), PAGE_BACKED_FLAGS);
        bitmap_set(dm->mapped, index, 1);
    }
    return vbase + offset;
}

static inline u64 direct_alloc_internal(direct_map dm, bytes size)
{
    u64 len = pad(size, dm->h.pagesize);
    u64 p = allocate_u64(dm->physical, len);
    if (p == INVALID_PHYSICAL)
        return p;
    return direct_map_add_physical(dm, p);
}

static inline boolean direct_map_validate_physical(direct_map dm, u64 p)
{
    return bitmap_get(dm->mapped, direct_get_index(dm, p));
}

static inline u64 direct_map_virtual_from_physical(direct_map dm, u64 p)
{
    assert(direct_map_validate_physical(dm, p));
    return direct_base_from_index(dm, direct_get_index(dm, p)) +
        (p & MASK(DIRECT_MAP_PAGELOG));
}

static inline u64 direct_map_physical_from_virtual(direct_map dm, u64 v)
{
    return (v - DIRECT_MAP_BASE) + dm->map_offset;
}

static u64 direct_alloc(heap h, bytes size)
{
    return direct_alloc_internal((direct_map)h, size);
}

static void direct_dealloc(heap h, u64 x, bytes size)
{
    /* nop */
}

static void direct_destroy(heap h)
{
    /* nop */
}

/* pass through to phys ... */
static bytes direct_allocated(heap h)
{
    return heap_allocated((heap)((direct_map)h)->physical);
}

static bytes direct_total(heap h)
{
    return heap_total((heap)((direct_map)h)->physical);
}

direct_map allocate_direct_map_heap(heap meta, heap physical, u64 phys_base)
{
    direct_map dm = allocate(meta, sizeof(*dm));
    if (dm == INVALID_ADDRESS)
        return dm;
    dm->h.alloc = direct_alloc;
    dm->h.dealloc = direct_dealloc;
    dm->h.destroy = direct_destroy;
    dm->h.allocated = direct_allocated;
    dm->h.total = direct_total;
    dm->h.pagesize = physical->pagesize;

    dm->meta = meta;
    dm->physical = physical;
    dm->map_offset = phys_base >> DIRECT_MAP_PAGELOG;
    dm->mapped = allocate_bitmap(meta, meta, DIRECT_MAP_IDX_LIMIT);
    bitmap_extend(dm->mapped, DIRECT_MAP_IDX_LIMIT - 1);
    return dm;
}

static direct_map pageheap;
static u64 init_table;
static range current_pt_phys;
static id_heap physheap;

static u64 kernel_tablebase;
static u64 user_tablebase;

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
    return pointer_from_u64(pageheap ? direct_map_virtual_from_physical(pageheap, pa) : pa);
}

void dump_ptes(void *vaddr)
{
    // XXX TODO
}

static boolean map_area(range v, u64 p, u64 flags);

/* pt_lock should already be held here */
static boolean get_table_page(u64 *phys)
{
    if (range_span(current_pt_phys) == 0) {
        page_init_debug_u64(current_pt_phys.start);
        page_init_debug(", \n");
        page_init_debug_u64(current_pt_phys.end);
        page_init_debug(", \n");
        page_init_debug_u64(range_span(current_pt_phys));

        u64 va = allocate_u64((heap)pageheap, PAGESIZE_2M);
        if (va == INVALID_PHYSICAL) {
            msg_err("failed to allocate 2M table page\n");
            return false;
        }

        current_pt_phys = irangel(direct_map_physical_from_virtual(pageheap, va), PAGESIZE_2M);
    }

    page_init_debug("current_pt_phys.start ");
    page_init_debug_u64(current_pt_phys.start);
    page_init_debug(", ");
    page_init_debug_u64(current_pt_phys.end);

    *phys = current_pt_phys.start;
    current_pt_phys.start += PAGESIZE;

    u64 *p = pointer_from_pteaddr(*phys);
    for (int i = 0; i < PAGESIZE >> 3; i += 4) {
        p[i] = 0;
        p[i + 1] = 0;
        p[i + 2] = 0;
        p[i + 3] = 0;
    }
    page_init_debug("\n");
    return true;
}

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
                u64 newtable;
                if (!get_table_page(&newtable)) {
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
                if (!map_level(pointer_from_pteaddr(newtable), level + 1, irangel(v.start, len),
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
            /* fail if page or block already installed */
            if (level == 3 || (pte & PAGE_L0_2_DESC_TABLE) == 0) {
                msg_err("would overwrite entry: level %d, v %R, pa 0x%lx, "
                        "flags 0x%lx, index %d, entry 0x%lx\n", level, v, *p,
                        flags, i, pte);
                return false;
            }
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
    u64 pbase = (vaddr & U64_FROM_BIT(55)) ? kernel_tablebase : user_tablebase;
    return pointer_from_pteaddr(pbase);
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

/* XXX don't need this variant anymore */
void unmap_and_free_phys(u64 virtual, u64 length)
{
    unmap_pages_with_handler(virtual, length, stack_closure(dealloc_phys_page));
}

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

/* called with lock held */
closure_function(2, 3, boolean, update_pte_flags,
                 u64, flags, flush_entry, fe,
                 int, level, u64, addr, u64 *, entry)
{
    /* we only care about present ptes */
    u64 old = *entry;
    if (!pt_entry_is_present(old) || !pt_entry_is_pte(level, old))
        return true;

    *entry = (old & ~PAGE_PROT_FLAGS) | bound(flags);
#ifdef PAGE_UPDATE_DEBUG
    page_debug("update 0x%lx: pte @ 0x%lx, 0x%lx -> 0x%lx\n", addr, entry, old, *entry);
#endif
    page_invalidate(bound(fe), addr);
    return true;
}

/* Update access protection flags for any pages mapped within a given area */
void update_map_flags(u64 vaddr, u64 length, u64 flags)
{
    page_debug("vaddr 0x%lx, length 0x%lx, flags 0x%lx\n", vaddr, length, flags);
    flush_entry fe = get_page_flush_entry();
    traverse_ptes(vaddr, length, stack_closure(update_pte_flags, flags, fe));
    page_invalidate_sync(fe, ignore);
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

extern void *START, *END;
extern void *LOAD_OFFSET;

/* init_pt is a 2M block to use for inital ptes */
void page_init_mmu(range init_pt, u64 vtarget)
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
    if (field_from_u64(read_psr(ID_AA64MMFR0_EL1),
                       ID_AA64MMFR0_EL1_TGran4) != 0)
        halt("%s: 4KB granule not supported\n", __func__);

    current_pt_phys = init_pt;
    init_table = init_pt.start;

    /* memory attributes */
    write_psr(MAIR_EL1, MAIR_EL1_INIT);
    
    assert(get_table_page(&user_tablebase));
    write_psr(TTBR0_EL1, user_tablebase);
    assert(get_table_page(&kernel_tablebase));
    write_psr(TTBR1_EL1, kernel_tablebase);
    
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
    write_psr(MDSCR_EL1, 0);

    u64 kernel_size = pad(u64_from_pointer(&END) -
                          u64_from_pointer(&START), PAGESIZE);
    page_init_debug("kernel_size ");
    page_init_debug_u64(kernel_size);
    page_init_debug("\n");
    map(KERNEL_BASE, KERNEL_PHYS, kernel_size, 0);

    page_init_debug("map devices\n");
    map(DEVICE_BASE, 0, DEV_MAP_SIZE, 0);

    page_init_debug("map temporary identity mapping\n");
    map(0x40000000, 0x40000000, INIT_IDENTITY_SIZE, 0);

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

    direct_map dm = allocate_direct_map_heap(locked, (heap)physical, PHYSMEM_BASE);
    assert(dm != INVALID_ADDRESS);
    direct_map_add_physical(dm, init_table);
    pageheap = dm;

    /* unmap temporary identity map */
    unmap(0x40000000, INIT_IDENTITY_SIZE);
}
