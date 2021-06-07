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

#ifdef KERNEL
static struct spinlock pt_lock;
#define pagetable_lock() u64 _savedflags = spin_lock_irq(&pt_lock)
#define pagetable_unlock() spin_unlock_irq(&pt_lock, _savedflags)
#else
#define pagetable_lock()
#define pagetable_unlock()
#endif

static inline u64 flags_from_pte(u64 pte)
{
    return pte & _PAGE_FLAGS_MASK;
}

static heap pageheap;
static u64 pagebase;

static u64 *(*pointer_from_pteaddr)(u64 pa);
static u64 (*pteaddr_from_pointer)(u64 *p);

#ifdef BOOT
static inline u64 *boot_pointer_from_pteaddr(u64 pa)
{
    return pointer_from_u64(pa);
}

static inline u64 boot_pteaddr_from_pointer(u64 *p)
{
    return u64_from_pointer(p);
}
#else
static table pt_p2v;
static range pt_initial_phys;

static inline u64 *boot_pointer_from_pteaddr(u64 pa)
{
    return (u64 *)pa;
}

static inline u64 boot_pteaddr_from_pointer(u64 *p)
{
    return (u64)p;
}

// XXX rid of p2v?
static inline u64 *kern_pointer_from_pteaddr(u64 pa)
{
    if (point_in_range(pt_initial_phys, pa)) {
        u64 v = (pa - pt_initial_phys.start) + PAGES_BASE;
        return pointer_from_u64(v);
    }
    u64 offset = pa & MASK(PAGELOG_2M);
    u64 p = pa & ~MASK(PAGELOG_2M);
    u64 v = (u64)table_find(pt_p2v, (void *)p);
    assert(v);
    return pointer_from_u64(v + offset);
}

static physical physical_from_virtual_locked(void *x);
static inline u64 kern_pteaddr_from_pointer(u64 *p)
{
    return physical_from_virtual_locked(p);
}
#endif

static inline u64 pte_lookup_phys(u64 table, u64 vaddr, int offset)
{
    return table + (((vaddr >> offset) & MASK(9)) << 3);
}

#ifndef physical_from_virtual
static inline u64 *pte_lookup_ptr(u64 table, u64 vaddr, int offset)
{
    return pointer_from_pteaddr(pte_lookup_phys(table, vaddr, offset));
}

static inline u64 page_lookup(u64 table, u64 vaddr, int offset)
{
    u64 a = *pte_lookup_ptr(table, vaddr, offset);
    return (a & 1) ? page_from_pte(a) : 0;
}

#define _pfv_level(table, vaddr, level)                                 \
    u64 *l ## level = pte_lookup_ptr(table, vaddr, PT_SHIFT_L ## level);        \
    if (!(*l ## level & 1))                                             \
        return INVALID_PHYSICAL;

#define _pfv_check_ps(level, vaddr)                                     \
    if (*l ## level & _PAGE_PS)                                         \
        return page_from_pte(*l ## level) | (vaddr & MASK(PT_SHIFT_L ## level));

static physical physical_from_virtual_locked(void *x)
{
    u64 xt = u64_from_pointer(x);
    _pfv_level(pagebase, xt, 1);
    _pfv_level(page_from_pte(*l1), xt, 2);
    _pfv_check_ps(2, xt);
    _pfv_level(page_from_pte(*l2), xt, 3);
    _pfv_check_ps(3, xt);
    _pfv_level(page_from_pte(*l3), xt, 4);
    return page_from_pte(*l4) | (xt & MASK(PT_SHIFT_L4));
}

physical physical_from_virtual(void *x)
{
    u64 a = u64_from_pointer(x);
    if (is_huge_backed_address(a))
        return phys_from_huge_backed_virt(a);
    u64 p;
    pagetable_lock();
    p = physical_from_virtual_locked(x);
    pagetable_unlock();
    return p;
}
#endif

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

void page_invalidate_sync(flush_entry f, thunk completion)
{
    apply(completion);
}

void page_invalidate_flush()
{

}

flush_entry get_page_flush_entry()
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

#define PTE_ENTRIES U64_FROM_BIT(9)
static boolean recurse_ptes(u64 pbase, int level, u64 vstart, u64 len, u64 laddr, entry_handler ph)
{
    int shift = pt_level_shift(level);
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
        if (addr & U64_FROM_BIT(47))
            addr |= 0xffff000000000000; /* make canonical */
        u64 pteaddr = pbase + (i * sizeof(u64));
        u64 *pte = pointer_from_pteaddr(pteaddr);
#ifdef TRAVERSE_PTES_DEBUG
        rprintf("   idx %d, offset 0x%lx, addr 0x%lx, pteaddr 0x%lx, *pte %p\n",
                i, offset, addr, pteaddr, *pte);
#endif
        if (!apply(ph, level, addr, pte))
            return false;
        if (pte_is_present(*pte) && level < 4 && (level == 1 || (*pte & _PAGE_PS) == 0) &&
            !recurse_ptes(page_from_pte(*pte), level + 1, vstart, len,
                          laddr + offset, ph))
            return false;
    }
    return true;
}

boolean traverse_ptes(u64 vaddr, u64 length, entry_handler ph)
{
#ifdef TRAVERSE_PTES_DEBUG
    rprintf("traverse_ptes vaddr 0x%lx, length 0x%lx\n", vaddr, length);
#endif
    pagetable_lock();
    boolean result = recurse_ptes(pagebase, 1, vaddr & MASK(VIRTUAL_ADDRESS_BITS),
                                  length, 0, ph);
    pagetable_unlock();
    return result;
}

/* called with lock held */
closure_function(0, 3, boolean, validate_entry,
                 int, level, u64, vaddr, pteptr, entry)
{
    return pte_is_present(pte_from_pteptr(entry));
}

/* validate that all pages in vaddr range [base, base + length) are present */
boolean validate_virtual(void * base, u64 length)
{
    page_debug("base %p, length 0x%lx\n", base, length);
    return traverse_ptes(u64_from_pointer(base), length, stack_closure(validate_entry));
}

/* called with lock held */
closure_function(2, 3, boolean, update_pte_flags,
                 pageflags, flags, flush_entry, fe,
                 int, level, u64, addr, pteptr, entry)
{
    /* we only care about present ptes */
    pte orig_pte = pte_from_pteptr(entry);
    if (!pte_is_present(orig_pte) || !pte_is_mapping(level, orig_pte))
        return true;

    pte_set(entry, (orig_pte & ~_PAGE_PROT_FLAGS) | bound(flags).w);
#ifdef PAGE_UPDATE_DEBUG
    page_debug("update 0x%lx: pte @ 0x%lx, 0x%lx -> 0x%lx\n", addr, entry, old,
               pte_from_pteptr(entry).w);
#endif
    page_invalidate(bound(fe), addr);
    return true;
}

/* Update access protection flags for any pages mapped within a given area */
void update_map_flags(u64 vaddr, u64 length, pageflags flags)
{
    flags.w &= ~_PAGE_NO_PS;
    page_debug("%s: vaddr 0x%lx, length 0x%lx, flags 0x%lx\n", __func__, vaddr, length, flags.w);

    /* Catch any attempt to change page flags in a huge_backed mapping */
    assert(!intersects_huge_backed(irangel(vaddr, length)));
    flush_entry fe = get_page_flush_entry();
    traverse_ptes(vaddr, length, stack_closure(update_pte_flags, flags, fe));
    page_invalidate_sync(fe, ignore);
}

static boolean map_level(u64 *table_ptr, int level, range v, u64 *p, u64 flags, flush_entry fe);

/* called with lock held */
closure_function(3, 3, boolean, remap_entry,
                 u64, new, u64, old, flush_entry, fe,
                 int, level, u64, curr, pteptr, entry)
{
    u64 offset = curr - bound(old);
    u64 oldentry = pte_from_pteptr(entry);
    u64 new_curr = bound(new) + offset;
    u64 phys = page_from_pte(oldentry);
    u64 flags = flags_from_pte(oldentry);
    int map_order = pte_order(level, oldentry);

#ifdef PAGE_UPDATE_DEBUG
    page_debug("level %d, old curr 0x%lx, phys 0x%lx, new curr 0x%lx, entry 0x%lx, *entry 0x%lx, flags 0x%lx\n",
               level, curr, phys, new_curr, entry, *entry, flags);
#endif

    /* only look at ptes at this point */
    if (!pte_is_present(oldentry) || !pte_is_mapping(level, oldentry))
        return true;

    /* transpose mapped page */
    assert(map_level(pointer_from_pteaddr(pagebase), 1,
                     irangel(new_curr & MASK(VIRTUAL_ADDRESS_BITS), U64_FROM_BIT(map_order)),
                     &phys, flags, bound(fe)));

    /* reset old entry */
    *entry = 0;

    /* invalidate old mapping (map_page takes care of new)  */
    page_invalidate(bound(fe), curr);

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
    assert(range_empty(range_intersection(irange(vaddr_new, vaddr_new + length),
                                          irange(vaddr_old, vaddr_old + length))));
    flush_entry fe = get_page_flush_entry();
    traverse_ptes(vaddr_old, length, stack_closure(remap_entry, vaddr_new, vaddr_old, fe));
    page_invalidate_sync(fe, ignore);
}

/* called with lock held */
closure_function(0, 3, boolean, zero_page,
                 int, level, u64, addr, pteptr, entry)
{
    u64 e = pte_from_pteptr(entry);
    if (pte_is_present(e) && pte_is_mapping(level, e)) {
        u64 size = pte_map_size(level, e);
#ifdef PAGE_UPDATE_DEBUG
        page_debug("addr 0x%lx, size 0x%lx\n", addr, size);
#endif
        zero(pointer_from_u64(addr), size);
    }
    return true;
}

void zero_mapped_pages(u64 vaddr, u64 length)
{
    traverse_ptes(vaddr, length, stack_closure(zero_page));
}

/* called with lock held */
closure_function(2, 3, boolean, unmap_page,
                 range_handler, rh, flush_entry, fe,
                 int, level, u64, vaddr, pteptr, entry)
{
    range_handler rh = bound(rh);
    u64 old_entry = pte_from_pteptr(entry);
    if (pte_is_present(old_entry) && pte_is_mapping(level, old_entry)) {
#ifdef PAGE_UPDATE_DEBUG
        page_debug("rh %p, level %d, vaddr 0x%lx, entry %p, *entry 0x%lx\n",
                   rh, level, vaddr, entry, *entry);
#endif
        *entry = 0;
        page_invalidate(bound(fe), vaddr);
        if (rh) {
            apply(rh, irangel(page_from_pte(old_entry),
                              pte_map_size(level, old_entry)));
        }
    }
    return true;
}

/* Be warned: the page table lock is held when rh is called; don't try
   to modify the page table while traversing it */
void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh)
{
    assert(!((virtual & PAGEMASK) || (length & PAGEMASK)));
    flush_entry fe = get_page_flush_entry();
    traverse_ptes(virtual, length, stack_closure(unmap_page, rh, fe));
    page_invalidate_sync(fe, ignore);
}

static void *get_table_page(u64 *phys)
{
    // XXX change to backed
    void *n = allocate_zero(pageheap, PAGESIZE);
    if (n != INVALID_ADDRESS)
        *phys = pteaddr_from_pointer(n);
    return n;
}

#define next_addr(a, mask) (a = (a + (mask) + 1) & ~(mask))
#define INDEX_MASK (PAGEMASK >> 3)
static boolean map_level(u64 *table_ptr, int level, range v, u64 *p, u64 flags, flush_entry fe)
{
    int shift = pt_level_shift(level);
    u64 mask = MASK(shift);
    u64 vlbase = level > 2 ? v.start & ~MASK(pt_level_shift(level - 1)) : 0;
    int first_index = (v.start >> shift) & INDEX_MASK;
    int last_index = ((v.end - 1) >> shift) & INDEX_MASK;

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
    assert(last_index < (PAGESIZE >> 3)); // XXX
    assert(first_index <= last_index);
    assert(table_ptr && table_ptr != INVALID_ADDRESS);

    for (int i = first_index; i <= last_index; i++, next_addr(v.start, mask)) {
        boolean invalidate = false; /* page at v.start */
        page_init_debug("   index ");
        page_init_debug_u64(i);
        page_init_debug(", v.start ");
        page_init_debug_u64(v.start);
        page_init_debug(", p ");
        page_init_debug_u64(*p);
        page_init_debug("\n");
        u64 pte = table_ptr[i];
        page_init_debug(": ");
        page_init_debug_u64(pte);
        page_init_debug("\n");
        if ((pte & _PAGE_PRESENT) == 0) {
            if (level == 4) {
                page_init_debug("   -pte-   ");
                pte = *p | (flags & ~_PAGE_NO_PS) | _PAGE_PRESENT;
                next_addr(*p, mask);
                invalidate = true;
            } else if (!(flags & _PAGE_NO_PS) && level > 1 && (v.start & mask) == 0 &&
                       (*p & mask) == 0 && range_span(v) >= U64_FROM_BIT(shift)) {
                page_init_debug(level == 2 ? "   -pdpe-  " : "   -pde-   ");
                page_init_debug_u64(v.start);
                page_init_debug(" span ");
                page_init_debug_u64(range_span(v));
                page_init_debug(" p ");
                page_init_debug_u64(*p);
                page_init_debug("\n");
                pte = *p | flags | _PAGE_PRESENT | _PAGE_PS;
                next_addr(*p, mask);
                invalidate = true;
            } else {
                page_init_debug("   -new level- ");
                void *tp;
                u64 tp_phys;
                if ((tp = get_table_page(&tp_phys)) == INVALID_ADDRESS) {
                    msg_err("failed to allocate page table memory\n");
                    return false;
                }
                /* user and writable are AND of flags from all levels */
                pte = tp_phys | _PAGE_WRITABLE | _PAGE_USER | _PAGE_PRESENT;
                u64 end = vlbase | (((u64)(i + 1)) << shift);
                /* length instead of end to avoid overflow at end of space */
                u64 len = MIN(range_span(v), end - v.start);
                page_init_debug("  end ");
                page_init_debug_u64(end);
                page_init_debug(", len ");
                page_init_debug_u64(len);
                page_init_debug("\n");
                if (!map_level(tp, level + 1, irangel(v.start, len), p, flags, fe))
                    return false;
            }
            page_init_debug("   SET @ ");
            page_init_debug_u64(u64_from_pointer(&table_ptr[i]));
            page_init_debug(" = ");
            page_init_debug_u64(pte);
            page_init_debug("\n");
            table_ptr[i] = pte;
            if (invalidate)
                page_invalidate(fe, v.start);
        } else {
            /* fail if page or block already installed */
            if (pte_is_mapping(level, pte)) {
                msg_err("would overwrite entry: level %d, v %R, pa 0x%lx, "
                        "flags 0x%lx, index %d, entry 0x%lx\n", level, v, *p,
                        flags, i, pte);
                return false;
            }
            u64 nexttable = page_from_pte(pte);
            u64 *nexttable_ptr = pointer_from_pteaddr(nexttable);
            u64 end = vlbase | (((u64)(i + 1)) << shift);
            u64 len = MIN(range_span(v), end - v.start);
            page_init_debug("   len 2 ");
            page_init_debug_u64(len);
            page_init_debug("\n");
            if (!map_level(nexttable_ptr, level + 1, irangel(v.start, len), p, flags, fe))
                return false;
        }
    }
    return true;
}

void map(u64 v, physical p, u64 length, pageflags flags)
{
    page_init_debug("map: v ");
    page_init_debug_u64(v);
    page_init_debug(", p ");
    page_init_debug_u64(p);
    page_init_debug(", length ");
    page_init_debug_u64(length);
    page_init_debug(", flags ");
    page_init_debug_u64(flags.w);
    page_init_debug(", called from ");
    page_init_debug_u64(u64_from_pointer(__builtin_return_address(0)));
    page_init_debug("\n");

    assert((v & PAGEMASK) == 0);
    assert((p & PAGEMASK) == 0);
    range r = irangel(v & MASK(VIRTUAL_ADDRESS_BITS), pad(length, PAGESIZE));
    flush_entry fe = get_page_flush_entry();
    pagetable_lock();
    u64 *table_ptr = pointer_from_pteaddr(pagebase);
    if (!map_level(table_ptr, 1, r, &p, flags.w, fe)) {
        pagetable_unlock();
        rprintf("ra %p\n", __builtin_return_address(0));
        print_frame_trace_from_here();
        halt("map failed for v 0x%lx, p 0x%lx, len 0x%lx, flags 0x%lx\n",
             v, p, length, flags.w);
    }
    page_invalidate_sync(fe, ignore);
    pagetable_unlock();
}

void unmap(u64 virtual, u64 length)
{
#ifdef PAGE_DEBUG
    rputs("unmap v: ");
    print_u64(virtual);
    rputs(", length: ");
    print_u64(length);
    rputs("\n");
#endif
    unmap_pages(virtual, length);
}

void *bootstrap_page_tables(heap initial)
{
    /* page table setup */
    pageheap = initial;
    void *pgdir = allocate_zero(initial, PAGESIZE);
    assert(pgdir != INVALID_ADDRESS);
    pagebase = u64_from_pointer(pgdir);
    pointer_from_pteaddr = boot_pointer_from_pteaddr;
    pteaddr_from_pointer = boot_pteaddr_from_pointer;
#ifdef KERNEL
    spin_lock_init(&pt_lock);
#endif
    return pgdir;
}

#ifdef KERNEL
static id_heap phys_internal;
static u64 pt_2m_next;

closure_function(0, 1, void, dealloc_phys_page,
                 range, r)
{
    if (!id_heap_set_area(phys_internal, r.start, range_span(r), true, false))
        msg_err("some of physical range %R not allocated in heap\n", r);
}

void unmap_and_free_phys(u64 virtual, u64 length)
{
    unmap_pages_with_handler(virtual, length, stack_closure(dealloc_phys_page));
}

/* pt_lock should already be held here */
static u64 pt_2m_alloc(heap h, bytes size)
{
    /* carve out a virtual ... no dealloc here - we don't dealloc pt
       pages either, but if we wanted to, the child 4k page heap
       will take care of reuse */
    assert(pt_2m_next > 0);
    u64 len = pad(size, PAGESIZE_2M);
    u64 v = pt_2m_next;
    pt_2m_next += len;
    assert(pt_2m_next >= PAGES_BASE);

    flush_entry fe = get_page_flush_entry();
    for (u64 i = v; i < v + len; i += PAGESIZE_2M) {
        u64 p = allocate_u64((heap)phys_internal, PAGESIZE_2M);
        if (p == INVALID_PHYSICAL)
            halt("%s: failed to allocate 2M physical page\n", __func__);
        /* we depend the pmd already being installed to avoid an alloc here */
        map(i, p, PAGESIZE_2M, pageflags_writable(pageflags_memory()));
        table_set(pt_p2v, (void *)p, (void *)i);
    }
    page_invalidate_sync(fe, ignore);
    return v;
}

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

/* this happens even before moving to the new stack, so ... be cool */
void init_page_tables(heap h, id_heap physical, range initial_phys)
{
    u32 v[4];
    cpuid(0x80000001, 0, v);
    // XXX we could switch off 1GB mappings...
    assert(v[3] & U64_FROM_BIT(26)); /* 1GB page support */
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_NXE);
    mov_from_cr("cr3", pagebase);
    pointer_from_pteaddr = kern_pointer_from_pteaddr;
    pteaddr_from_pointer = kern_pteaddr_from_pointer;
    spin_lock_init(&pt_lock);
    phys_internal = physical;

    pt_p2v = allocate_table(h, identity_key, pointer_equal);
    assert(pt_p2v != INVALID_ADDRESS);

    /* store initial boundaries for p->v lookup */
    pt_initial_phys = initial_phys;
    pt_2m_next = PAGES_BASE + pad(range_span(initial_phys), PAGESIZE_2M);

    /* 2m heap for stage3 pt allocs */
    heap pt_2m = allocate(h, sizeof(struct heap));
    assert(pt_2m != INVALID_ADDRESS);
    pt_2m->alloc = pt_2m_alloc;
    pt_2m->dealloc = leak;
    pt_2m->pagesize = PAGESIZE_2M;

    /* 4k page heap */
    pageheap = (heap)create_id_heap_backed(h, /* XXX */ h, pt_2m, PAGESIZE, true);
    assert(pageheap != INVALID_ADDRESS);
}
#else
/* stage2 */
void init_page_tables(heap initial)
{
    void *vmbase = bootstrap_page_tables(initial);
    mov_to_cr("cr3", vmbase);
}
#endif
