#include <kernel.h>
#include <page.h>

/* Would be nice to have one debug output with a mux to console for early init (i.e. before formatters enabled) */
//#define PAGE_DEBUG
//#define PAGE_UPDATE_DEBUG
//#define PTE_DEBUG

#if defined(PAGE_DEBUG) && !defined(BOOT)
#define page_debug(x, ...) do {log_printf("PAGE", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define page_debug(x, ...)
#endif

#ifdef STAGE3
static struct spinlock pt_lock;
#define pagetable_lock() u64 _savedflags = spin_lock_irq(&pt_lock)
#define pagetable_unlock() spin_unlock_irq(&pt_lock, _savedflags)
#else
#define pagetable_lock()
#define pagetable_unlock()
#endif

#define PT1 39
#define PT2 30
#define PT3 21
#define PT4 12

static heap pageheap;

static const int level_shift[5] = { -1, PT1, PT2, PT3, PT4 };

static u64 pagebase;

static u64 *(*pointer_from_pteaddr)(u64 pa);
static u64 (*pteaddr_from_pointer)(u64 *p);

#ifdef BOOT
static inline u64 *boot_pointer_from_pteaddr(u64 pa)
{
    return (u64*)(u32)pa;
}

static inline u64 boot_pteaddr_from_pointer(u64 *p)
{
    return (u64)(u32)p;
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

static inline u64 flags_from_pte(u64 pte)
{
    return pte & PAGE_FLAGS_MASK;
}

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

static physical physical_from_virtual_locked(void *x)
{
    u64 xt = u64_from_pointer(x);
    u64 l3 = page_lookup(pagebase, xt, PT1);
    if (!l3) return INVALID_PHYSICAL;
    u64 l2 = page_lookup(l3, xt, PT2);
    if (!l2) return INVALID_PHYSICAL;
    u64 l1 = page_lookup(l2, xt, PT3); // 2m pages
    if (!l1) return INVALID_PHYSICAL;
    if (*pte_lookup_ptr(l2, xt, PT3) & PAGE_2M_SIZE) {
        return (l1 | (xt & MASK(PT3)));
    }
    u64 l0 = page_lookup(l1, xt, PT4);
    return l0 ? l0 | (xt & MASK(PT4)) : INVALID_PHYSICAL;
}

physical physical_from_virtual(void *x)
{
    u64 p;
    pagetable_lock();
    p = physical_from_virtual_locked(x);
    pagetable_unlock();
    return p;
}
#endif

void flush_tlb()
{
    pagetable_lock();
    u64 *base;
    mov_from_cr("cr3", base);
    mov_to_cr("cr3", base);
    pagetable_unlock();
}

#ifdef BOOT
void page_invalidate(u64 address, thunk completion)
{
    flush_tlb();
    apply(completion);
}
#endif

#ifndef BOOT
void dump_ptes(void *x)
{
    pagetable_lock();
    u64 xt = u64_from_pointer(x);

    rprintf("dump_ptes 0x%lx\n", x);
    u64 l1 = *pte_lookup_ptr(pagebase, xt, PT1);
    rprintf("  l1: 0x%lx\n", l1);
    if (l1 & 1) {
        u64 l2 = *pte_lookup_ptr(l1, xt, PT2);
        rprintf("  l2: 0x%lx\n", l2);
        if (l2 & 1) {
            u64 l3 = *pte_lookup_ptr(l2, xt, PT3);
            rprintf("  l3: 0x%lx\n", l3);
            if ((l3 & 1) && (l3 & PAGE_2M_SIZE) == 0) {
                u64 l4 = *pte_lookup_ptr(l3, xt, PT4);
                rprintf("  l4: 0x%lx\n", l4);
            }
        }
    }
    pagetable_unlock();
}
#endif

static void write_pte(u64 target, physical to, u64 flags, boolean * invalidate)
{
    u64 new = to | flags;
    u64 *pteptr = pointer_from_pteaddr(target);
#ifdef PTE_DEBUG
    console(", write_pte: ");
    print_u64(u64_from_pointer(target));
    console(" = ");
    print_u64(new);
#endif
    assert((new & PAGE_NO_FAT) == 0);
    if (*pteptr == new) {
#ifdef PTE_DEBUG
	console(", pte same; no op");
#endif
	return;
    }
    /* invalidate when changing any pte that was marked as present */
    if (*pteptr & PAGE_PRESENT) {
#ifdef PTE_DEBUG
        console("   invalidate, old ");
        print_u64(*pteptr);
        console(", new ");
        print_u64(new);
        console("\n");
#endif
	*invalidate = true;
    }
    *pteptr = new;
#ifdef PTE_DEBUG
    console("\n");
#endif
}

#ifdef PTE_DEBUG
static void print_level(int level)
{
    int i;
    for (i = 0; i < level - 1; i++)
	rprintf(" ");
    rprintf("%d", level);
    for (i = 0; i < 5 - level; i++)
	rprintf(" ");
}
#endif

/* p == 0 && flags == 0 for unmap */
static boolean force_entry(u64 b, u64 v, physical p, int level,
			   boolean fat, u64 flags, boolean *invalidate)
{
    u64 pte_phys = pte_lookup_phys(b, v, level_shift[level]);
    assert((flags & PAGE_NO_FAT) == 0);

    if (level == (fat ? 3 : 4)) {
#ifdef PTE_DEBUG
	console("! ");
	print_level(level);
	console(", phys ");
	print_u64(pte_phys);
#endif
	if (fat)
	    flags |= PAGE_2M_SIZE;
	write_pte(pte_phys, p, flags, invalidate);
	return true;
    } else {
	if (*pointer_from_pteaddr(pte_phys) & PAGE_PRESENT) {
            if (pt_entry_is_fat(level, *pointer_from_pteaddr(pte_phys))) {
                console("\nforce_entry fail: attempting to map a 4K page over an "
                        "existing 2M mapping\n");
                return false;
            }
            /* XXX when unmapping, add a check here to see if the
               directory page is completely unused, and explicitly
               remove and free them when possible. This will avoid the
               occasional invalidate caused by lingering mid
               directories without entries */
	    return force_entry(page_from_pte(*pointer_from_pteaddr(pte_phys)), v, p, level + 1,
                               fat, flags, invalidate);
	} else {
	    if (flags == 0)	/* only lookup for unmap */
		return false;
	    u64 *n = allocate_zero(pageheap, PAGESIZE);
	    if (n == INVALID_ADDRESS)
		return false;

            /* TODO kind of ridiculous to lose the phys addr from the
               allocation just to look it up again... */
            u64 n_addr = pteaddr_from_pointer(n);
	    if (!force_entry(n_addr, v, p, level + 1, fat, flags, invalidate))
                return false;
#ifdef PTE_DEBUG
            // XXX update debugs
	    console("- ");
	    print_level(level);
	    console(", phys ");
	    print_u64(pte_phys);
#endif
            /* user and writable are AND of flags from all levels */
	    write_pte(pte_phys, n_addr, PAGE_WRITABLE | PAGE_USER | PAGE_PRESENT, invalidate);
	    return true;
	}
    }
}

/* called with lock held */
static inline boolean map_page(u64 base, u64 v, physical p,
                               boolean fat, u64 flags, boolean * invalidate)
{
    boolean invalidate_entry = false;
#ifdef PAGE_UPDATE_DEBUG
    rprintf("force entry base 0x%p, v 0x%lx, p 0x%lx, fat %d, flags 0x%lx\n",
            base, v, p, fat, flags);
#endif
    v &= MASK(VIRTUAL_ADDRESS_BITS);
    if (!force_entry(base, v, p, 1, fat, flags, &invalidate_entry))
	return false;
    if (invalidate_entry) {
        // move this up to construct ranges?
        page_invalidate(v, ignore);
        if (invalidate)
            *invalidate = true;
    }
    return true;
}

//#define TRAVERSE_PTES_DEBUG

#define PTE_ENTRIES U64_FROM_BIT(9)
static boolean recurse_ptes(u64 pbase, int level, u64 vstart, u64 len, u64 laddr, entry_handler ph)
{
    int shift = level_shift[level];
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
        if (!pt_entry_is_present(*pte))
            continue;
        if (level == 3 && (*pte & PAGE_2M_SIZE) != 0)
            continue;
        if (level < 4) {
            if (!recurse_ptes(page_from_pte(*pte), level + 1, vstart, len,
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
    boolean result = recurse_ptes(pagebase, 1, vaddr & MASK(VIRTUAL_ADDRESS_BITS),
                                  length, 0, ph);
    if (!result)
        rprintf("fail\n");
    pagetable_unlock();
    return result;
}

/* called with lock held */
closure_function(0, 3, boolean, validate_entry,
                 int, level, u64, vaddr, u64 *, entry)
{
    return pt_entry_is_present(*entry);
}

/* validate that all pages in vaddr range [base, base + length) are present */
boolean validate_virtual(void * base, u64 length)
{
    page_debug("base %p, length 0x%lx\n", base, length);
    return traverse_ptes(u64_from_pointer(base), length, stack_closure(validate_entry));
}

/* called with lock held */
closure_function(1, 3, boolean, update_pte_flags,
                 u64, flags,
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
    page_invalidate(addr, ignore);
    return true;
}

/* Update access protection flags for any pages mapped within a given area */
void update_map_flags(u64 vaddr, u64 length, u64 flags)
{
    flags &= ~PAGE_NO_FAT;
    page_debug("vaddr 0x%lx, length 0x%lx, flags 0x%lx\n", vaddr, length, flags);
    traverse_ptes(vaddr, length, stack_closure(update_pte_flags, flags));
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
    page_debug("level %d, old curr 0x%lx, phys 0x%lx, new curr 0x%lx, entry 0x%lx, *entry 0x%lx, flags 0x%lx\n",
               level, curr, phys, new_curr, entry, *entry, flags);
#endif

    /* only look at ptes at this point */
    if (!pt_entry_is_present(oldentry) || !pt_entry_is_pte(level, oldentry))
        return true;

    /* transpose mapped page */
    map_page(pagebase, new_curr, phys, pt_entry_is_fat(level, oldentry), flags, 0);

    /* reset old entry */
    *entry = 0;

    /* invalidate old mapping (map_page takes care of new)  */
    page_invalidate(curr, ignore);

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
    traverse_ptes(vaddr_old, length, stack_closure(remap_entry, vaddr_new, vaddr_old));
}

/* called with lock held */
closure_function(0, 3, boolean, zero_page,
                 int, level, u64, addr, u64 *, entry)
{
    u64 e = *entry;
    if (pt_entry_is_present(e) && pt_entry_is_pte(level, e)) {
        u64 size = pt_entry_is_fat(level, e) ? PAGESIZE_2M : PAGESIZE;
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
        *entry = 0;
        page_invalidate(vaddr, ignore);
        if (rh) {
            apply(rh, irangel(page_from_pte(old_entry),
                              (pt_entry_is_fat(level, old_entry) ?
                               PAGESIZE_2M : PAGESIZE)));
        }
    }
    return true;
}

/* Be warned: the page table lock is held when rh is called; don't try
   to modify the page table while traversing it */
void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh)
{
    assert(!((virtual & PAGEMASK) || (length & PAGEMASK)));
    traverse_ptes(virtual, length, stack_closure(unmap_page, rh));
}

// error processing
static void map_range(u64 virtual, physical p, u64 length, u64 flags)
{
    u64 len = pad(length, PAGESIZE);
    u64 vo = virtual;
    u64 po = p;

    pagetable_lock();
    u64 pb = pagebase;

    /* may be extreme, but can't be careful enough */
    memory_barrier();

    if ((virtual & PAGEMASK) || (p & PAGEMASK) || (length & PAGEMASK)) {
	if (flags == 0)
	    console("un");
	console("map() called with unaligned paramters!\n v: ");
	print_u64(virtual);
	console(", p: ");
	print_u64(p);
	console(", length: ");
	print_u64(length);
	halt("\n");
    }

#ifdef PAGE_DEBUG
    console("map_range v: ");
    print_u64(virtual);
    console(", p: ");
    print_u64(p);
    console(", length: ");
    print_u64(length);
    console(", flags: ");
    print_u64(flags);
    console("\n");
#endif

    boolean invalidate = false;
    for (int i = 0; i < len;) {
	boolean fat = ((flags & PAGE_NO_FAT) == 0) && !(vo & MASK(PT3)) &&
            !(po & MASK(PT3)) && ((len - i) >= (1ull<<PT3));
	if (!map_page(pb, vo, po, fat, flags & ~PAGE_NO_FAT, &invalidate)) {
            /* may fail if flags == 0 and no mapping, but that's not a problem */
            if (flags)
		halt("map: ran out of page table memory\n");
	}
        int off = 1ull << (fat ? PT3 : PT4);
        vo += off;
        po += off;
        i += off;
    }
#ifdef PAGE_DEBUG
    if (invalidate && p)        /* don't care about invalidate on unmap */
        console("   - part of map caused invalidate\n");
#endif

    memory_barrier();
    pagetable_unlock();
}

void map(u64 virtual, physical p, u64 length, u64 flags)
{
    map_range(virtual, p, length, flags | PAGE_PRESENT);
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

void *bootstrap_page_tables(heap initial)
{
    /* page table setup */
    pageheap = initial;
    void *pgdir = allocate_zero(initial, PAGESIZE);
    pagebase = u64_from_pointer(pgdir);
    pointer_from_pteaddr = boot_pointer_from_pteaddr;
    pteaddr_from_pointer = boot_pteaddr_from_pointer;
#ifdef STAGE3
    spin_lock_init(&pt_lock);
#endif
    return pgdir;
}

#ifdef STAGE3
static id_heap phys_internal;

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

/* these methods would hook into free page list / epoch stuff... */
static u64 wrap_alloc(heap h, bytes b)
{
    pagetable_lock();
    u64 r = allocate_u64((heap)phys_internal, b);
    pagetable_unlock();
    return r;
}

static void wrap_dealloc(heap h, u64 a, bytes b)
{
    pagetable_lock();
    deallocate_u64((heap)phys_internal, a, b);
    pagetable_unlock();
}

static boolean wrap_add_range(id_heap i, u64 base, u64 length)
{
    pagetable_lock();
    boolean r = id_heap_add_range(phys_internal, base, length);
    pagetable_unlock();
    return r;
}

static boolean wrap_set_area(id_heap i, u64 base, u64 length, boolean validate, boolean allocate)
{
    pagetable_lock();
    boolean r = id_heap_set_area(phys_internal, base, length, validate, allocate);
    pagetable_unlock();
    return r;
}

static void wrap_set_randomize(id_heap i, boolean randomize)
{
    pagetable_lock();
    id_heap_set_randomize(phys_internal, randomize);
    pagetable_unlock();
}

static u64 wrap_alloc_subrange(id_heap i, bytes count, u64 start, u64 end)
{
    pagetable_lock();
    u64 r = id_heap_alloc_subrange(phys_internal, count, start, end);
    pagetable_unlock();
    return r;
}

/* don't need lock for these */
static u64 wrap_total(heap h)
{
    return phys_internal->total;
}

static u64 wrap_allocated(heap h)
{
    return phys_internal->allocated;
}

static u64 pt_2m_next;

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

    for (u64 i = v; i < v + len; i += PAGESIZE_2M) {
        u64 p = allocate_u64((heap)phys_internal, PAGESIZE_2M);
        if (p == INVALID_PHYSICAL)
            halt("%s: failed to allocate 2M physical page\n", __func__);
        /* we depend the pmd already being installed to avoid an alloc here */
        map_page(pagebase, i, p, true, PAGE_WRITABLE | PAGE_PRESENT, 0);
        table_set(pt_p2v, (void *)p, (void *)i);
    }
    return v;
}

void map_setup_2mbpages(u64 v, physical p, int pages, u64 flags,
                      u64 *pdpt, u64 *pdt)
{
    assert(!(v & PAGEMASK_2M));
    assert(!(p & PAGEMASK_2M));
    u64 *pml4;
    mov_from_cr("cr3", pml4);
    flags |= PAGE_PRESENT;
    pml4[(v >> PT1) & MASK(9)] = u64_from_pointer(pdpt) | flags;
    v &= MASK(PT1);
    pdpt[v >> PT2] = u64_from_pointer(pdt) | flags;
    v &= MASK(PT2);
    assert(v + pages <= 512);
    for (int i = 0; i < pages; i++)
        pdt[v + i] = (p + (i << PAGELOG_2M)) | flags | PAGE_2M_SIZE;
    memory_barrier();
}

/* this happens even before moving to the new stack, so ... be cool */
id_heap init_page_tables(heap h, id_heap physical, range initial_phys)
{
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_NXE);
    mov_from_cr("cr3", pagebase);
    pointer_from_pteaddr = kern_pointer_from_pteaddr;
    pteaddr_from_pointer = kern_pteaddr_from_pointer;
    spin_lock_init(&pt_lock);
    phys_internal = physical;
    id_heap i = allocate(h, sizeof(struct id_heap));
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    i->h.alloc = wrap_alloc;
    i->h.dealloc = wrap_dealloc;
    i->h.destroy = 0;
    i->h.allocated = wrap_allocated;
    i->h.total = wrap_total;
    i->h.pagesize = physical->h.pagesize;
    i->add_range = wrap_add_range;
    i->set_area = wrap_set_area;
    i->set_randomize = wrap_set_randomize;
    i->alloc_subrange = wrap_alloc_subrange;

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
    pageheap = (heap)create_id_heap_backed(h, /* XXX */ h, pt_2m, PAGESIZE);
    assert(pageheap != INVALID_ADDRESS);
    return i;
}
#else
/* stage2 */
void init_page_tables(heap initial)
{
    void *vmbase = bootstrap_page_tables(initial);
    mov_to_cr("cr3", vmbase);
}
#endif
