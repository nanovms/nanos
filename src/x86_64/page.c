#include <runtime.h>
#include <x86_64.h>
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


#define PAGEMASK MASK(PAGELOG)
typedef u64 *page;

#define PT1 39
#define PT2 30
#define PT3 21
#define PT4 12

static const int level_shift[5] = { -1, PT1, PT2, PT3, PT4 };

static inline u64 phys_from_pte(u64 pte)
{
    /* page directory pointer base address [51:12] */
    return pte & (MASK(52) & ~PAGEMASK);
}

static inline page page_from_pte(u64 pte)
{
    return (page)pointer_from_u64(phys_from_pte(pte));
}

static inline u64 flags_from_pte(u64 pte)
{
    return pte & PAGE_FLAGS_MASK;
}

static inline u64 pindex(u64 x, u64 offset)
{
    return ((x >> offset) & MASK(9));
}

static inline boolean entry_is_present(u64 entry)
{
    return (entry & PAGE_PRESENT) != 0;
}

static inline boolean entry_is_fat(int level, u64 entry)
{
    return level == 3 && (entry & PAGE_2M_SIZE) != 0;
}

static inline boolean entry_is_pte(int level, u64 entry)
{
    return level == 4 || entry_is_fat(level, entry);
}

static inline page pagebase()
{
    page base;
    // since cr3 never changes it seems a shame to pay for mov_from_cr
    mov_from_cr("cr3", base);
    return base;
}

#ifdef PAGE_USE_FLUSH
static inline void flush_tlb()
{
    page base;
    mov_from_cr("cr3", base);
    mov_to_cr("cr3", base);
}
#endif

// there is a def64 and def32 now
#ifndef physical_from_virtual
static inline page pt_lookup(page table, u64 t, unsigned int x)
{
    u64 a = table[pindex(t, x)];
    if (a & 1)
        return page_from_pte(a);
    return 0;
}

physical physical_from_virtual(void *x)
{
    u64 xt = u64_from_pointer(x);

    u64 *l3 = pt_lookup(pagebase(), xt, PT1);
    if (!l3) return INVALID_PHYSICAL;
    u64 *l2 = pt_lookup(l3, xt, PT2);
    if (!l2) return INVALID_PHYSICAL;    
    u64 *l1 = pt_lookup(l2, xt, PT3); // 2m pages
    if (!l1) return INVALID_PHYSICAL;        
    if (l2[pindex(xt, PT3)] & PAGE_2M_SIZE) return ((u64)l1 | (xt & MASK(PT3)));
    u64 *l0 = pt_lookup(l1, xt, PT4);
    if (!l0) return INVALID_PHYSICAL;
    return (u64)l0 | (xt & MASK(PT4));
}
#endif

#ifndef BOOT
static u64 dump_lookup(u64 base, u64 t, unsigned int x)
{
    return page_from_pte(base)[pindex(t, x)];
}

void dump_ptes(void *x)
{
    u64 xt = u64_from_pointer(x);

    rprintf("dump_ptes 0x%lx\n", x);
    u64 l1 = dump_lookup((u64)pagebase(), xt, PT1);
    rprintf("  l1: 0x%lx\n", l1);
    if ((l1 & 1) == 0)
        return;
    u64 l2 = dump_lookup(l1, xt, PT2);
    rprintf("  l2: 0x%lx\n", l2);
    if ((l2 & 1) == 0)
        return;
    u64 l3 = dump_lookup(l2, xt, PT3);
    rprintf("  l3: 0x%lx\n", l3);
    if ((l3 & 1) == 0 || (l3 & PAGE_2M_SIZE))
        return;
    u64 l4 = dump_lookup(l3, xt, PT4);
    rprintf("  l4: 0x%lx\n", l4);
}
#endif

/* virtual from physical of n required if we move off the identity map for pages */
static void write_pte(page target, physical to, u64 flags, boolean * invalidate)
{
    u64 new = to | flags;
#ifdef PTE_DEBUG
    console(", write_pte: ");
    print_u64(u64_from_pointer(target));
    console(" = ");
    print_u64(new);
#endif
    assert((new & PAGE_NO_FAT) == 0);
    if (*target == new) {
#ifdef PTE_DEBUG
	console(", pte same; no op");
#endif
	return;
    }
    /* invalidate when changing any pte that was marked as present */
    if (*target & PAGE_PRESENT) {
#ifdef PTE_DEBUG
        console("   invalidate for target ");
        print_u64(u64_from_pointer(target));
        console(", old ");
        print_u64(*target);
        console(", new ");
        print_u64(new);
        console("\n");
#endif
	*invalidate = true;
    }
    *target = new;
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
static boolean force_entry(heap h, page b, u64 v, physical p, int level,
			   boolean fat, u64 flags, boolean * invalidate)
{
    u32 offset = pindex(v, level_shift[level]);
    page pte = b + offset;

    assert((flags & PAGE_NO_FAT) == 0);

    if (level == (fat ? 3 : 4)) {
#ifdef PTE_DEBUG
	console("! ");
	print_level(level);
	console(", offset ");
	print_u64(offset);
#endif
	if (fat)
	    flags |= PAGE_2M_SIZE;
	write_pte(pte, p, flags, invalidate);
	return true;
    } else {
	if (*pte & PAGE_PRESENT) {
            if (entry_is_fat(level, *pte)) {
                console("\nforce_entry fail: attempting to map a 4K page over an "
                        "existing 2M mapping\n");
                return false;
            }
            /* XXX when unmapping, add a check here to see if the
               directory page is completely unused, and explicitly
               remove and free them when possible. This will avoid the
               occasional invalidate caused by lingering mid
               directories without entries */

	    return force_entry(h, page_from_pte(b[offset]), v, p, level + 1, fat, flags, invalidate);
	} else {
	    if (flags == 0)	/* only lookup for unmap */
		return false;
	    page n = allocate_zero(h, PAGESIZE);
	    if (n == INVALID_ADDRESS)
		return false;
	    if (!force_entry(h, n, v, p, level + 1, fat, flags, invalidate))
		return false;
#ifdef PTE_DEBUG
	    console("- ");
	    print_level(level);
	    console(", offset ");
	    print_u64(offset);
#endif
            /* user and writable are AND of flags from all levels */
	    write_pte(pte, u64_from_pointer(n), PAGE_WRITABLE | PAGE_USER | PAGE_PRESENT, invalidate);
	    return true;
	}
    }
}

static inline void page_invalidate(u64 v)
{
#ifdef PAGE_USE_FLUSH
    /* It isn't efficient to do this for each page, but this option is
       only used for stage2 and debugging... */
    flush_tlb();
#else
    asm volatile("invlpg (%0)" :: "r" (v) : "memory");
#endif
}

static inline boolean map_page(page base, u64 v, physical p, heap h,
                               boolean fat, u64 flags, boolean * invalidate)
{
    boolean invalidate_entry = false;
#ifdef PAGE_UPDATE_DEBUG
    rprintf("force entry base 0x%p, v 0x%lx, p 0x%lx, fat %d, flags 0x%lx\n",
            base, v, p, fat, flags);
#endif
    if (!force_entry(h, base, v, p, 1, fat, flags, &invalidate_entry))
	return false;
    if (invalidate_entry) {
        page_invalidate(v);
        if (invalidate)
            *invalidate = true;
    }
    return true;
}

static inline u64 pt_level_end(u64 p, int level)
{
    return (p & ~MASK(level)) + U64_FROM_BIT(level);
}

#define for_level(base, start, end, level, levelend)                    \
    for (u64 addr ## level = start, next ## level, end ## level, * pte ## level; \
         next ## level = pt_level_end(addr ## level, PT ## level),      \
             end ## level = MIN(next ## level, end),                    \
             pte ## level = ((u64*)base) + pindex(addr ## level, PT ## level), \
             addr ## level < levelend;                                  \
         addr ## level = next ## level)

typedef closure_type(entry_handler, boolean /* success */, int /* level */, u64 /* vaddr */, u64 * /* entry */);

static boolean traverse_entries(u64 vaddr, u64 length, entry_handler ph)
{
    u64 end = vaddr + length;

    for_level(pagebase(), vaddr, end, 1, end) {
        if (!apply(ph, 1, addr1, pte1))
            return false;
        if (!entry_is_present(*pte1))
            continue;
        for_level(page_from_pte(*pte1), addr1, end, 2, end1) {
            if (!apply(ph, 2, addr2, pte2))
                return false;
            if (!entry_is_present(*pte2))
                continue;
            for_level(page_from_pte(*pte2), addr2, end, 3, end2) {
                if (!apply(ph, 3, addr3, pte3))
                    return false;
                if (!entry_is_present(*pte3))
                    continue;
                if ((*pte3 & PAGE_2M_SIZE) == 0) {
                    for_level(page_from_pte(*pte3), addr3, end, 4, end3) {
                        if (!apply(ph, 4, addr4, pte4))
                            return false;
                        (void)end4;
                    }
                }
            }
        }
    }
    return true;
}

static CLOSURE_0_3(validate_entry, boolean, int, u64, u64 *);
static boolean validate_entry(int level, u64 vaddr, u64 * entry)
{
    return entry_is_present(*entry);
}

/* validate that all pages in vaddr range [base, base + length) are present */
boolean validate_virtual(void * base, u64 length)
{
    page_debug("base %p, length 0x%lx\n", base, length);
    return traverse_entries(u64_from_pointer(base), length, stack_closure(validate_entry));
}

static CLOSURE_1_3(update_pte_flags, boolean, u64, int, u64, u64 *);
static boolean update_pte_flags(u64 flags, int level, u64 addr, u64 * entry)
{
    /* we only care about present ptes */
    u64 old = *entry;
    if (!entry_is_present(old) || !entry_is_pte(level, old))
        return true;

    *entry = (old & ~PAGE_PROT_FLAGS) | flags;
#ifdef PAGE_UPDATE_DEBUG
    page_debug("update 0x%lx: pte @ 0x%lx, 0x%lx -> 0x%lx\n", addr, entry, old, *entry);
#endif
    page_invalidate(addr);
    return true;
}

/* Update access protection flags for any pages mapped within a given area */
void update_map_flags(u64 vaddr, u64 length, u64 flags)
{
    flags &= ~PAGE_NO_FAT;
    page_debug("vaddr 0x%lx, length 0x%lx, flags 0x%lx\n", vaddr, length, flags);

    traverse_entries(vaddr, length, stack_closure(update_pte_flags, flags));
}

static CLOSURE_3_3(remap_entry, boolean, u64, u64, heap, int, u64, u64 *);
static boolean remap_entry(u64 new, u64 old, heap h, int level, u64 curr, u64 * entry)
{
    u64 offset = curr - old;
    u64 oldentry = *entry;
    u64 new_curr = new + offset;
    u64 phys = phys_from_pte(oldentry);
    u64 flags = flags_from_pte(oldentry);
#ifdef PAGE_UPDATE_DEBUG
    page_debug("level %d, old curr 0x%lx, phys 0x%lx, new curr 0x%lx, entry 0x%lx, *entry 0x%lx, flags 0x%lx\n",
               level, curr, phys, new_curr, entry, *entry, flags);
#endif

    /* transpose any unmapped gaps to target */
    if (!entry_is_present(oldentry)) {
        u64 len = U64_FROM_BIT(level_shift[level]);
#ifdef PAGE_UPDATE_DEBUG
        page_debug("unmapping [0x%lx, 0x%lx)\n", new_curr, new_curr + len);
#endif
        unmap_pages(new_curr, len);
        return true;
    }

    /* only look at ptes at this point */
    if (!entry_is_pte(level, oldentry))
        return true;

    /* transpose mapped page */
    map_page(pagebase(), new_curr, phys, h, entry_is_fat(level, oldentry), flags, 0);

    /* reset old entry */
    *entry = 0;

    /* invalidate old mapping (map_page takes care of new)  */
    page_invalidate(curr);

    return true;
}

/* We're just going to do forward traversal, for we don't yet need to
   support overlapping moves. Should the latter become necessary
   (e.g. to support MREMAP_FIXED in mremap(2) without depending on
   MREMAP_MAYMOVE), write a "traverse_entries_reverse" to walk pages
   from high address to low (like memcpy).
*/
void remap_pages(u64 vaddr_new, u64 vaddr_old, u64 length, heap h)
{
    page_debug("vaddr_new 0x%lx, vaddr_old 0x%lx, length 0x%lx\n", vaddr_new, vaddr_old, length);
    if (vaddr_new == vaddr_old)
        return;
    assert(range_empty(range_intersection(irange(vaddr_new, vaddr_new + length),
                                          irange(vaddr_old, vaddr_old + length))));
    traverse_entries(vaddr_old, length, stack_closure(remap_entry, vaddr_new, vaddr_old, h));
}

static CLOSURE_0_3(zero_page, boolean, int, u64, u64 *);
static boolean zero_page(int level, u64 addr, u64 * entry)
{
    u64 e = *entry;
    if (entry_is_present(e) && entry_is_pte(level, e)) {
        u64 size = entry_is_fat(level, e) ? PAGESIZE_2M : PAGESIZE;
#ifdef PAGE_UPDATE_DEBUG
        page_debug("addr 0x%lx, size 0x%lx\n", addr, size);
#endif
        zero(pointer_from_u64(addr), size);
    }
    return true;
}

void zero_mapped_pages(u64 vaddr, u64 length)
{
    traverse_entries(vaddr, length, stack_closure(zero_page));
}

static CLOSURE_2_3(is_page_mapped, boolean, u64, u8 *, int, u64, u64 *);
boolean is_page_mapped(u64 baseaddr, u8 * vec, int level, u64 addr, u64 * entry)
{
    u64 e = *entry;
    int pgoff, i;

    if (entry_is_present(e)) {
        pgoff = (addr - baseaddr) >> PAGELOG;

        if (entry_is_fat(level, e)) {
            /* whole level is mapped */
            for (i = 0; i < 512; i++)
                vec[pgoff + i] = 1;
        } else if (entry_is_pte(level, e)) {
            vec[pgoff] = 1;
        }
    }

    return true;
}

void mincore_pages(u64 vaddr, u64 length, u8 *vec)
{
    traverse_entries(vaddr, length, stack_closure(is_page_mapped, vaddr, vec));
}

static CLOSURE_1_3(unmap_page, boolean, range_handler, int, u64, u64 *);
boolean unmap_page(range_handler rh, int level, u64 vaddr, u64 * entry)
{
    u64 old_entry = *entry;
    if (entry_is_present(old_entry) && entry_is_pte(level, old_entry)) {
#ifdef PAGE_UPDATE_DEBUG
        page_debug("rh %p, level %d, vaddr 0x%lx, entry %p, *entry 0x%lx\n",
                   rh, level, vaddr, entry, *entry);
#endif
        *entry = 0;
        page_invalidate(vaddr);
        if (rh) {
            u64 phys = phys_from_pte(old_entry);
            range p = irange(phys, phys + (entry_is_fat(level, old_entry) ? PAGESIZE_2M : PAGESIZE));
            apply(rh, p);
        }
    }
    return true;
}

void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh)
{
    assert(!((virtual & PAGEMASK) || (length & PAGEMASK)));
    traverse_entries(virtual, length, stack_closure(unmap_page, rh));
}

// error processing
static void map_range(u64 virtual, physical p, u64 length, u64 flags, heap h)
{
    u64 len = pad(length, PAGESIZE);
    u64 vo = virtual;
    u64 po = p;
    page pb = pagebase();

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
	if (!map_page(pb, vo, po, h, fat, flags & ~PAGE_NO_FAT, &invalidate)) {
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
}

void map(u64 virtual, physical p, u64 length, u64 flags, heap h)
{
    map_range(virtual, p, length, flags | PAGE_PRESENT, h);
}

void unmap(u64 virtual, u64 length, heap h)
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
