#include <runtime.h>
#include <x86_64.h>
#include <page.h>

//#define PAGE_DEBUG
//#define PTE_DEBUG
//#define PAGE_UPDATE_DEBUG

#define PAGEMASK MASK(PAGELOG)
typedef u64 *page;

#define PT1 39
#define PT2 30
#define PT3 21
#define PT4 12

static const int level_shift[5] = { -1, PT1, PT2, PT3, PT4 };

static inline page page_from_pte(u64 pte)
{
    /* page directory pointer base address [51:12] */
    return (page)pointer_from_u64(pte & (MASK(52) & ~PAGEMASK));
}

static inline u64 pindex(u64 x, u64 offset)
{
    return ((x >> offset) & MASK(9));
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
	serial_out(' ');
    serial_out('0' + level);
    for (i = 0; i < 5 - level; i++)
	serial_out(' ');
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
            if (level == 3 && (*pte & PAGE_2M_SIZE)) {
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
//    rprintf("map_page: force entry base 0x%p, v 0x%lx, p 0x%lx, fat %d, flags 0x%lx\n",
//            base, v, p, fat, flags);
    if (!force_entry(h, base, v, p, 1, fat, flags, &invalidate_entry))
	return false;
    if (invalidate_entry) {
        page_invalidate(v);
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
             end ## level = MIN(next ## level, end), addr ## level < levelend; \
         addr ## level = next ## level)                                 \
        if ((*(pte ## level = ((u64*)base) + pindex(addr ## level, PT ## level)) & PAGE_PRESENT))

boolean validate_virtual(void * base, u64 length)
{
    u64 start = u64_from_pointer(base);
    u64 end = start + length;
    for_level(pagebase(), start, end, 1, end) {
        for_level(page_from_pte(*pte1), addr1, end, 2, end1) {
            for_level(page_from_pte(*pte2), addr2, end, 3, end2) {
                if ((*pte3 & PAGE_2M_SIZE) == 0) {
                    for_level(page_from_pte(*pte3), addr3, end, 4, end3) {
                        (void)end4;
                    } else {
                        return false;
                    }
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }
    return true;
}

typedef closure_type(page_handler, void, u64, u64 *);

static void traverse_range(u64 vaddr, u64 length, page_handler ph)
{
    u64 end = vaddr + length;

    for_level(pagebase(), vaddr, end, 1, end) {
        for_level(page_from_pte(*pte1), addr1, end, 2, end1) {
            for_level(page_from_pte(*pte2), addr2, end, 3, end2) {
                if ((*pte3 & PAGE_2M_SIZE)) {
                    apply(ph, addr3, pte3);
                } else {
                    for_level(page_from_pte(*pte3), addr3, end, 4, end3) {
                        apply(ph, addr4, pte4);
                        (void)end4;
                    }
                }
            }
        }
    }
}

static CLOSURE_1_2(update_pte_flags, void, u64, u64, u64 *);
static void update_pte_flags(u64 flags, u64 addr, u64 * pte)
{
    u64 old = *pte;
    *pte = (old & ~PAGE_PROT_FLAGS) | flags;
#ifdef PAGE_UPDATE_DEBUG
    rprintf("  update 0x%lx: pte @ 0x%lx, 0x%lx -> 0x%lx\n", addr, pte, old, *pte);
#endif
    page_invalidate(addr);
}

/* Update access protection flags for any pages mapped within a given area */
void update_map_flags(u64 vaddr, u64 length, u64 flags)
{
    flags &= ~PAGE_NO_FAT;
#ifdef PAGE_DEBUG
    rprintf("update_map_flags: vaddr 0x%lx, length 0x%lx, flags 0x%lx\n", vaddr, length, flags);
#endif

    traverse_range(vaddr, length, closure(transient, update_pte_flags, flags));
}

static CLOSURE_0_2(zero_page, void, u64, u64 *);
static void zero_page(u64 addr, u64 * pte)
{
    zero(pointer_from_u64(addr), *pte & PAGE_2M_SIZE ? PAGE_2M_SIZE : PAGESIZE);
}

void zero_mapped_pages(u64 vaddr, u64 length)
{
    traverse_range(vaddr, length, closure(transient, zero_page));
}

static CLOSURE_1_2(unmap_page, void, range_handler, u64, u64 *);
void unmap_page(range_handler rh, u64 vaddr, u64 * pte)
{
    int pagesize = *pte & PAGE_2M_SIZE ? PAGE_2M_SIZE : PAGESIZE;
    u64 phys = *pte & ~PAGE_FLAGS_MASK;
    *pte = 0;
    range p = irange(phys, phys + pagesize);
    apply(rh, p);
}

void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh)
{
    assert(!((virtual & PAGEMASK) || (length & PAGEMASK)));
    traverse_range(virtual, length, closure(transient, unmap_page, rh));
}

// error processing
static void map_range(u64 virtual, physical p, int length, u64 flags, heap h)
{
    int len = pad(length, PAGESIZE);
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
        if (po != INVALID_PHYSICAL)
            po += off;
        i += off;
    }
#ifdef PAGE_DEBUG
    if (invalidate && p)        /* don't care about invalidate on unmap */
        console("   - part of map caused invalidate\n");
#endif

    memory_barrier();
}

void map(u64 virtual, physical p, int length, u64 flags, heap h)
{
    map_range(virtual, p, length, flags | PAGE_PRESENT, h);
}

void unmap(u64 virtual, int length, heap h)
{
    map_range(virtual, 0, length, 0, h);
}
