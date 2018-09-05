#include <runtime.h>

//#define PAGE_DEBUG

#define PAGEMASK MASK(PAGELOG)
#define PAGE_2M_SIZE (1<<7)
#define PAGE_PRESENT (1<<0)
#define PAGE_WRITABLE (1<<1)
#define PAGE_USER (1<<2)
typedef u64 *page;

#define PT1 39
#define PT2 30
#define PT3 21
#define PT4 12

static const int level_shift[5] = { -1, PT1, PT2, PT3, PT4 };

static inline u64 pindex(u64 x, u64 offset)
{
    return ((x >> offset) & MASK(9));
}


static inline page pt_lookup(page table, u64 t, unsigned int x)
{
    u64 a = table[pindex(t, x)];
    if (a & 1) 
        return (page)pointer_from_u64(a & ~PAGEMASK);
    return 0;
}

static inline page pagebase()
{
    page base;
    // since cr3 never changes it seems a shame to pay for mov_from_cr
    mov_from_cr("cr3", base);
    return base;
}

// there is a def64 and def32 now
#ifndef physical_from_virtual
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
    return (u64)l0 | (xt & MASK(PT4));
}
#endif

/* virtual from physical of n required if we move off the identity map for pages */
static void write_pte(page target, physical to, u64 flags)
{
#ifdef PAGE_DEBUG
    console(", write_pte: ");
    print_u64(u64_from_pointer(target));
    console(" = ");
    print_u64(to | flags);
    console("\n");
#endif
    *target = to | flags;
}

/* p == 0 && flags == 0 for unmap */
static boolean force_entry(heap h, page b, u64 v, physical p, int level,
			   boolean fat, u64 flags, boolean * invalidate)
{
    u32 offset = pindex(v, level_shift[level]);
    page pte = b + offset;
    boolean present = b[offset] & PAGE_PRESENT;

    if (level == (fat ? 3 : 4)) {
	if (present)
	    *invalidate = true;
#ifdef PAGE_DEBUG
	console(" ! level ");
	print_u64(level);
	console(", offset ");
	print_u64(offset);
#endif
	write_pte(pte, p, (fat && flags) ? (flags | PAGE_2M_SIZE) : flags);
	return true;
    } else {
	if (present) {
	    return force_entry(h, pointer_from_u64(b[offset] & ~PAGEMASK),
			       v, p, level + 1, fat, flags, invalidate);
	} else {
	    if (flags == 0)	/* only lookup for unmap */
		return false;
	    page n = allocate_zero(h, PAGESIZE);
	    if (n == INVALID_ADDRESS)
		return false;
	    if (!force_entry(h, n, v, p, level + 1, fat, flags, invalidate))
		return false;
	    *invalidate = true;	/* XXX necessary when adding table entry? */
#ifdef PAGE_DEBUG
	    console(" - level ");
	    print_u64(level);
	    console(", offset ");
	    print_u64(offset);
#endif
	    write_pte(pte, u64_from_pointer(n), flags);
	    return true;
	}
    }
}

static boolean map_page(page base, u64 v, physical p, heap h, boolean fat, boolean flags)
{
    boolean invalidate = false;
    if (!force_entry(h, base, v, p, 1, fat, flags, &invalidate))
	return false;
    if (invalidate) {
	asm volatile("invlpg %0"::"m"(v):);
    }
    return true;
}

#ifndef BITS32
boolean validate_virtual(void *base, u64 length)
{
    u64 e = u64_from_pointer(base) + length;    
    u64 p  = u64_from_pointer(base);
    page pb = pagebase(), l1, l2, l3;

    while (p < e) {
        if (!(l1 = pt_lookup(pb, p, PT1))) return false;
        u64 e1 = MIN(p + (1ull<<PT1), e);
        while(p < e1) {
            if (!(l2 =  pt_lookup(l1, p, PT2))) return false;
            u64 e2 = MIN(p + (1ull<<PT2), e);
            while(p < e2) {
                if (!(l3 =  pt_lookup(l2, p, PT3))) return false;
                u64 e3 = MIN(p + (1ull<<PT3), e);
                while(p < e3) {
                    if (l3[pindex(p,PT3)] & PAGE_2M_SIZE) {
                        p += 1<<PT3;
                    } else {
                        u64 e3 = MIN(p + (1ull<<PT3), e);
                        while (p < e3) {
                            if (!pt_lookup(l3, p, PT4)) return false;
                            p += 1<<PAGELOG;
                        }
                    }
                }
            }
        }
    }
    return true;
}
#endif

// error processing
static void map_range(u64 virtual, physical p, int length, u64 flags, heap h)
{
    int len = pad(length, PAGESIZE);
    u64 vo = virtual;
    u64 po = p;
    page pb = pagebase();

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

    for (int i = 0; i < len;) {
	boolean fat = !(vo & MASK(PT3)) && !(po & MASK(PT3)) && ((len - i) >= (1<<PT3));
	if (!map_page(pb, vo, po, h, fat, flags)) {
	    if (flags == 0)
		console("unmap: area missing page mappings\n");
	    else
		halt("map: ran out of page table memory");
	}
        int off = 1 << (fat ? PT3 : PT4);
        vo += off;
        if (po != INVALID_PHYSICAL)
            po += off;
        i += off;
    }
}

void map(u64 virtual, physical p, int length, heap h)
{
    // really set user?
    u64 flags = PAGE_WRITABLE | PAGE_PRESENT | PAGE_USER;
    map_range(virtual, p, length, flags, h);
}

void unmap(u64 virtual, int length, heap h)
{
    map_range(virtual, 0, length, 0, h);
}
