#include <runtime.h>

#define PAGEMASK MASK(PAGELOG)
#define PAGE_2M_SIZE (1<<7)
#define PAGE_PRESENT (1<<0)
#define PAGE_WRITABLE (1<<1)
#define PAGE_USER (1<<2)
typedef u64 *page;

static page pt_lookup(page table, u64 t, unsigned int x)
{
    u64 a = table[(t>>x)&MASK(9)] & ~PAGEMASK;
    return (page)pointer_from_u64(a);
}

// allow protect mode override
#ifndef physical_from_virtual
physical physical_from_virtual(void *x)
{
    page base;
    // this has to be in an identity region, we could cache this
    mov_from_cr("cr3", base);
    
    u64 xt = u64_from_pointer(x);

    u64 *l3 = pt_lookup(base, xt, 39);
    u64 *l2 = pt_lookup(l3, xt, 30);
    u64 *l1 = pt_lookup(l2, xt, 21); // 2m pages
    if (l2[xt>>21] & PAGE_2M_SIZE)
        return ((u64)l1);
    u64 *l0 = pt_lookup(l1, xt, 12);
    return (u64)l0 | (xt & MASK(12));
}
#endif

static void write_pte(page target, physical to, boolean fat)
{
    // really set user?
    if (to == PHYSICAL_INVALID)
        *target = 0;
    else 
        *target = to | PAGE_WRITABLE | PAGE_PRESENT | PAGE_USER | (fat?PAGE_2M_SIZE:0);
}

static page force_entry(page b, u32 offset, heap h)
{
    if (b[offset] &1) {
        return pointer_from_u64(b[offset] & ~PAGEMASK);
    } else {
        page n = allocate_zero(h, PAGESIZE);
        // virtual from physical of n required if we
        // move off the identity map for pages
        write_pte(b + offset, u64_from_pointer(n), false);
        return n;
    }
}

static void map_page_4k(page base, u64 virtual, physical p, heap h)
{
    page x = base;
    x = force_entry(x, (virtual >> 39) & MASK(9), h);
    x = force_entry(x, (virtual >> 30) & MASK(9), h);
    x = force_entry(x, (virtual >> 21) & MASK(9), h);
    u64 off = (virtual >> 12) & MASK(9);
    write_pte(x + off, p, false);
}

static void map_page_2m(page base, u64 virtual, physical p, heap h)
{
    // this code is rn in 32 bit and 64 bit right now
    void *x = base;
    u64 k = (u32)virtual;
    x = force_entry(x, (k >> 39) & MASK(9), h);
    x = force_entry(x, (k >> 30) & MASK(9), h);
    u64 off = (k >> 21) & MASK(9);
    write_pte(x+off, p, true);
}

void map(u64 virtual, physical p, int length, heap h)
{
    page base;
    // this has to be in an identity region, we could cache this
    mov_from_cr("cr3", base);

    int len = pad(length, PAGESIZE);
    u64 vo = virtual;
    u64 po = p;

    for (int i = 0; i < len;) {
        int off = 1<<12;
        
        if (!(vo & MASK(21)) && !(po & MASK(21)) && ((len - i) >= (1<<21))) {
            map_page_2m(base, vo, po, h);
            off = 1<<21;
        } else map_page_4k(base, vo, po, h);
        vo += off;
        if (po != PHYSICAL_INVALID)
            po += off;
        i += off;
    }
}
