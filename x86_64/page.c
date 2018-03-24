#include <runtime.h>
#include <x86_64.h>

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

// allow stage2 to override - not so important since this is still identity
// should return PHYSICAL_INVALID
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
    if (l2[xt>>21] & PAGE_2M_SIZE) return ((u64)l1 | (xt & MASK(21)));
    u64 *l0 = pt_lookup(l1, xt, 12);
    return (u64)l0 | (xt & MASK(12));
}
#endif

static void write_pte(page target, physical to, boolean fat)
{
    //    console("pte: ");
    //    print_u64(target);
    //    console(" ");
    //    print_u64(to | PAGE_WRITABLE | PAGE_PRESENT | PAGE_USER | (fat?PAGE_2M_SIZE:0));
    //    console("\n");    
    
    
    // really set user?
    if (to == INVALID_PHYSICAL)
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
        if (n == pointer_from_u64(INVALID_PHYSICAL))
            console("ran out of page memory\n");
        // virtual from physical of n required if we
        // move off the identity map for pages
        write_pte(b + offset, u64_from_pointer(n), false);
        return n;
    }
}

static void map_page_4k(page base, u64 virtual, physical p, heap h)
{
    page x = base;
    if ((x = force_entry(x, (virtual >> 39) & MASK(9), h)) != INVALID_ADDRESS) {
        if ((x = force_entry(x, (virtual >> 30) & MASK(9), h)) != INVALID_ADDRESS) {
            if ((x = force_entry(x, (virtual >> 21) & MASK(9), h)) != INVALID_ADDRESS) {
                u64 off = (virtual >> 12) & MASK(9);
                write_pte(x + off, p, false);
                return; 
            }
        }
    }
    halt("ran out of page map memory");
}

static void map_page_2m(page base, u64 virtual, physical p, heap h)
{
    page x = base;
    if ((x = force_entry(x, (virtual >> 39) & MASK(9), h)) != INVALID_ADDRESS) {
        if ((x = force_entry(x, (virtual >> 30) & MASK(9), h)) != INVALID_ADDRESS) {
            u64 off = (virtual >> 21) & MASK(9);
            write_pte(x+off, p, true);
            return; 
        }
    }
    halt("ran out of page map memory");
}

boolean validate_virtual(void *base, u64 length)
{
    // its not, not true
    return true;
}

// error processing
void map(u64 virtual, physical p, int length, heap h)
{
    page base;
    // this has to be in an identity region, we could cache this
    mov_from_cr("cr3", base);

    int len = pad(length, PAGESIZE);
    u64 vo = virtual;
    u64 po = p;
#if 0
    console("map: ");
    print_u64(virtual);
    console(" ");
    print_u64(p);
    console(" ");
    print_u64(length);              
    console("\n");
#endif
    for (int i = 0; i < len;) {
        int off = 1<<12;
                if (!(vo & MASK(21)) && !(po & MASK(21)) && ((len - i) >= (1<<21))) {
                    map_page_2m(base, vo, po, h);
                    off = 1<<21;
                } else
            {
            map_page_4k(base, vo, po, h);
        }
        vo += off;
        if (po != INVALID_PHYSICAL)
            po += off;
        i += off;
    }
}
