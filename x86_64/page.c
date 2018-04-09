#include <basic_runtime.h>
#include <x86_64.h>

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

// xxx - stage2 has his own verison
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

static void write_pte(page target, physical to, boolean fat)
{
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
    if ((x = force_entry(x, pindex(virtual, PT1), h)) != INVALID_ADDRESS) {
        if ((x = force_entry(x, pindex(virtual, PT2), h)) != INVALID_ADDRESS) {
            if ((x = force_entry(x, pindex(virtual, PT3), h)) != INVALID_ADDRESS) {
                write_pte(x + pindex(virtual, PT4), p, false);
                return; 
            }
        }
    }
    halt("ran out of page map memory");
}

static void map_page_2m(page base, u64 virtual, physical p, heap h)
{
    page x = base;
    if ((x = force_entry(x, pindex(virtual, PT1), h)) != INVALID_ADDRESS) {
        if ((x = force_entry(x, pindex(virtual, PT2), h)) != INVALID_ADDRESS) {
            u64 off = pindex(virtual, PT3);
            write_pte(x+off, p, true);
            return; 
        }
    }
    halt("ran out of page map memory");
}

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

// error processing
void map(u64 virtual, physical p, int length, heap h)
{
    int len = pad(length, PAGESIZE);
    u64 vo = virtual;
    u64 po = p;
    page pb = pagebase();

    console("map: ");
    print_u64(virtual);
    console(" ");
    print_u64(p);
    console(" ");
    print_u64(length);              
    console("\n");

    for (int i = 0; i < len;) {
        int off = 1<<12;
        if (!(vo & MASK(PT3)) && !(po & MASK(PT3)) && ((len - i) >= (1<<PT3))) {
            map_page_2m(pb, vo, po, h);
            off = 1<<PT3;
        } else  {
            map_page_4k(pb, vo, po, h);
        }
        vo += off;
        if (po != INVALID_PHYSICAL)
            po += off;
        i += off;
    }
}
