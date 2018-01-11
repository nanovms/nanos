
#define PAGELOG 12
#define PAGESIZE (1<<PAGELOG)
#define PAGEMASK ((1ull<<PAGELOG)-1)
#define PAGE_2M_SIZE (1<<7)
#define PAGE_PRESENT 1
#define PAGE_WRITABLE 2
typedef u64 *page;

static inline page pt_lookup(page table, u64 t, unsigned int x)
{
    u64 a = table[(t>>x)&MASK(9)] & ~MASK(12);
    return (page)pointer_from_u64(a);
}

// allow protect mode override
#ifndef virtual_to_physical
static inline physical virtual_to_physical(void *x)
{
    u64 xt = u64_from_pointer(x);

    u64 *l3 = pt_lookup(pagebase, xt, 39);
    u64 *l2 = pt_lookup(l3, xt, 30);
    u64 *l1 = pt_lookup(l2, xt, 21); // 2m pages
    if (l2[xt>>21] & PAGE_2M_SIZE)
        return ((u64)l1);
    u64 *l0 = pt_lookup(l1, xt, 12);
    return (u64)l0 | (xt & MASK(12));
}
#endif

static inline void write_pte(page target, physical to, boolean fat)
{
    // present and writable 
    *target = to | PAGE_WRITABLE | PAGE_PRESENT | (fat?PAGE_2M_SIZE:0);
}

static inline page force_entry(page b, u32 offset, page (*alloc)())
{
    if (b[offset] &1) {
        return pointer_from_u64(b[offset] & ~PAGEMASK);
    } else {
        page n = alloc();
        write_pte(b + offset, virtual_to_physical(n), false);
        return n;
    }
}

static void map_page_4k(page base, u64 virtual, physical p, page (*alloc)())
{
    // this code is rn in 32 bit and 64 bit right now
    page x = base;
    u64 k = (u32)virtual; // ?
    x = force_entry(x, (k >> 39) & ((1<<9)-1), alloc);
    x = force_entry(x, (k >> 30) & ((1<<9)-1), alloc);
    x = force_entry(x, (k >> 21) & ((1<<9)-1), alloc);
    u64 off = (k >> 12) & ((1<<9)-1);
    write_pte(x + off * 8, p, false);
}

static void map_page_2m(void *base, u64 virtual, physical p, page (*alloc)())
{
    // this code is rn in 32 bit and 64 bit right now
    void *x = base;
    u64 k = (u32)virtual;
    x = force_entry(x, (k >> 39) & ((1<<9)-1), alloc);
    x = force_entry(x, (k >> 30) & ((1<<9)-1), alloc);
    u64 off = (k >> 21) & ((1<<9)-1);    
    write_pte(x+off, p, true);
}

static void map(void *table, u64 virtual, physical p, int length, page (*alloc)())
{
    int len = pad(length, PAGESIZE);
    u64 vo = virtual;
    u64 po = p;
    for (int i = 0; i < len;) {
        int off = 1<<12;
        if (!(vo & MASK(22)) && !(po & MASK(22)) && (len > (1<<22))) {
            map_page_2m(table, vo, po, alloc);
            off = 1<<22;
        } else map_page_4k(table, vo, po, alloc);
        vo += off;
        po += off;
        i += off;
    }
}
