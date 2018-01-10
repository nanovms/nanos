
#define PAGELOG 12
#define PAGESIZE (1<<PAGELOG)
#define PAGEMASK ((1ull<<PAGELOG)-1)

// xxx - still in use by 32 bit stage2
#ifndef pointer
#define pointer(__a) ((u64 *)(void *)(u64)__a)
#endif

static inline void write_pte(u64 *target, physical to)
{
    console("pte ");
    print_u64(target);
    console(" ");
    print_u64(to);
    console("\n");
    // present and writable - add size bit for 2M pages
    *target = to | 3;
}


static inline physical force_entry(u64 *b, u32 offset, physical (*alloc)())
{
    if (b[offset] &1) {
        return b[offset] & ~PAGEMASK;
    } else {
        u64 n = alloc();
        write_pte(b + offset, n);
        return n;
    }
}

static void map_page(void *base, u64 virtual, physical p, physical (*alloc)())
{
    // this code is rn in 32 bit and 64 bit right now
    void *x = base;
    u64 k = (u32)virtual;
    x = pointer(force_entry(x, (k >> 39) & ((1<<9)-1), alloc));
    x = pointer(force_entry(x, (k >> 30) & ((1<<9)-1), alloc));
    x = pointer(force_entry(x, (k >> 21) & ((1<<9)-1), alloc));
    u64 off = (k >> 12) & ((1<<9)-1);
    write_pte(x + off * 8, p);
}

static void map(void *table, u64 virtual, physical p, int length, physical (*alloc)())
{
    int len = pad(length, PAGESIZE)>>12;

    console("map ");
    print_u64(virtual);
    console(" ");
    print_u64(p);
    console(" ");
    print_u64(length);
    console("\n");
    
    // if any portion of this is physically aligned on a 2M boundary
    // and is of a 2M size, can do a 2M mapping..inline map page
    // and conditionalize
    for (int i = 0; i < len; i++) 
        map_page(table, virtual + i *PAGESIZE, p + i *PAGESIZE, alloc); 
}
