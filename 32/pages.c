#include <runtime.h>
#include <vm.h>


static address base = 0;
// better allocation?
static address region = 0xa000;

#define pointer(__a) ((u64 *)(void *)(u32)__a)

address allocate()
{
    address result= region;
    for (int i=0; i < 4906>>6; i++) 
        (pointer(result))[i] = 0;
    region += 0x1000;
    return result;
}

static inline void write_pte(address target, address to)
{
    // present and writable
    *(pointer(target)) = to | 3;
}

static inline address force_entry(address base, u32 offset)
{
    u64 *b = pointer(base);
    if (b[offset] &1) {
        return b[offset] & ~PAGEMASK;
    } else {
        u64 n = allocate();
        write_pte(base + offset * 8, n);
        return n;
    }
}

static void map_page(address virtual, address physical)
{
    if (base == 0) {
        base = allocate();
        mov_to_cr("cr3", base);
    }
    u64 x = base;
    x = force_entry(x, (virtual >> 39) & ((1<<9)-1));
    x = force_entry(x, (virtual >> 30) & ((1<<9)-1));
    x = force_entry(x, (virtual >> 21) & ((1<<9)-1));
    u64 off = (virtual >> 12) & ((1<<9)-1);
    write_pte(x + off * 8, physical);
}

void map(address virtual, address physical, int length)
{
    int len = pad(length, PAGESIZE)>>12;
    for (int i = 0; i < len; i++) 
        map_page(virtual + i *PAGESIZE, physical + i *PAGESIZE); 
}





