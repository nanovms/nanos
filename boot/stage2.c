#include <runtime.h>
#include <elf64.h>

u32 startelf = 0x9000;
extern void run64(u32 entry);

typedef u64 address;

static address base = 0;
// better allocation?
static address region = 0xb000;


#define PAGELOG 12
#define PAGESIZE (1<<PAGELOG)
#define PAGEMASK ((1ull<<PAGELOG)-1)

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

void centry()
{
    Elf64_Ehdr *elfh = (void *)startelf;
    u32 ph = elfh->e_phentsize;
    u32 po = elfh->e_phoff + startelf;
    int pn = elfh->e_phnum;
    // identity map stage2
    map(0x8000, 0x8000, PAGESIZE);
    // stack
    map(0x0000, 0x0000, PAGESIZE);    
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;        
        if (p->p_type == PT_LOAD) 
            map(p->p_vaddr, startelf + p->p_offset, pad(p->p_memsz, PAGESIZE));
    }
    run64(elfh->e_entry);
}





