#include <runtime.h>
#include <elf64.h>

u32 startelf = 0x9000;
extern void run64(u32 entry, u64 heap_start);

static physical base = 0;
// better allocation?
static physical region = 0xe000;


#define PAGELOG 12
#define PAGESIZE (1<<PAGELOG)
#define PAGEMASK ((1ull<<PAGELOG)-1)

#define pointer(__a) ((u64 *)(void *)(u32)__a)


physical pt_allocate()
{
    physical result= region;
    for (int i=0; i < 4906>>6; i++) 
        (pointer(result))[i] = 0;
    region += 0x1000;
    return result;
}

static inline void write_pte(physical target, physical to)
{
    // present and writable
    *(pointer(target)) = to | 3;
}

static inline physical force_entry(physical base, u32 offset)
{
    u64 *b = pointer(base);
    if (b[offset] &1) {
        return b[offset] & ~PAGEMASK;
    } else {
        u64 n = pt_allocate();
        write_pte(base + offset * 8, n);
        return n;
    }
}

static void map_page(void *virtual, physical p)
{
    if (base == 0) {
        base = pt_allocate();
        mov_to_cr("cr3", base);
    }

    u64 x = base;
    u64 k = (u32)virtual;
    x = force_entry(x, (k >> 39) & ((1<<9)-1));
    x = force_entry(x, (k >> 30) & ((1<<9)-1));
    x = force_entry(x, (k >> 21) & ((1<<9)-1));
    u64 off = (k >> 12) & ((1<<9)-1);
    write_pte(x + off * 8, p);
}

void map(void *virtual, physical p, int length)
{
    int len = pad(length, PAGESIZE)>>12;

    // if any portion of this is physically aligned on a 2M boundary
    // and is of a 2M size, can do a 2M mapping..inline map page
    // and conditionalize
    for (int i = 0; i < len; i++) 
        map_page(virtual + i *PAGESIZE, p + i *PAGESIZE); 
}

#define SECTOR_LOG 12

// pass the memory parameters (end of load, end of mem)
void centry()
{
    region = ((startelf + STAGE2SIZE + STAGE3SIZE + ((1<<SECTOR_LOG) -1)) >>SECTOR_LOG) << SECTOR_LOG;

    Elf64_Ehdr *elfh = (void *)startelf;
    u32 ph = elfh->e_phentsize;
    u32 po = elfh->e_phoff + startelf;
    int pn = elfh->e_phnum;
    
    // xxx - assume application is loaded at 0x400000
    // you're in a position to check that
    map(0x0000, 0x0000, 0x400000);    
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;
        if (p->p_type == PT_LOAD) {
            // void * is the wrong type, since here its 32 bits
            map((void *)(u32)p->p_vaddr, startelf + p->p_offset, pad(p->p_memsz, PAGESIZE));
            // clean the bss - destroys the rest of the bss - what about exceeding elf?
            void *start = (void *)startelf + p->p_offset;
            for (u8 *x =  start + p->p_filesz; x < (u8 *)start + p->p_memsz; x++)
                *x = 0;
        }
    }
    *START_ADDRESS = region;
    run64(elfh->e_entry, region);
}

