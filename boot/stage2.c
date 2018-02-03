#include <pruntime.h>

static void print_block(void *addr, int length)
{
    for (int i = 0; i< length; i+=8){
        print_u64(*(u64 *)(addr+i));
        console ("\n");
    }
}

extern void run64(u32 entry);

u64 offset = 0x1000;

static u64 stage2_allocator(heap h, bytes b)
{
    u64 result = offset;
    offset += b;
    return offset;
}

#define IDENTITY_START 0x100000
#define IDENTITY_END 0x1000000

// pass the memory parameters (end of load, end of mem)
void centry()
{
    struct heap workings;
    workings.allocate = stage2_allocator;
    heap working = &workings;
    int sector_offset = (STAGE2SIZE>>sector_log) + (STAGE1SIZE>>sector_log);

    for (region e = regions; ;e -= 1) {
        console("region ");
        print_u64(region_base(e));
        console(" ");
        print_u64(region_length(e));
        console("\n");
    }

    create_region(IDENTITY_START, IDENTITY_END-IDENTITY_START, REGION_IDENTITY);
    heap pages = region_allocator(working, REGION_IDENTITY, PAGESIZE);
    // remove identity page region from phy
    heap physical = region_allocator(working, REGION_PHYSICAL, PAGESIZE);    
    void *vmbase = allocate_zero(pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);

    // lose a page, and assume ph is in the first page
    void *header = allocate(physical, PAGESIZE);
    read_sectors(header, sector_offset, PAGESIZE);
    // check signature
    Elf64_Ehdr *elfh = header;
    u32 ph = elfh->e_phentsize;
    u32 po = elfh->e_phoff + u64_from_pointer(header);
    int pn = elfh->e_phnum;

    // should drop this in stage3? 
    map(PAGESIZE, PAGESIZE, 0xa0000-PAGESIZE, pages);
    create_region(0, 0xa0000, REGION_VERBOTEN);
    
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;
        if (p->p_type == PT_LOAD) {
            int ssize = pad(p->p_memsz, PAGESIZE);
            void *load = allocate(physical, ssize);

            read_sectors(load,
                         (p->p_offset>>sector_log) + sector_offset,
                         pad(p->p_filesz, 1<<sector_log));
            create_region(p->p_vaddr, ssize, REGION_VIRTUAL);            
            map(p->p_vaddr, u64_from_pointer(load), ssize, (heap)&pages);
            void *start = load + p->p_offset;
            for (u8 *x =  start + p->p_filesz; x < (u8 *)start + p->p_memsz; x++)
                *x = 0;
        }
    }
    run64((u32)elfh->e_entry);
}

