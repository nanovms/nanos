#include <runtime.h>
#include <elf64.h>

static void print_block(void *addr, int length)
{
    for (int i = 0; i< length; i+=8){
        print_u64(*(u64 *)(addr+i));
        console ("\n");
    }
}

extern void run64(u32 entry);

struct region_heap working;
struct region_heap pages;

// pass the memory parameters (end of load, end of mem)
void centry()
{
    console("start stage 2\n");
    int sector_offset = (STAGE2SIZE>>sector_log) + (STAGE1SIZE>>sector_log);

    for (region e = regions; region_type(e); e--) {
        if (region_type(e) == 1) {
            region_allocator(&working, e, 1);
            break;
        }
    }
    // maybe there is another 256k at the top here
    region_allocator(&pages, create_region(0x10000, 0x80000, REGION_PHYSICAL), PAGESIZE);
    void *vmbase = (void *)(u32)allocate_zero((heap)&pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);
    
    void *header = allocate((heap)&pages, PAGESIZE);
    read_sectors(header, sector_offset, PAGESIZE);
    // check signature
    Elf64_Ehdr *elfh = header;
    u32 ph = elfh->e_phentsize;
    u32 po = elfh->e_phoff + u64_from_pointer(header);
    int pn = elfh->e_phnum;
    
    map(0, 0, 0xa0000, (heap)&pages);
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;
        if (p->p_type == PT_LOAD) {
            int ssize = pad(p->p_memsz, PAGESIZE);
            void *load = allocate((heap)&working, ssize);

            read_sectors(load,
                         (p->p_offset>>sector_log) + sector_offset,
                         pad(p->p_filesz, 1<<sector_log));
            map(p->p_vaddr, u64_from_pointer(load), ssize, (heap)&pages);
            void *start = load + p->p_offset;
            for (u8 *x =  start + p->p_filesz; x < (u8 *)start + p->p_memsz; x++)
                *x = 0;
        }
    }
    run64((u32)elfh->e_entry);
}

