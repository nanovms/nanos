#include <basic_runtime.h>
#include <x86_64.h>
#include <booto.h>


static void print_block(void *addr, int length)
{
    for (int i = 0; i< length; i+=8){
        print_u64(*(u64 *)(addr+i));
        console ("\n");
    }
}

extern void run64(u32 entry);

// there are a few of these little allocators
u64 offset = 0x1000;

static u64 stage2_allocator(heap h, bytes b)
{
    u64 result = offset;
    offset += b;
    return offset;
}

// pass the memory parameters (end of load, end of mem)
void centry()
{
    struct heap workings;
    workings.alloc = stage2_allocator;
    heap working = &workings;
    int sector_offset = (STAGE2SIZE>>sector_log) + (STAGE1SIZE>>sector_log);
    
    // xxx - we can derive this from the physical region and the start of stage3
    // except the child wants to start at 0x400000..maye we should throw
    // this at the .. end of the pci gap? or use a simple offset and make v and p
    // mututally aligned?
    u64 identity_start = 0x100000;
    u64 identity_length = 0x300000;

    for (region e = regions; region_type(e); e -= 1) {
        if (identity_start == region_base(e)) 
            region_base(e) = identity_start + identity_length;
    }

    create_region(identity_start, identity_length, REGION_IDENTITY);
        
    heap pages = region_allocator(working, PAGESIZE, REGION_IDENTITY);
    heap physical = region_allocator(working, PAGESIZE, REGION_PHYSICAL);
    void *vmbase = allocate_zero(pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);
    map(identity_start, identity_start, identity_length, pages);

    // lose a page, and assume ph is in the first page
    void *header = allocate(working, PAGESIZE);
    read_sectors(header, sector_offset, PAGESIZE);
    
    // check signature
    Elf64_Ehdr *elfh = header;
    u32 ph = elfh->e_phentsize;
    u32 po = elfh->e_phoff + u64_from_pointer(header);
    int pn = elfh->e_phnum;

    // should drop this in stage3? ... i think we just need
    // service32 and the stack.. this doesn't show up in the e820 regions
    // stack is currently in the first page, so lets leave it mapped
    // and take it out later...ideally move the stack here
    map(0, 0, 0xa000, pages);
    create_region(0, 0xa0000, REGION_VIRTUAL);

    // this can be generic read_elf, but we'd need to parameterize
    // out the load function. this happens* to be identity mapped
    // because of the page alloc and stage3 setup.
    // which makes it convenient for debugging, but may
    // introduce some bad implicit assumptions. debug then
    // move it around
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;
        if (p->p_type == PT_LOAD) {
            int ssize = pad(p->p_memsz, PAGESIZE);
            void *load = allocate(physical, ssize);
            read_sectors(load,
                         (p->p_offset>>sector_log) + sector_offset,
                         pad(p->p_filesz, 1<<sector_log));
            create_region(p->p_vaddr, ssize, REGION_VIRTUAL);            
            map(p->p_vaddr, u64_from_pointer(load), ssize, pages);
            zero(load + p->p_offset + p->p_filesz,  p->p_memsz - p->p_filesz);
        }
    }
    run64((u32)elfh->e_entry);
}

