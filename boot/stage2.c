#define pointer(__a) ((u64 *)(void *)(u32)__a)
#include <runtime.h>
#include <elf64.h>

#define BASE 0x3f8

u32 startelf = 0x9000;

extern void run64(u32 entry, u64 heap_start);

static physical region;

#define SECTOR_LOG 12

physical pt_allocate()
{
    physical result= region;
    for (int i=0; i < 4906>>6; i++) 
        (pointer(result))[i] = 0;
    region += 0x1000;
    return result;
}

static boolean is_transmit_empty() {
    return in8(BASE + 5) & 0x20;
}

void serial_out(char a)
{
    while (!is_transmit_empty());
    out8(BASE, a);
}


// pass the memory parameters (end of load, end of mem)
void centry()
{
    region = ((startelf + STAGE2SIZE + STAGE3SIZE + ((1<<SECTOR_LOG) -1)) >>SECTOR_LOG) << SECTOR_LOG;
    void *base = (void *)(u32)pt_allocate();
    mov_to_cr("cr3", base);


    Elf64_Ehdr *elfh = (void *)startelf;
    u32 ph = elfh->e_phentsize;
    u32 po = elfh->e_phoff + startelf;
    int pn = elfh->e_phnum;

    // start allocating after all the load regions
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;
        if (p->p_type == PT_LOAD) {
            u32 end =  pad(startelf + p->p_offset + p->p_memsz, PAGESIZE);
            if (end > region) region = end;
        }
     }
    
    // xxx - assume application is loaded at 0x400000
    // you're in a position to check that...maybe just fix up the
    // stage3 virtual allocation and stop running in this little identity
    // region2
    map(base, 0x0000, 0x0000, 0x400000, pt_allocate);
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;
        if (p->p_type == PT_LOAD) {
            // void * is the wrong type, since here its 32 bits
            map(base, p->p_vaddr, startelf + p->p_offset, pad(p->p_memsz, PAGESIZE), pt_allocate);
            // clean the bss - this will fail dramatically if the bss isn't
            // the last logical part of the elf file. so, copy out if necessary,
            // - could use physically unrelated zero pages to build it
            void *start = (void *)startelf + p->p_offset;
            for (u8 *x =  start + p->p_filesz; x < (u8 *)start + p->p_memsz; x++)
                *x = 0;
        }
    }
    *START_ADDRESS = region;
    run64(elfh->e_entry, region);
}

