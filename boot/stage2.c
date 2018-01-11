#include <runtime.h>
#include <elf64.h>

#define BASE 0x3f8

// check to make sure stage2 is still 0x1000
#define STAGE2_LENGTH  0x1000
#define STAGE1_LENGTH  0x0200

static char hex[]="0123456789abcdef";

void print_u64(u64 s)
{
    for (int x = 60; x >= 0; x -= 4)
        serial_out(hex[(s >> x)&0xf]);
}

static void print_block(void *addr, int length)
{
    for (int i = 0; i< length; i+=8){
        print_u64(*(u64 *)(addr+i));
        console ("\n");
    }
}
void console(char *x)
{
    for (char *i = x; *i; i++) 
        serial_out(*i);
}

extern void run64(u32 entry, u64 heap_start);

u32 alloc = 0x8000 + STAGE2_LENGTH;

#define SECTOR_LOG 12

page pt_allocate()
{
    void *result = pointer_from_u64(alloc);
    for (int i=0; i < 4096>>6; i++) 
        ((u64 *)result)[i] = 0;
    alloc += 0x1000;
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
    int sector_offset = (STAGE2_LENGTH>>sector_log) + (STAGE1_LENGTH>>sector_log);
    void *vmbase = (void *)(u32)pt_allocate();
    mov_to_cr("cr3", vmbase);

    read_sectors((void *)alloc, sector_offset, PAGESIZE);
    
    // check signature
    Elf64_Ehdr *elfh = (void *)alloc;
    u32 ph = elfh->e_phentsize;
    u32 po = elfh->e_phoff + alloc;
    int pn = elfh->e_phnum;
    alloc += 4096;
    
    // xxx - assume application is loaded at 0x400000.. need to
    // at least identity map 0x8000-0x9000 identity for the
    // page flip
    map(vmbase, 0x0000, 0x0000, 0x400000, pt_allocate);
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;
        if (p->p_type == PT_LOAD) {
            int ssize = pad(p->p_memsz, PAGESIZE);
            u32 load = alloc;
            alloc += ssize;
            
            read_sectors((void *)load, (p->p_offset>>sector_log) + sector_offset, pad(p->p_filesz, 1<<sector_log));
            // void * is the wrong type, since here its 32 bits
            map(vmbase, p->p_vaddr, load, ssize, pt_allocate);
            void *start = (void *)load + p->p_offset;
            for (u8 *x =  start + p->p_filesz; x < (u8 *)start + p->p_memsz; x++)
                *x = 0;
        }
    }
    *START_ADDRESS = alloc;
    run64((u32)elfh->e_entry, alloc);
}

