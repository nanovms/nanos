#define pointer(__a) ((u64 *)(void *)(u32)__a)
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

void console(char *x)
{
    for (char *i = x; *i; i++) 
        serial_out(*i);
}

extern void run64(u32 entry, u64 heap_start);

u32 alloc = 0x8000 + STAGE2_LENGTH;

#define SECTOR_LOG 12

physical pt_allocate()
{
    physical result= alloc;
    console("pagey ");
    print_u64(alloc);
    console("\n");
    for (int i=0; i < 4906>>6; i++) 
        (pointer(result))[i] = 0;
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

    console("spanky\n");
    read_sectors((void *)alloc, sector_offset, PAGESIZE);
    
    // check signature
    Elf64_Ehdr *elfh = (void *)alloc;
    u32 ph = elfh->e_phentsize;
    u32 po = elfh->e_phoff + alloc;
    int pn = elfh->e_phnum;
    alloc += 4096;
    
    // xxx - assume application is loaded at 0x400000
    // you're in a position to check that...maybe just fix up the
    // stage3 virtual allocation and stop running in this little identity
    // region2
    map(vmbase, 0x0000, 0x0000, 0x400000, pt_allocate);
    for (int i = 0; i< pn; i++){
        Elf64_Phdr *p = (void *)po + i * ph;
        if (p->p_type == PT_LOAD) {
            console("section ");
            print_u64(p->p_offset);
            console(" ");
            print_u64(p->p_filesz);
            console(" ");
            print_u64(p->p_vaddr);
            console(" ");
            print_u64(alloc);
            console("\n");
            read_sectors((void *)alloc, (p->p_offset>>sector_log) + sector_offset, p->p_filesz);
            // void * is the wrong type, since here its 32 bits
            int ssize = pad(p->p_memsz, PAGESIZE);
            u32 load = alloc;
            alloc += ssize;
            map(vmbase, p->p_vaddr, load, ssize, pt_allocate);
            void *start = (void *)alloc + p->p_offset;
            for (u8 *x =  start + p->p_filesz; x < (u8 *)start + p->p_memsz; x++)
                *x = 0;
            alloc += pad(p->p_memsz, PAGESIZE);
        }
    }
    *START_ADDRESS = alloc;

    print_u64(elfh->e_entry);
    console(" ");
    print_u64(*(u64 *)(0xf000+(elfh->e_entry&0xfff)));
    console("\n");
    // 64 bit entries
    run64((u32)elfh->e_entry, alloc);
}

