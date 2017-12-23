#include <runtime.h>
#include <bottom.h>
#include <elf64.h>
#include <vm.h>

u32 startelf = 0x9000;
extern void run64(u32 entry);

void centry()
{
    //    console("stage2 started\r\n");
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





