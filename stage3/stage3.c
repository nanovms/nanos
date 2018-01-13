#include <runtime.h>

extern void *_binary_test_bin_start;

void startup(heap pages)
{
    console("stage3\n");
    void *base = &_binary_test_bin_start;
    Elf64_Ehdr *elfh = base;

    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = elfh->e_phoff + base + i * elfh->e_phentsize;
        if (p->p_type == PT_LOAD) {
            int ssize = pad(p->p_memsz, PAGESIZE);
            console("map: ");
            print_u64(p->p_vaddr);
            console(" ");
            print_u64(u64_from_pointer(base)+p->p_offset);
            console(" ");
            print_u64(physical_from_virtual(base+p->p_offset));
            console(" ");
            print_u64(ssize);
            console("\n");
            map(p->p_vaddr, physical_from_virtual(base+p->p_offset), ssize, pages);
            // need to allocate the bss here
            //            for (u8 *x =  start + p->p_filesz; x < (u8 *)start + p->p_memsz; x++)
            //                *x = 0;
        }
    }
    console("entry: ");
    print_u64(elfh->e_entry);
    console("\n");
    ((void(*)())elfh->e_entry)();
}

