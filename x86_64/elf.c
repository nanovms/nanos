#include <runtime.h>
#include <elf64.h>

// this doesn't really belong in x86_64, but it does belong
// in the kernel runtime

#define trim(x) ((x) & ~MASK(PAGELOG))

// buffer would be better for range checking, but stage2 uses this
void *load_elf(void *base, u64 offset, heap pages, heap bss)
{
    Elf64_Ehdr *elfh = base;

    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = elfh->e_phoff + base + i * elfh->e_phentsize;
        if (p->p_type == PT_LOAD) {
            // unaligned segment? uncool bro
            u64 aligned = trim(p->p_vaddr);
            u64 phy = physical_from_virtual(base+p->p_offset);
            int ssize = pad(p->p_memsz + (p->p_vaddr - trim (p->p_vaddr)), PAGESIZE);
            map(aligned+offset, phy, ssize, pages);

            // always zero up to the next aligned page start
            u64 bss_start = p->p_vaddr + offset + p->p_filesz;
            u32 bss_size = p->p_memsz-p->p_filesz;            
            u64 initial_len = pad(bss_start, PAGESIZE) - bss_start;
            vpzero(pointer_from_u64(bss_start), phy + p->p_filesz, initial_len);

            console("bss: ");
            print_u64(u64_from_pointer(bss_start));
            console(" ");
            print_u64(bss_size);
            console(" ");            
            print_u64(u64_from_pointer(base));
            console(" ");            
            print_u64(u64_from_pointer(initial_len));
            console("\n");

            // add as many zero pages as necesary to cover the rest of the bss
            if (bss_size > initial_len) {
                u64 pstart = bss_start + initial_len;
                u32 new_pages = pad((bss_size-initial_len), PAGESIZE);
                u64 phys = allocate_u64(bss, new_pages);
                map(pstart, phys, new_pages, pages);
                vpzero(pstatr, phys, new_pages);
            }
        }
    }
    u64 entry = elfh->e_entry;
    entry += offset; 
    return pointer_from_u64(entry);
}
