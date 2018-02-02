#include <runtime.h>

// returns entry address.. need the base of the elf also for ld.so
// bss is allocated virtual and double mapped. should pass
// a physical allocator
void *load_elf(void *base, u64 offset, heap pages, heap bss)
{
    Elf64_Ehdr *elfh = base;

    // ld.so cant be loaded at its ph location, 0
    // also - write a virtual address space allocator that
    // maximizes sparsity
    // xxx looks like a page table setup problem?

    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = elfh->e_phoff + base + i * elfh->e_phentsize;
        if (p->p_type == PT_LOAD) {
            // unaligned segment? uncool bro
            u64 vbase = (p->p_vaddr & ~MASK(PAGELOG)) + offset;
            int ssize = pad(p->p_memsz + (p->p_vaddr & MASK(PAGELOG)), PAGESIZE);
            map(vbase, physical_from_virtual((void *)(base+p->p_offset)), ssize, pages);

            void *bss_start = (void *)vbase + p->p_filesz + (p->p_vaddr & MASK(PAGELOG));
            u32 bss_size = p->p_memsz-p->p_filesz;
            u32 already_pad = PAGESIZE - bss_size & MASK(PAGELOG);
            if ((bss_size > already_pad)) {
                u32 new_pages = pad(bss_size, PAGESIZE);
                u64 phy = physical_from_virtual(allocate(bss, new_pages));
                map(u64_from_pointer(bss_start), phy, new_pages, pages);
            }
            // there is probably a shorter way to express all this
            u64 end = u64_from_pointer(bss_start + bss_size);
            bss_size += pad(end, PAGESIZE) - end;
                
            rprintf("zero bss: %p %p %p\n", bss_start, bss_start+bss_size, bss_size);
            zero(bss_start, bss_size);
        }
    }
    u64 entry = elfh->e_entry;
    entry += offset; // see above
    return pointer_from_u64(entry);
}
