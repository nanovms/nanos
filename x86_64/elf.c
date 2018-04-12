#include <basic_runtime.h>
#include <elf64.h>

// this doesn't really belong in x86_64, but it does belong
// in the kernel runtime

// buffer would be better for range checking, but stage2 uses this
void *load_elf(buffer elf, u64 offset, heap pages, heap bss)
{
    Elf64_Ehdr *elfh = buffer_ref(elf, 0);

    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = buffer_ref(elf, elfh->e_phoff + i * elfh->e_phentsize);
        if (p->p_type == PT_LOAD) {
            // unaligned segment? doesn't seem useful
            u64 aligned = p->p_vaddr & (~MASK(PAGELOG));
            u64 trim_offset = p->p_vaddr & MASK(PAGELOG);
            u64 phy = physical_from_virtual(u64_from_pointer(buffer_ref(elf, p->p_offset)) & ~MASK(PAGELOG));
            int ssize = pad(p->p_memsz + trim_offset, PAGESIZE);
            map(aligned + offset, phy, ssize, pages);

            // always zero up to the next aligned page start
            u64 bss_start = p->p_vaddr + offset + p->p_filesz;
            u32 bss_size = p->p_memsz-p->p_filesz;            
            u64 initial_len = MIN(bss_size, pad(bss_start, PAGESIZE) - bss_start);

            vpzero(pointer_from_u64(bss_start), phy + p->p_filesz, initial_len);

            if (bss_size > initial_len) {
                u64 pstart = bss_start + initial_len;
                u32 new_pages = pad((bss_size-initial_len), PAGESIZE);
                u64 phys = allocate_u64(bss, new_pages);
                map(pstart, phys, new_pages, pages);
                vpzero(pstart, phys, new_pages);
            }
        }
    }
    u64 entry = elfh->e_entry;
    entry += offset; 
    return pointer_from_u64(entry);
}
