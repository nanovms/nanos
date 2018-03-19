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
            int ssize = pad(p->p_memsz + (p->p_vaddr - trim (p->p_vaddr)), PAGESIZE);
            map(aligned+offset, physical_from_virtual(base+p->p_offset), ssize, pages);

            void *bss_start = pointer_from_u64(p->p_vaddr) + offset + p->p_filesz;
            u32 bss_size = p->p_memsz-p->p_filesz;
            if (bss_size) {
                u64 st = u64_from_pointer(bss_start);
                u64 pstart = pad(st, PAGESIZE);
                u64 len = pstart - st;
                if (bss_size > len) {
                    u32 new_pages = pad((bss_size-len), PAGESIZE);
                    len += new_pages;
                    map(pstart, allocate_u64(bss, new_pages), new_pages, pages);
                }
                zero(bss_start, len);
            }
        }
    }
    u64 entry = elfh->e_entry;
    entry += offset; 
    return pointer_from_u64(entry);
}
