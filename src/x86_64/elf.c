#include <runtime.h>
#include <elf64.h>


static inline char *elf_string(buffer elf, Elf64_Shdr *string_section, u64 offset)
{
    return (char *)(buffer_ref(elf, string_section->sh_offset + offset));
}

void elf_symbols(buffer elf, closure_type(each, void, char *, u64, u64, u8))
{
    char *symbol_string_name = ".strtab";
    Elf64_Ehdr *elfh = buffer_ref(elf, 0);
    Elf64_Shdr *section_names = buffer_ref(elf, elfh->e_shoff + elfh->e_shstrndx * elfh->e_shentsize);
    Elf64_Shdr *symbols =0 , *symbol_strings =0;
    Elf64_Shdr *s = buffer_ref(elf, elfh->e_shoff);

    for (int i = 0; i< elfh->e_shnum; i++) {
        if (s->sh_type == SHT_SYMTAB) symbols = s;
        // elf is kinda broken wrt finding the right string table for the symbols
        if ((s->sh_type == SHT_STRTAB) &&
            (compare_bytes(elf_string(elf, section_names, s->sh_name), symbol_string_name, sizeof(symbol_string_name)-1)))
            symbol_strings = s;
        s++;
    }

    if (!symbols || !symbol_strings) {
        msg_err("failed: symtab not found\n");
        return;
    }

    Elf64_Sym *sym = buffer_ref(elf, symbols->sh_offset);
    for (int i = 0; i < symbols->sh_size; i+=symbols->sh_entsize) {
        apply(each,
              elf_string(elf, symbol_strings, sym->st_name),
              sym->st_value, sym->st_size, sym->st_info);
        sym++;
    }
}

void *load_elf(buffer elf, u64 offset, heap pages, heap bss)
{
    Elf64_Ehdr *e = buffer_ref(elf, 0);
    foreach_phdr(e, p) {
        if (p->p_type == PT_LOAD) {
            // unaligned segment? doesn't seem useful
            u64 aligned = p->p_vaddr & (~MASK(PAGELOG));
            u64 trim_offset = p->p_vaddr & MASK(PAGELOG);
            u64 vstart = u64_from_pointer(buffer_ref(elf, p->p_offset)) & ~MASK(PAGELOG);
            u64 phy = physical_from_virtual(pointer_from_u64(vstart));
            int ssize = pad(p->p_filesz + trim_offset, PAGESIZE);
            map(aligned + offset, phy, ssize, pages);

            // always zero up to the next aligned page start
            s64 bss_size = p->p_memsz - p->p_filesz;

            if (bss_size < 0)
                halt("load_elf with p->p_memsz (%d) < p->p_filesz (%d)\n",
                     p->p_memsz, p->p_filesz);
            else if (bss_size == 0)
                continue;

            u64 bss_start = p->p_vaddr + offset + p->p_filesz;
            u64 initial_len = MIN(bss_size, pad(bss_start, PAGESIZE) - bss_start);

            /* vpzero does the right thing whether stage2 or 3... */
            vpzero(pointer_from_u64(bss_start), phy + p->p_filesz, initial_len);

            if (bss_size > initial_len) {
                u64 pstart = bss_start + initial_len;
                u64 psize = pad((bss_size - initial_len), PAGESIZE);
                u64 phys = allocate_u64(bss, psize);
                map(pstart, phys, psize, pages);
                vpzero(pointer_from_u64(pstart), phys, psize);
            }
        }
    }
    u64 entry = e->e_entry;
    entry += offset; 
    return pointer_from_u64(entry);
}
