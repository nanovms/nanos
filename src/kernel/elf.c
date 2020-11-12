#include <kernel.h>
#include <elf64.h>
#include <page.h>

//#define ELF_DEBUG
#ifdef ELF_DEBUG
#define elf_debug(x, ...) do {rprintf("ELF: " x, ##__VA_ARGS__);} while(0)
#else
#define elf_debug(x, ...)
#endif

static char *elf_string(buffer elf, Elf64_Shdr *string_section, u64 offset)
{
    char * str = buffer_ref(elf, string_section->sh_offset + offset);
    char * end = buffer_ref(elf, string_section->sh_offset + string_section->sh_size);
    for (char * c = str; c < end; c++)
        if (*c == '\0')
            return str;
    return 0;                   /* no null terminator found */
}

#define ELF_CHECK_PTR(ptr, type)                  \
    if (((void*)ptr) + sizeof(type) > elf_end)    \
        goto out_elf_fail;

void elf_symbols(buffer elf, elf_sym_handler each)
{
    char *symbol_string_name = ".strtab";
    void * elf_end = buffer_ref(elf, buffer_length(elf));
    Elf64_Ehdr *elfh = buffer_ref(elf, 0);
    ELF_CHECK_PTR(elfh, Elf64_Ehdr);
    Elf64_Shdr *section_names = buffer_ref(elf, elfh->e_shoff + elfh->e_shstrndx * elfh->e_shentsize);
    ELF_CHECK_PTR(section_names, Elf64_Shdr);
    if (elf_string(elf, section_names, section_names->sh_size) > (char*)elf_end)
        goto out_elf_fail;

    Elf64_Shdr *symbols =0 , *symbol_strings =0;
    Elf64_Shdr *s = buffer_ref(elf, elfh->e_shoff);

    for (int i = 0; i< elfh->e_shnum; i++) {
        ELF_CHECK_PTR(s, Elf64_Shdr);
        if (s->sh_type == SHT_SYMTAB) {
            symbols = s;
        } else if (s->sh_type == SHT_STRTAB) {
            char * name = elf_string(elf, section_names, s->sh_name);
            if (!name)
                goto out_elf_fail;
            if (runtime_memcmp(name, symbol_string_name, sizeof(symbol_string_name)-1) == 0)
                symbol_strings = s;
        }
        s++;
    }

    if (!symbols || !symbol_strings) {
        msg_warn("failed: symtab not found\n");
        return;
    }

    Elf64_Sym *sym = buffer_ref(elf, symbols->sh_offset);
    for (int i = 0; i < symbols->sh_size; i+=symbols->sh_entsize) {
        ELF_CHECK_PTR(sym, Elf64_Sym);
        char * name = elf_string(elf, symbol_strings, sym->st_name);
        if (!name)
            goto out_elf_fail;
        apply(each, name, sym->st_value, sym->st_size, sym->st_info);
        sym++;
    }
    return;
  out_elf_fail:
    msg_err("failed to parse elf file, len %d; check file image consistency\n", buffer_length(elf));
}

void walk_elf(buffer elf, range_handler rh)
{
    void *elf_end = buffer_ref(elf, buffer_length(elf));
    Elf64_Ehdr *e = buffer_ref(elf, 0);
    elf_debug("%s: buffer %p, load_offset 0x%lx, mapper %p (%F), buf [%p, %p)\n",
              __func__, elf, load_offset, mapper, mapper, e, elf_end);
    ELF_CHECK_PTR(e, Elf64_Ehdr);
    foreach_phdr(e, p) {
        ELF_CHECK_PTR(p, Elf64_Phdr);
        if (p->p_type == PT_LOAD) {
            range r = irangel(p->p_vaddr & (~MASK(PAGELOG)),
                pad(p->p_filesz + (p->p_vaddr & MASK(PAGELOG)), PAGESIZE));
            apply(rh, r);
            if (p->p_memsz > range_span(r))
                apply(rh, irangel(r.end, pad(p->p_memsz - range_span(r), PAGESIZE)));
        }
    }
  out_elf_fail:
    return;
}

void *load_elf(buffer elf, u64 load_offset, elf_map_handler mapper)
{
    void *elf_end = buffer_ref(elf, buffer_length(elf));
    Elf64_Ehdr *e = buffer_ref(elf, 0);
    elf_debug("%s: buffer %p, load_offset 0x%lx, mapper %p (%F), buf [%p, %p)\n",
              __func__, elf, load_offset, mapper, mapper, e, elf_end);
    ELF_CHECK_PTR(e, Elf64_Ehdr);
    foreach_phdr(e, p) {
        ELF_CHECK_PTR(p, Elf64_Phdr);
        if (p->p_type == PT_LOAD) {
            elf_debug("   PT_LOAD vaddr 0x%lx, offset 0x%lx, ssize 0x%lx\n",
                      p->p_vaddr, p->p_offset, p->p_filesz);
            // unaligned segment? doesn't seem useful
            u64 aligned = p->p_vaddr & (~MASK(PAGELOG));
            u64 trim_offset = p->p_vaddr & MASK(PAGELOG);
            u64 vstart = u64_from_pointer(buffer_ref(elf, p->p_offset)) & ~MASK(PAGELOG);
            u64 phy = physical_from_virtual(pointer_from_u64(vstart));
            int ssize = pad(p->p_filesz + trim_offset, PAGESIZE);

            /* determine access permissions */
            u64 flags = 0;
            if ((p->p_flags & PF_X) == 0)
                flags |= PAGE_NO_EXEC;
            if ((p->p_flags & PF_W))
                flags |= PAGE_WRITABLE;
            apply(mapper, aligned + load_offset, phy, ssize, flags);

            // always zero up to the next aligned page start
            s64 bss_size = p->p_memsz - p->p_filesz;
            elf_debug("   bss_size 0x%lx\n", bss_size);

            if (bss_size < 0)
                halt("load_elf with p->p_memsz (%ld) < p->p_filesz (%ld)\n",
                     p->p_memsz, p->p_filesz);
            else if (bss_size == 0)
                continue;

            u64 bss_start = p->p_vaddr + load_offset + p->p_filesz;

            /* Zero bss up to a page boundary. ld-linux may use the unused
               part of the page after bss and expects it to be zeroed. */
            u64 initial_len_padded = pad(bss_start, PAGESIZE) - bss_start;
            elf_debug("   bss_start 0x%lx, initial_len 0x%lx\n", bss_start, initial_len_padded);

            /* vpzero does the right thing whether stage2 or 3... */
            vpzero(pointer_from_u64(bss_start), phy + p->p_filesz, initial_len_padded);

            if (bss_size > initial_len_padded) {
                u64 pstart = bss_start + initial_len_padded;
                u64 psize = pad((bss_size - initial_len_padded), PAGESIZE);
                apply(mapper, pstart, INVALID_PHYSICAL, psize, flags);
            }
        }
    }
    u64 entry = e->e_entry + load_offset;
    elf_debug("   done; entry 0x%lx\n", entry);
    return pointer_from_u64(entry);
  out_elf_fail:
    msg_err("failed to parse elf file, len %d; check file image consistency\n", buffer_length(elf));
    return INVALID_ADDRESS;
}
