#include <kernel.h>
#include <elf64.h>

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
    elf_debug("%s: buffer %p, handler %p (%F), buf [%p, %p)\n",
              __func__, elf, rh, rh, e, elf_end);
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
            elf_debug("   PT_LOAD p_vaddr 0x%lx, p_offset 0x%lx, p_filesz 0x%lx\n",
                      p->p_vaddr, p->p_offset, p->p_filesz);
            /* determine access permissions */
            pageflags flags = pageflags_memory();
            if (p->p_flags & PF_X)
                flags = pageflags_exec(flags);
            if (p->p_flags & PF_W)
                flags = pageflags_writable(flags);

            u64 aligned = p->p_vaddr & (~MASK(PAGELOG));
            u64 trim_offset = p->p_vaddr & MASK(PAGELOG);
            u64 src = u64_from_pointer(buffer_ref(elf, p->p_offset)) & ~MASK(PAGELOG);
            u64 phys = physical_from_virtual(pointer_from_u64(src));
            s64 bss_size = p->p_memsz - p->p_filesz;
            if (bss_size < 0)
                halt("load_elf with p->p_memsz (%ld) < p->p_filesz (%ld)\n",
                     p->p_memsz, p->p_filesz);
            u64 bss_start = p->p_vaddr + load_offset + p->p_filesz;
            u64 ssize = p->p_filesz + trim_offset;

            /* If there is a bss in this segment and it doesn't start on a
               page boundary, truncate the mapped file data to the page
               boundary and copy the remainder into the bss mapping. */
            u64 tail_copy = ssize & MASK(PAGELOG);
            if (bss_size > 0 && tail_copy != 0)
                ssize &= ~MASK(PAGELOG);

            elf_debug("      src 0x%lx, phys 0x%lx, bss_size 0x%lx, bss_start 0x%lx\n",
                      src, phys, bss_size, bss_start);
            elf_debug("      ssize 0x%lx, tail_copy 0x%lx, flags 0x%lx\n",
                      ssize, tail_copy, flags);

            if (ssize > 0)
                apply(mapper, aligned + load_offset, phys, pad(ssize, PAGESIZE), flags);

            if (bss_size > 0) {
                u64 map_start = bss_start & ~MASK(PAGELOG);
                u64 va = apply(mapper, map_start, INVALID_PHYSICAL,
                               pad(tail_copy + bss_size, PAGESIZE), flags);
                if (tail_copy > 0)
                    runtime_memcpy(pointer_from_u64(va), pointer_from_u64(src + ssize), tail_copy);
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
