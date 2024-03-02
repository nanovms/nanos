#include <kernel.h>
#include <elf64.h>

//#define ELF_DEBUG
#ifdef ELF_DEBUG
#ifdef KERNEL
#define elf_debug(x, ...) do {tprintf(sym(elf), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define elf_debug(x, ...) do {rprintf(" ELF: " x, ##__VA_ARGS__);} while(0)
#endif
#else
#define elf_debug(x, ...)
#endif

sstring elf_string(buffer elf, Elf64_Shdr *string_section, u64 offset)
{
    char * str = buffer_ref(elf, string_section->sh_offset + offset);
    char * end = buffer_ref(elf, string_section->sh_offset + string_section->sh_size);
    for (char * c = str; c < end; c++)
        if (*c == '\0')
            return isstring(str, c - str);
    return sstring_null();  /* no null terminator found */
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
    if (section_names->sh_offset + section_names->sh_size > buffer_length(elf))
        goto out_elf_fail;

    Elf64_Shdr *symbols =0 , *symbol_strings =0;
    Elf64_Shdr *s = buffer_ref(elf, elfh->e_shoff);

    for (int i = 0; i< elfh->e_shnum; i++) {
        ELF_CHECK_PTR(s, Elf64_Shdr);
        if (s->sh_type == SHT_SYMTAB) {
            symbols = s;
        } else if (s->sh_type == SHT_STRTAB) {
            sstring name = elf_string(elf, section_names, s->sh_name);
            if (sstring_is_null(name))
                goto out_elf_fail;
            if (runtime_memcmp(name.ptr, symbol_string_name, sizeof(symbol_string_name)-1) == 0)
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
        sstring name = elf_string(elf, symbol_strings, sym->st_name);
        if (sstring_is_null(name))
            goto out_elf_fail;
        apply(each, name, sym->st_value, sym->st_size, sym->st_info);
        sym++;
    }
    return;
  out_elf_fail:
    msg_err("failed to parse elf file, len %d; check file image consistency\n", buffer_length(elf));
}

closure_function(6, 1, boolean, elf_sym_relocate,
                 buffer, elf, void *, load_addr, Elf64_Sym *, syms, u64, sym_count, Elf64_Shdr *, strtab, elf_sym_resolver, resolver,
                 Elf64_Rela *rel)
{
    u64 sym_index = ELF64_R_SYM(rel->r_info);
    sstring sym_name;
    if (sym_index < bound(sym_count))
        sym_name = elf_string(bound(elf), bound(strtab), bound(syms)[sym_index].st_name);
    else
        sym_name = sstring_null();
    if (sstring_is_null(sym_name))
        return false;
    void *sym_addr = apply(bound(resolver), sym_name);
    if (sym_addr == INVALID_ADDRESS)
        return false;
    u64 *target = bound(load_addr) + rel->r_offset;
    *target = u64_from_pointer(sym_addr);
    return true;
}

boolean elf_dyn_parse(buffer elf, Elf64_Shdr **symtab, Elf64_Shdr **strtab, Elf64_Rela **reltab,
                      int *relcount)
{
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(elf, 0);
    void *elf_end = buffer_end(elf);

    /* Look for the dynamic section */
    Elf64_Dyn *dyn = 0;
    foreach_shdr(e, s) {
        ELF_CHECK_PTR(s, Elf64_Shdr);
        if (s->sh_type == SHT_DYNAMIC) {
            dyn = buffer_ref(elf, s->sh_offset);
            break;
        }
    }
    *symtab = *strtab = 0;
    *reltab = 0;
    if (!dyn)
        return true;

    /* Get the offsets of the tables referenced in the dynamic section */
    u64 symtab_offset = 0, strtab_offset = 0, reltab_offset = 0;
    while (true) {
        ELF_CHECK_PTR(dyn, Elf64_Dyn);
        if (dyn->d_tag == DT_NULL)
           break;
        switch (dyn->d_tag) {
        case DT_SYMTAB:
            symtab_offset = dyn->d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab_offset = dyn->d_un.d_ptr;
            break;
        case DT_RELA:
        case DT_JMPREL:
            if (!reltab_offset || (dyn->d_un.d_ptr < reltab_offset))
                reltab_offset = dyn->d_un.d_ptr;
            break;
        }
        dyn++;
    }
    if (!symtab_offset || !strtab_offset || !reltab_offset)
        return true;

    /* Look for the section headers of the tables referenced in the dynamic section. If there are
     * multiple relocation sections, merge them so they appear as a single relocation table.*/
    Elf64_Shdr *rel_section = 0;
    foreach_shdr(e, s) {
        switch (s->sh_type) {
        case SHT_DYNSYM:
            if (s->sh_addr == symtab_offset)
                *symtab = s;
            break;
        case SHT_STRTAB:
            if (s->sh_addr == strtab_offset)
                *strtab = s;
            break;
        case SHT_RELA:
            ELF_CHECK_PTR(s, Elf64_Shdr);
            assert(s->sh_entsize == sizeof(Elf64_Rela));
            if (s->sh_addr == reltab_offset) {
                rel_section = s;
                *reltab = buffer_ref(elf, s->sh_offset);
                *relcount = s->sh_size / sizeof(Elf64_Rela);
            } else if (rel_section && (s->sh_addr == rel_section->sh_addr + rel_section->sh_size)) {
                *relcount += s->sh_size / sizeof(Elf64_Rela);
            }
            break;
        }
    }
    if (!*symtab || !*strtab || !*reltab)
        goto out_elf_fail;

    ELF_CHECK_PTR(*symtab, Elf64_Shdr);
    ELF_CHECK_PTR(*strtab, Elf64_Shdr);
    return true;
  out_elf_fail:
    msg_err("failed to parse elf, len %d\n", buffer_length(elf));
    return false;
}

boolean elf_dyn_link(buffer elf, void *load_addr, elf_sym_resolver resolver)
{
    Elf64_Shdr *symtab, *strtab;
    Elf64_Rela *reltab;
    int relcount;
    if (!elf_dyn_parse(elf, &symtab, &strtab, &reltab, &relcount))
        return false;
    if (!symtab || !strtab || !reltab)
        return true;
    return elf_apply_relocate_syms(elf, reltab, relcount,
                                   stack_closure(elf_sym_relocate, elf, load_addr,
                                                 buffer_ref(elf, symtab->sh_offset),
                                                 symtab->sh_size / symtab->sh_entsize, strtab,
                                                 resolver));
}

void elf_dyn_relocate(u64 base, u64 offset, Elf64_Dyn *dyn, Elf64_Sym *syms)
{
    Elf64_Rela *rel = 0;
    u64 relsz = 0, relent = 0, relcount = 0;
    int i;

    for (i = 0; dyn[i].d_tag != DT_NULL; ++i) {
        switch (dyn[i].d_tag) {
            case DT_RELA:
                rel = (Elf64_Rela *)pointer_from_u64(dyn[i].d_un.d_ptr + base);
                break;
            case DT_RELASZ:
                relsz = dyn[i].d_un.d_val;
                break;
            case DT_RELAENT:
                relent = dyn[i].d_un.d_val;
                break;
            case DT_RELACOUNT:
                relcount = dyn[i].d_un.d_val;
                break;
            default:
                break;
        }
    }
    if (!rel || (relent != sizeof(Elf64_Rela)))
        return;
    if (relsz == 0)
        relsz = relent * relcount;
    arch_elf_relocate(rel, relsz, syms, base, offset);
}

boolean elf_plt_get(buffer elf, u64 *addr, u64 *offset, u64 *size)
{
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(elf, 0);
    void *elf_end = buffer_end(elf);
    Elf64_Shdr *section_names = buffer_ref(elf, e->e_shoff + e->e_shstrndx * e->e_shentsize);
    ELF_CHECK_PTR(section_names, Elf64_Shdr);
    if (section_names->sh_offset + section_names->sh_size > buffer_length(elf))
        goto out_elf_fail;
    Elf64_Shdr *plt_section = 0;
    sstring name;
    foreach_shdr(e, s) {
        switch (s->sh_type) {
        case SHT_PROGBITS:
        case SHT_NOBITS:
            name = elf_string(elf, section_names, s->sh_name);
            if (sstring_is_null(name))
                goto out_elf_fail;
            char plt_prefix[] = {'.', 'p', 'l', 't'};
            if ((name.len >= sizeof(plt_prefix)) &&
                !runtime_memcmp(name.ptr, plt_prefix, sizeof(plt_prefix))) {
                ELF_CHECK_PTR(s, Elf64_Shdr);
                elf_debug("%s: found section %s\n", func_ss, name);
                if (!plt_section) {
                    plt_section = s;
                    *addr = s->sh_addr;
                    *offset = s->sh_offset;
                    *size = s->sh_size;
                    elf_debug("  address 0x%lx, offset 0x%lx, size 0x%lx\n", *addr, *offset, *size);
                } else if (s->sh_addr == plt_section->sh_addr + *size) {
                    *size += s->sh_size;
                    elf_debug("  size expanded to 0x%lx\n", *size);
                }
            }
            break;
        }
    }
    return (plt_section != 0);
  out_elf_fail:
    return false;
}

void walk_elf(buffer elf, range_handler rh)
{
    void *elf_end = buffer_ref(elf, buffer_length(elf));
    Elf64_Ehdr *e = buffer_ref(elf, 0);
    elf_debug("%s: buffer %p, handler %p (%F), buf [%p, %p)\n",
              func_ss, elf, rh, rh, e, elf_end);
    ELF_CHECK_PTR(e, Elf64_Ehdr);
    foreach_phdr(e, p) {
        ELF_CHECK_PTR(p, Elf64_Phdr);
        if (p->p_type == PT_LOAD) {
            range r = irangel(p->p_vaddr & (~MASK(PAGELOG)),
                pad(p->p_filesz + (p->p_vaddr & MASK(PAGELOG)), PAGESIZE));
            if (!apply(rh, r))
                return;
            if (p->p_memsz > range_span(r))
                if (!apply(rh, irangel(r.end, pad(p->p_memsz - range_span(r), PAGESIZE))))
                    return;
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
              func_ss, elf, load_offset, mapper, mapper, e, elf_end);
    ELF_CHECK_PTR(e, Elf64_Ehdr);
    foreach_phdr(e, p) {
        ELF_CHECK_PTR(p, Elf64_Phdr);
        if (p->p_type != PT_LOAD)
            continue;
        elf_debug("   PT_LOAD p_vaddr 0x%lx, p_offset 0x%lx, p_filesz 0x%lx\n",
                  p->p_vaddr, p->p_offset, p->p_filesz);
        /* determine access permissions */
        pageflags flags = pageflags_memory();
        if (p->p_flags & PF_X)
            flags = pageflags_exec(flags);
        if (p->p_flags & PF_W)
            flags = pageflags_writable(flags);
        if (p->p_memsz < p->p_filesz)
            halt("load_elf with p->p_memsz (%ld) < p->p_filesz (%ld)\n",
                 p->p_memsz, p->p_filesz);
        elf_debug("      apply mapper %F: vaddr 0x%lx, offset 0x%lx, "
                  "data size 0x%lx, bss size 0x%lx, flags 0x%lx\n",
                  mapper, p->p_vaddr + load_offset, p->p_offset, p->p_filesz,
                  p->p_memsz - p->p_filesz, flags);
        if (!apply(mapper, p->p_vaddr + load_offset, p->p_offset, p->p_filesz,
                   p->p_memsz - p->p_filesz, flags)) {
            msg_err("call to mapper %F failed (vaddr 0x%lx, offset 0x%lx, "
                    "data size 0x%lx, bss size 0x%lx, flags 0x%lx)\n",
                    mapper, p->p_vaddr + load_offset, p->p_offset, p->p_filesz,
                    p->p_memsz - p->p_filesz, flags);
            goto out_elf_fail;
        }
    }
    u64 entry = e->e_entry + load_offset;
    elf_debug("   done; entry 0x%lx\n", entry);
    return pointer_from_u64(entry);
  out_elf_fail:
    msg_err("failed to parse elf file, len %d; check file image consistency\n", buffer_length(elf));
    return INVALID_ADDRESS;
}

closure_function(5, 1, void, elf_load_program,
                 heap, h, Elf64_Phdr *, phdr, Elf64_Half, phnum, elf_loader, loader, status_handler, sh,
                 status s)
{
    heap h = bound(h);
    Elf64_Phdr *phdr = bound(phdr);
    Elf64_Half phnum = bound(phnum);
    status_handler sh = bound(sh);
    if (is_ok(s)) {
        merge m = allocate_merge(h, sh);
        assert(m != INVALID_ADDRESS);
        sh = apply_merge(m);
        for (int i = 0; i < phnum; i++) {
            Elf64_Phdr *p = &phdr[i];
            if ((p->p_type == PT_LOAD) && (p->p_filesz > 0)) {
                elf_debug("    PT_LOAD paddr 0x%lx, offset 0x%lx, filesz 0x%lx\n",
                          p->p_paddr, p->p_offset, p->p_filesz);
                apply(bound(loader), p->p_offset, p->p_filesz, pointer_from_u64(p->p_paddr),
                      apply_merge(m));
            }
        }
    }
    apply(sh, STATUS_OK);
    deallocate(bound(h), phdr, sizeof(Elf64_Phdr) * phnum);
    closure_finish();
}

closure_function(5, 1, void, elf_load_phdr,
                 heap, h, Elf64_Ehdr *, e, elf_loader, loader, u64 *, entry, status_handler, sh,
                 status s)
{
    heap h = bound(h);
    Elf64_Ehdr *e = bound(e);
    elf_loader loader = bound(loader);
    status_handler sh = bound(sh);
    if (is_ok(s)) {
        elf_debug("  %d program headers, entry %p\n", e->e_phnum, e->e_entry);
        *(bound(entry)) = e->e_entry;
        Elf64_Phdr *phdr = allocate(h, sizeof(Elf64_Phdr) * e->e_phnum);
        assert(phdr != INVALID_ADDRESS);
        status_handler load_program = closure(h, elf_load_program, h, phdr, e->e_phnum, loader, sh);
        assert(load_program != INVALID_ADDRESS);
        apply(loader, e->e_phoff, e->e_phentsize * e->e_phnum, phdr, load_program);
    } else {
        apply(sh, s);
    }
    deallocate(h, e, sizeof(Elf64_Ehdr));
    closure_finish();
}


void load_elf_to_physical(heap h, elf_loader loader, u64 *entry, status_handler sh)
{
    Elf64_Ehdr *e = allocate(h, sizeof(Elf64_Ehdr));
    assert(e != INVALID_ADDRESS);
    status_handler load_phdr = closure(h, elf_load_phdr, h, e, loader, entry, sh);
    assert(load_phdr != INVALID_ADDRESS);
    apply(loader, 0, sizeof(Elf64_Ehdr), e, load_phdr);
}
