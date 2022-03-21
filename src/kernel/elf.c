#include <kernel.h>
#include <elf64.h>

//#define ELF_DEBUG
#ifdef ELF_DEBUG
#ifdef KERNEL
#define elf_debug(x, ...) do {tprintf(sym(elf), 0, x, ##__VA_ARGS__);} while(0)
#else
#define elf_debug(x, ...) do {rprintf(" ELF: " x, ##__VA_ARGS__);} while(0)
#endif
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

closure_function(6, 1, boolean, elf_sym_relocate,
                 buffer, elf, void *, load_addr, Elf64_Sym *, syms, u64, sym_count, Elf64_Shdr *, strtab, elf_sym_resolver, resolver,
                 Elf64_Rela *, rel)
{
    u64 sym_index = ELF64_R_SYM(rel->r_info);
    const char *sym_name;
    if (sym_index < bound(sym_count))
        sym_name = elf_string(bound(elf), bound(strtab), bound(syms)[sym_index].st_name);
    else
        sym_name = 0;
    if (!sym_name)
        return false;
    void *sym_addr = apply(bound(resolver), sym_name);
    if (sym_addr == INVALID_ADDRESS)
        return false;
    u64 *target = bound(load_addr) + rel->r_offset;
    *target = u64_from_pointer(sym_addr);
    return true;
}

boolean elf_dyn_link(buffer elf, void *load_addr, elf_sym_resolver resolver)
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
            reltab_offset = dyn->d_un.d_ptr;
            break;
        }
        dyn++;
    }
    if (!symtab_offset || !strtab_offset || !reltab_offset)
        return true;

    /* Look for the section headers of the tables referenced in the dynamic section */
    Elf64_Shdr *symtab = 0, *strtab = 0, *reltab = 0;
    foreach_shdr(e, s) {
        switch (s->sh_type) {
        case SHT_DYNSYM:
            if (s->sh_offset == symtab_offset)
                symtab = s;
            break;
        case SHT_STRTAB:
            if (s->sh_offset == strtab_offset)
                strtab = s;
            break;
        case SHT_RELA:
            if (s->sh_offset == reltab_offset)
                reltab = s;
            break;
        }
    }
    if (!symtab || !strtab || !reltab)
        goto out_elf_fail;

    ELF_CHECK_PTR(symtab, Elf64_Shdr);
    ELF_CHECK_PTR(strtab, Elf64_Shdr);
    ELF_CHECK_PTR(reltab, Elf64_Shdr);
    return elf_apply_relocate_syms(elf, reltab,
                                   stack_closure(elf_sym_relocate, elf, load_addr,
                                                 buffer_ref(elf, symtab_offset),
                                                 symtab->sh_size / symtab->sh_entsize, strtab,
                                                 resolver));
  out_elf_fail:
    msg_err("failed to parse elf, len %d\n", buffer_length(elf));
    return false;
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

closure_function(5, 1, void, elf_load_program,
                 heap, h, Elf64_Phdr *, phdr, Elf64_Half, phnum, elf_loader, loader, status_handler, sh,
                 status, s)
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
                 status, s)
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
