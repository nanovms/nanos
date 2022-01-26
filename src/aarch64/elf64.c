#include <kernel.h>
#include <elf64.h>

#define R_AARCH64_GLOB_DAT   1025
#define R_AARCH64_JUMP_SLOT  1026
#define R_AARCH64_RELATIVE   1027

void elf_apply_relocate_add(buffer elf, Elf64_Shdr *s, u64 offset)
{
    Elf64_Rela *rel = buffer_ref(elf, s->sh_addr);
    for (int i = 0; i < s->sh_size / sizeof(*rel); i++) {
        void *loc = buffer_ref(elf, rel[i].r_offset);
        switch (ELF64_R_TYPE(rel[i].r_info)) {
        case R_AARCH64_RELATIVE:
            *(u64 *)loc += offset;
            break;
        }
    }
}

boolean elf_apply_relocate_syms(buffer elf, Elf64_Shdr *s, elf_sym_relocator relocator)
{
    Elf64_Rela *rel = buffer_ref(elf, s->sh_addr);
    for (int i = 0; i < s->sh_size / sizeof(*rel); i++) {
        switch (ELF64_R_TYPE(rel[i].r_info)) {
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_JUMP_SLOT:
            if (!apply(relocator, &rel[i]))
                return false;
            break;
        }
    }
    return true;
}

void elf_dyn_relocate(u64 base, Elf64_Dyn *dyn)
{
    Elf64_Rela *rel = 0;
    u64 relsz = 0, relent = 0;
    u64 *loc;
    int i;

    for (i = 0; dyn[i].d_tag != DT_NULL; ++i) {
        switch (dyn[i].d_tag) {
            case DT_RELA:
                rel = pointer_from_u64(dyn[i].d_un.d_ptr + base);
                break;
            case DT_RELASZ:
                relsz = dyn[i].d_un.d_val;
                break;
            case DT_RELAENT:
                relent = dyn[i].d_un.d_val;
                break;
            default:
                break;
        }
    }
    if (!rel || !relent)
        return;
    while (relsz > 0) {
        switch (ELF64_R_TYPE (rel->r_info)) {
            case R_AARCH64_RELATIVE:
                loc = pointer_from_u64(base + rel->r_offset);
                *loc = base + rel->r_addend;
                break;
            default:
                break;
        }
        rel = (Elf64_Rela *) ((void *)rel + relent);
        relsz -= relent;
    }
}
