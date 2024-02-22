#include <kernel.h>
#include <elf64.h>

#define R_X86_64_NONE       0
#define R_X86_64_64         1
#define R_X86_64_PC32       2
#define R_X86_64_GOT32      3
#define R_X86_64_PLT32      4
#define R_X86_64_COPY       5
#define R_X86_64_GLOB_DAT   6
#define R_X86_64_JUMP_SLOT  7
#define R_X86_64_RELATIVE   8

void elf_apply_relocate_add(buffer elf, Elf64_Shdr *s, u64 offset)
{
    Elf64_Rela *rel = buffer_ref(elf, s->sh_addr);
    for (int i = 0; i < s->sh_size / sizeof(*rel); i++) {
        void *loc = buffer_ref(elf, rel[i].r_offset);
        switch (ELF64_R_TYPE(rel[i].r_info)) {
        case R_X86_64_RELATIVE:
            *(u64 *)loc += offset;
            break;
        }
    }
}

boolean elf_apply_relocate_syms(buffer elf, Elf64_Rela *rel, int relcount,
                                elf_sym_relocator relocator)
{
    for (int i = 0; i < relcount; i++) {
        switch (ELF64_R_TYPE(rel[i].r_info)) {
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            if (!apply(relocator, &rel[i]))
                return false;
            break;
        }
    }
    return true;
}

void arch_elf_relocate(Elf64_Rela *rel, u64 relsz, Elf64_Sym *syms, u64 base, u64 offset)
{
    u64 *loc;
    u64 value;
    while (relsz > 0) {
        switch (ELF64_R_TYPE (rel->r_info)) {
        case R_X86_64_RELATIVE:
            value = 0;
            break;
        default:
            goto next;
        }
        loc = pointer_from_u64(base + rel->r_offset);
        *loc = value + rel->r_addend + offset;
next:
        rel++;
        relsz -= sizeof(*rel);
    }
}
