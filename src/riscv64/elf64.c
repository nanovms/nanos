#include <kernel.h>
#include <elf64.h>

#define R_RISCV_64         2
#define R_RISCV_RELATIVE   3
#define R_RISCV_JUMP_SLOT  5

void elf_apply_relocate_add(buffer elf, Elf64_Shdr *s, u64 offset)
{
    Elf64_Rela *rel = buffer_ref(elf, s->sh_addr);
    for (int i = 0; i < s->sh_size / sizeof(*rel); i++) {
        void *loc = buffer_ref(elf, rel[i].r_offset);
        switch (ELF64_R_TYPE(rel[i].r_info)) {
        case R_RISCV_RELATIVE:
            *(u64 *)loc += offset + rel[i].r_addend;
            break;
        }
    }
}

boolean elf_apply_relocate_syms(buffer elf, Elf64_Shdr *s, elf_sym_relocator relocator)
{
    Elf64_Rela *rel = buffer_ref(elf, s->sh_addr);
    assert(sizeof(*rel) == s->sh_entsize);
    for (int i = 0; i < s->sh_size / sizeof(*rel); i++) {
        switch (ELF64_R_TYPE(rel[i].r_info)) {
        case R_RISCV_64:
        case R_RISCV_JUMP_SLOT:
            if (!apply(relocator, &rel[i]))
                return false;
            break;
        }
    }
    return true;
}

