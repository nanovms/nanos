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

boolean elf_apply_relocate_syms(buffer elf, Elf64_Rela *rel, int relcount,
                                elf_sym_relocator relocator)
{
    for (int i = 0; i < relcount; i++) {
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

void arch_elf_relocate(Elf64_Rela *rel, u64 relsz, Elf64_Sym *syms, u64 base, u64 offset)
{
    u64 *loc;
    u64 value;
    while (relsz > 0) {
        switch (ELF64_R_TYPE(rel->r_info)) {
        case R_RISCV_64:
            value = syms[ELF64_R_SYM(rel->r_info)].st_value;
            break;
        case R_RISCV_RELATIVE:
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
