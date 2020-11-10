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
