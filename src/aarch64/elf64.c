#include <kernel.h>
#include <elf64.h>

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
