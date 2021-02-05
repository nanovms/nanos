void init_symtab(kernel_heaps kh);
void add_elf_syms(buffer b, u64 load_offset);
char * find_elf_sym(u64 a, u64 *offset, u64 *len);
void print_u64_with_sym(u64 a);
