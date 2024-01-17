void init_symtab(kernel_heaps kh);
boolean symtab_is_empty(void);
void *symtab_get_addr(sstring sym_name);
void symtab_remove_addrs(range r);
void add_elf_syms(buffer b, u64 load_offset);
sstring find_elf_sym(u64 a, u64 *offset, u64 *len);
void print_u64_with_sym(u64 a);
