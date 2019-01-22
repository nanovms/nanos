#include <runtime.h>
#include <region.h>
#include <elf64.h>

static heap general;
static rtrie elf_symtable;

CLOSURE_0_4(elf_symtable_add, void, char *, u64, u64, u8);
void elf_symtable_add(char * name, u64 a, u64 len, u8 info)
{
    int type = ELF64_ST_TYPE(info);

    /* store bind info? */
    if (a == 0 || len == 0 || !name || name[0] == '\0' ||
	(type != STT_FUNC && type != STT_OBJECT))
	return;

    assert(elf_symtable);

    char * m;
    if ((m = rtrie_lookup(elf_symtable, a, 0)) ||
	(m = rtrie_lookup(elf_symtable, a + len - 1, 0))) {
#ifdef ELF_SYMTAB_DEBUG
	rprintf("!!! %s (%P) exists in rtrie as \"%s\"; skipping\n",
		name, a, m);
#endif
	return;
    }

    rtrie_insert(elf_symtable, a, len, name);
}

char * find_elf_sym(u64 a, u64 *offset, u64 *len)
{
    if (!elf_symtable)
        return 0;

    range r;
    char * m = rtrie_lookup(elf_symtable, a, &r);
    if (!m)
        return 0;

    if (offset)
        *offset = a - r.start;

    if (len)
        *len = r.end - r.start;

    return m;
}

void add_elf_syms(buffer b)
{
    if (elf_symtable)
	elf_symbols(b, closure(general, elf_symtable_add));
    else
	console("can't add ELF symbols; symtab not initialized\n");
}

void init_symtab(kernel_heaps kh)
{
    general = heap_general(kh);
    elf_symtable = allocate_rtrie(general);
}
