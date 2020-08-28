#include <kernel.h>
#include <elf64.h>

/* really this should be an instance... */
static heap general;
static rangemap elf_symtable;

typedef struct elfsym {
    struct rmnode node;
    char * name;
} *elfsym;

static inline elfsym allocate_elfsym(range r, char * name)
{
    elfsym es = allocate(general, sizeof(struct elfsym));
    assert(es != INVALID_ADDRESS);
    rmnode_init(&es->node, r);
    int bytes = runtime_strlen(name) + 1;
    es->name = allocate(general, bytes);
    assert(es->name != INVALID_ADDRESS);
    runtime_memcpy(es->name, name, bytes);
    return es;
}

closure_function(0, 4, void, elf_symtable_add,
                 char *, name, u64, a, u64, len, u8, info)
{
    int type = ELF64_ST_TYPE(info);

    /* store bind info? */
    if (a == 0 || len == 0 || !name || name[0] == '\0' ||
	(type != STT_FUNC && type != STT_OBJECT))
	return;

    assert(elf_symtable);

    range r = irange(a, a + len);
    boolean match = rangemap_range_intersects(elf_symtable, r);
    if (match) {
#ifdef ELF_SYMTAB_DEBUG
	msg_err("\"%s\" %R would overlap in rangemap; skipping\n", name, r);
#endif
	return;
    }

    elfsym es = allocate_elfsym(r, name);
    if (!rangemap_insert(elf_symtable, &es->node)) {
        /* shouldn't ever happen, so bark if it does */
        msg_err("unable to add symbol \"%s\" of range %R to map; skipping\n",
                name, r);
    }
}

char * find_elf_sym(u64 a, u64 *offset, u64 *len)
{
    if (!elf_symtable)
        return 0;

    elfsym es = (elfsym)rangemap_lookup(elf_symtable, a);
    if (es == INVALID_ADDRESS)
        return 0;
    range r = range_from_rmnode(&es->node);

    if (offset)
        *offset = a - r.start;

    if (len)
        *len = r.end - r.start;

    return es->name;
}

void add_elf_syms(buffer b)
{
    if (elf_symtable)
	elf_symbols(b, stack_closure(elf_symtable_add));
    else
	console("can't add ELF symbols; symtab not initialized\n");
}

void print_u64_with_sym(u64 a)
{
    char * name;
    u64 offset, len;

    print_u64(a);

    name = find_elf_sym(a, &offset, &len);
    if (name) {
	console("\t(");
	console(name);
	console(" + ");
	print_u64(offset);
        console("/");
        print_u64(len);
	console(")");
    }
}

void init_symtab(kernel_heaps kh)
{
    general = heap_general(kh);
    elf_symtable = allocate_rangemap(general);
}
