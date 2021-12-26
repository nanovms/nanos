#include <kernel.h>
#include <elf64.h>

/* really this should be an instance... */
BSS_RO_AFTER_INIT static heap general;
BSS_RO_AFTER_INIT static rangemap elf_symtable;

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

static inline void deallocate_elfsym(elfsym es)
{
    deallocate(general, es->name, runtime_strlen(es->name) + 1);
    deallocate(general, es, sizeof(struct elfsym));
}

closure_function(1, 4, void, elf_symtable_add,
                 u64, load_offset,
                 char *, name, u64, a, u64, len, u8, info)
{
    int type = ELF64_ST_TYPE(info);

    /* store bind info? */
    if (a == 0 || len == 0 || !name || name[0] == '\0' ||
	(type != STT_FUNC && type != STT_OBJECT))
	return;

    assert(elf_symtable);

    range r = irangel(a + bound(load_offset), len);
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

closure_function(0, 1, void, symtab_remove_sym,
                 rmnode, n)
{
    elfsym sym = struct_from_field(n, elfsym, node);
    rangemap_remove_node(elf_symtable, n);
    deallocate_elfsym(sym);
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

void add_elf_syms(buffer b, u64 load_offset)
{
    if (elf_symtable)
	elf_symbols(b, stack_closure(elf_symtable_add, load_offset));
    else
	rputs("can't add ELF symbols; symtab not initialized\n");
}

void print_u64_with_sym(u64 a)
{
    char * name;
    u64 offset, len;

    print_u64(a);

    name = find_elf_sym(a, &offset, &len);
    if (name) {
	rputs("\t(");
	rputs(name);
	rputs(" + ");
	print_u64(offset);
        rputs("/");
        print_u64(len);
	rputs(")");
    }
}

boolean symtab_is_empty(void)
{
    return (rangemap_first_node(elf_symtable) == INVALID_ADDRESS);
}

void *symtab_get_addr(const char *sym_name)
{
    rangemap_foreach(elf_symtable, n) {
        elfsym sym = struct_from_field(n, elfsym, node);
        if (!runtime_strcmp(sym->name, sym_name))
            return pointer_from_u64(sym->node.r.start);
    }
    return INVALID_ADDRESS;
}

void symtab_remove_addrs(range r)
{
    rangemap_range_lookup(elf_symtable, r, stack_closure(symtab_remove_sym));
}

void init_symtab(kernel_heaps kh)
{
    general = heap_locked(kh);
    elf_symtable = allocate_rangemap(heap_general(kh));
}
