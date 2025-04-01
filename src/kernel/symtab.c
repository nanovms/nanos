#include <kernel.h>
#include <elf64.h>

/* really this should be an instance... */
BSS_RO_AFTER_INIT static heap general;
BSS_RO_AFTER_INIT static rangemap elf_symtable;

typedef struct elfsym {
    struct rmnode node;
    sstring name;
} *elfsym;

static inline elfsym allocate_elfsym(range r, sstring name)
{
    elfsym es = mem_alloc(general, sizeof(struct elfsym), MEM_NOWAIT | MEM_NOFAIL);
    rmnode_init(&es->node, r);
    int bytes = name.len;
    es->name.ptr = mem_alloc(general, bytes, MEM_NOWAIT | MEM_NOFAIL);
    runtime_memcpy(es->name.ptr, name.ptr, bytes);
    es->name.len = bytes;
    return es;
}

static inline void deallocate_elfsym(elfsym es)
{
    deallocate(general, es->name.ptr, es->name.len);
    deallocate(general, es, sizeof(struct elfsym));
}

closure_function(1, 4, void, elf_symtable_add,
                 u64, load_offset,
                 sstring name, u64 a, u64 len, u8 info)
{
    int type = ELF64_ST_TYPE(info);

    /* store bind info? */
    if (a == 0 || len == 0 || sstring_is_empty(name) ||
	(type != STT_FUNC && type != STT_OBJECT))
	return;

    assert(elf_symtable);

    range r = irangel(a + bound(load_offset), len);
    boolean match = rangemap_range_intersects(elf_symtable, r);
    if (match) {
	msg_warn("%s: \"%s\" %R would overlap in rangemap; skipping", func_ss, name, r);
	return;
    }

    elfsym es = allocate_elfsym(r, name);
    if (!rangemap_insert(elf_symtable, &es->node)) {
        /* shouldn't ever happen, so bark if it does */
        msg_err("%s: unable to add symbol \"%s\" of range %R to map; skipping", func_ss,
                name, r);
    }
}

closure_func_basic(rmnode_handler, boolean, symtab_remove_sym,
                   rmnode n)
{
    elfsym sym = struct_from_field(n, elfsym, node);
    rangemap_remove_node(elf_symtable, n);
    deallocate_elfsym(sym);
    return true;
}

sstring find_elf_sym(u64 a, u64 *offset, u64 *len)
{
    if (!elf_symtable)
        return sstring_null();

    elfsym es = (elfsym)rangemap_lookup(elf_symtable, a);
    if (es == INVALID_ADDRESS)
        return sstring_null();
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
    sstring name;
    u64 offset, len;

    print_u64(a);

    name = find_elf_sym(a, &offset, &len);
    if (!sstring_is_null(name)) {
	rputs("\t(");
	rput_sstring(name);
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

void *symtab_get_addr(sstring sym_name)
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
    rangemap_range_lookup(elf_symtable, r, stack_closure_func(rmnode_handler, symtab_remove_sym));
}

void init_symtab(kernel_heaps kh)
{
    general = heap_locked(kh);
    elf_symtable = allocate_rangemap(heap_general(kh));
}
