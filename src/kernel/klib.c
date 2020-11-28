#include <kernel.h>
#include <elf64.h>
#include <pagecache.h>
#include <tfs.h>
#include <page.h>
#include <symtab.h>

//#define KLIB_DEBUG
#ifdef KLIB_DEBUG
#define klib_debug(x, ...) do {log_printf("KLIB", x, ##__VA_ARGS__);} while(0)
#else
#define klib_debug(x, ...)
#endif

static kernel_heaps klib_kh;
static filesystem klib_fs;
static tuple klib_root;
static table export_syms;
static id_heap klib_heap;

/* from linker script */
extern void *klib_syms_start;
extern void *klib_syms_end;

static void add_sym(void *syms, const char *s, void *p)
{
    table_set((table)syms, sym_this(s), p ? p : INVALID_ADDRESS); /* allow zero value */
}

static void *get_sym(const char *name)
{
    return table_find(export_syms, sym_this(name));
}

closure_function(1, 1, void, klib_elf_walk,
                 klib, kl,
                 range, r)
{
    klib kl = bound(kl);
    if (range_empty(kl->load_range)) {
        kl->load_range = r;
    } else {
        if (r.start < kl->load_range.start)
            kl->load_range.start = r.start;
        else if (r.end > kl->load_range.end)
            kl->load_range.end = r.end;
    }
    klib_debug("%s: kl %s, r %R, load_range %R\n", __func__, kl->name, r, kl->load_range);
}

closure_function(1, 4, void, klib_elf_map,
                 klib, kl,
                 u64, vaddr, u64, paddr, u64, size, u64, flags)
{
    klib kl = bound(kl);
    boolean is_bss = paddr == INVALID_PHYSICAL;
    if (is_bss) {
        paddr = allocate_u64((heap)heap_physical(klib_kh), size);
        assert(paddr != INVALID_PHYSICAL);
    }

    klib_mapping km = allocate(heap_general(klib_kh), sizeof(struct klib_mapping));
    assert(km != INVALID_ADDRESS);
    km->n.r = irangel(vaddr, size);
    km->phys = paddr;
    km->flags = flags;

    klib_debug("%s: kl %s, vaddr 0x%lx, paddr 0x%lx%s, size 0x%lx, flags 0x%lx\n",
               __func__, kl->name, vaddr, paddr, is_bss ? " (bss)" : "", size, flags);

    assert(rangemap_insert(kl->mappings, &km->n));
    map(vaddr, paddr, size, flags);
    if (is_bss)
        zero(pointer_from_u64(vaddr), size);
}

closure_function(2, 1, status, load_klib_complete,
                 const char *, name, klib_handler, complete,
                 buffer, b)
{
    heap h = heap_general(klib_kh);
    klib_handler complete = bound(complete);
    klib kl = allocate(h, sizeof(struct klib));
    assert(kl != INVALID_ADDRESS);

    kl->mappings = allocate_rangemap(h);
    assert(kl->mappings != INVALID_ADDRESS);

    int namelen = MIN(runtime_strlen(bound(name)), KLIB_MAX_NAME - 1);
    runtime_memcpy(kl->name, bound(name), namelen);
    kl->name[namelen] = '\0';
    kl->syms = allocate_table(h, key_from_symbol, pointer_equal);
    assert(kl->syms != INVALID_ADDRESS);
    kl->elf = b;

    klib_debug("%s: klib %p, read length %ld\n", __func__, kl, buffer_length(b));
    kl->load_range = irange(0, 0);
    walk_elf(b, stack_closure(klib_elf_walk, kl));
    u64 where = allocate_u64((heap)klib_heap, range_span(kl->load_range));
    assert(where != INVALID_PHYSICAL);
    kl->load_range = range_add(kl->load_range, where);

    klib_debug("   loading klib @ %R, resolving relocations\n", kl->load_range);
    elf_apply_relocs(b, where);

    klib_debug("   loading elf file\n");
    void *entry = load_elf(b, where, stack_closure(klib_elf_map, kl));
    assert(entry != INVALID_ADDRESS);

    klib_debug("   ingesting elf symbols for debug\n");
    add_elf_syms(b, where);

    klib_debug("   init entry @ %p, first word 0x%lx\n", entry, *(u64*)entry);
    klib_init ki = (klib_init)entry;
    int rv = ki(kl->syms, get_sym, add_sym);
    status s = rv == KLIB_INIT_OK ? STATUS_OK :
        timm("result", "module initialization failed with %d", rv);
    klib_debug("   init status %v, applying completion\n", s);
    apply(complete, kl, s);
    closure_finish();
    return STATUS_OK;
}

closure_function(1, 1, void, load_klib_failed,
                 klib_handler, complete,
                 status, s)
{
    klib_handler complete = bound(complete);
    klib_debug("%s: complete %p (%F), status %v\n", __func__, complete, complete, s);
    apply(complete, INVALID_ADDRESS, s);
    closure_finish();
}

void load_klib(const char *name, klib_handler complete)
{
    klib_debug("%s: \"%s\", complete %p (%F)\n", __func__, name, complete, complete);
    if (!klib_root || !klib_fs) {
        apply(complete, INVALID_ADDRESS, timm("result", "klib not initialized"));
        return;
    }
    heap h = heap_general(klib_kh);
    tuple md = resolve_path(klib_root, split(h, alloca_wrap_buffer(name, runtime_strlen(name)), '/'));
    if (!md) {
        apply(complete, INVALID_ADDRESS, timm("result", "unable to resolve module name \"%s\"", name));
    } else {
        filesystem_read_entire(klib_fs, md, heap_backed(klib_kh),
                               closure(h, load_klib_complete, name, complete),
                               closure(h, load_klib_failed, complete));
    }
}
KLIB_EXPORT(load_klib);

void *klib_sym(klib kl, symbol s)
{
    void *p = table_find(kl->syms, s);
    if (p == 0)
        return INVALID_ADDRESS;
    else if (p == INVALID_ADDRESS)
        return 0;
    else
        return p;
}
KLIB_EXPORT(klib_sym);

closure_function(1, 1, void, destruct_mapping,
                 klib, kl,
                 rmnode, n)
{
    klib_mapping km = (klib_mapping)n;
    klib_debug("   v %R, p 0x%lx, flags 0x%lx\n", km->n.r, km->phys, km->flags);
    unmap(km->n.r.start, range_span(km->n.r));
    deallocate(heap_general(klib_kh), km, sizeof(struct klib_mapping));
}

void unload_klib(klib kl)
{
    klib_debug("%s: kl %s\n", __func__, kl->name);
    heap h = heap_general(klib_kh);
    deallocate_rangemap(kl->mappings, stack_closure(destruct_mapping, kl));
    deallocate_u64((heap)klib_heap, kl->load_range.start, range_span(kl->load_range));
    deallocate_buffer(kl->elf);
    deallocate_table(kl->syms);
    deallocate(h, kl, sizeof(struct klib));
    klib_debug("   unload complete\n");
}

/* this should move to hypothetical in-kernel test / diag area */
closure_function(0, 2, void, klib_test_loaded,
                 klib, kl, status, s)
{
    if (!is_ok(s))
        halt("klib test load failed: %v\n", s);

    rprintf("%s: klib %s\n", __func__, kl->name);
    if (!is_ok(s))
        halt("   failed; status %v\n", s);
    if (klib_sym(kl, sym(bob)) != INVALID_ADDRESS)
        halt("%s: lookup of sym \"bob\" should have failed.\n", __func__);

    int (*foo)(int x) = klib_sym(kl, sym(foo));
    if (foo == INVALID_ADDRESS)
        halt("%s: sym \"foo\" not found\n", __func__);
    int r = foo(1);
    if (r != 124)
        halt("%s: foo call failed\n", __func__);
    if (klib_sym(kl, sym(bar)) != 0)
        halt("%s: sym \"bar\" should have 0 value\n", __func__);

    unload_klib(kl);
    rprintf("   klib test passed\n");
    closure_finish();
    return;
}

closure_function(0, 2, void, radar_loaded,
                 klib, kl, status, s)
{
    if (!is_ok(s))
        halt("Radar klib load failed: %v\n", s);
    closure_finish();
}

void init_klib(kernel_heaps kh, void *fs, tuple config_root, tuple klib_md)
{
    klib_debug("%s: fs %p, config_root %p, klib_md %p\n",
               __func__, fs, config_root, klib_md);
    assert(fs);
    assert(config_root);
    assert(klib_md);
    heap h = heap_general(kh);
    klib_kh = kh;
    klib_fs = (filesystem)fs;
    klib_root = klib_md;
    export_syms = allocate_table(h, key_from_symbol, pointer_equal);
    assert(export_syms != INVALID_ADDRESS);

    /* add exported symbols to table */
    for (export_sym s = (export_sym)&klib_syms_start; s < (export_sym)&klib_syms_end; s++) {
        klib_debug("   export \"%s\", v %p\n", s->name, s->v);
        table_set(export_syms, sym_this(s->name), s->v);
    }

    extern u8 END;
    u64 klib_heap_start = pad(u64_from_pointer(&END), PAGESIZE_2M);
    u64 klib_heap_size = KERNEL_LIMIT - klib_heap_start;
    klib_debug("%s: creating klib heap @ 0x%lx, size 0x%lx\n", __func__,
               klib_heap_start, klib_heap_size);
    klib_heap = create_id_heap(h, h, klib_heap_start, klib_heap_size, PAGESIZE, false);
    assert(klib_heap != INVALID_ADDRESS);
    if (table_find(config_root, sym(klib_test))) {
        klib_debug("   loading klib test\n");
        load_klib("/klib/test", closure(h, klib_test_loaded));
    }
    if (table_find(get_environment(), sym(RADAR_KEY)))
        load_klib("/klib/radar", closure(h, radar_loaded));
}
