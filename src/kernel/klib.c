#include <kernel.h>
#include <elf64.h>
#include <pagecache.h>
#include <tfs.h>
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
static table klib_syms;
static id_heap klib_heap;

/* from linker script */
extern void *klib_syms_start;
extern void *klib_syms_end;

static void add_sym(void *syms, const char *s, void *p)
{
    symbol sy = sym_this(s);
    void *value = (p ? p : INVALID_ADDRESS);    /* allow zero value */
    table_set((table)syms, sy, value);
    table_set(klib_syms, sy, value);
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

closure_function(1, 4, u64, klib_elf_map,
                 klib, kl,
                 u64, vaddr, u64, paddr, u64, size, pageflags, flags)
{
    klib kl = bound(kl);
    boolean is_bss = paddr == INVALID_PHYSICAL;
    if (is_bss) {
        paddr = allocate_u64((heap)heap_physical(klib_kh), size);
        assert(paddr != INVALID_PHYSICAL);
    }

    klib_mapping km = allocate(heap_locked(klib_kh), sizeof(struct klib_mapping));
    assert(km != INVALID_ADDRESS);
    km->n.r = irangel(vaddr, size);
    km->phys = paddr;
    km->flags = flags;

    klib_debug("%s: kl %s, vaddr 0x%lx, paddr 0x%lx%s, size 0x%lx, flags 0x%lx\n",
               __func__, kl->name, vaddr, paddr, is_bss ? " (bss)" : "", size, flags.w);

    assert(rangemap_insert(kl->mappings, &km->n));
    map(vaddr, paddr, size, flags);
    if (is_bss)
        zero(pointer_from_u64(vaddr), size);
    return vaddr;
}

closure_function(3, 1, status, load_klib_complete,
                 const char *, name, klib_handler, complete, status_handler, sh,
                 buffer, b)
{
    heap h = heap_locked(klib_kh);
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
    kl->ki = (klib_init)entry;
    int rv = kl->ki(kl->syms, get_sym, add_sym, bound(sh));
    klib_debug("   init return value %d, applying completion\n", rv);
    apply(complete, kl, rv);
    closure_finish();
    return STATUS_OK;
}

closure_function(1, 1, void, load_klib_failed,
                 klib_handler, complete,
                 status, s)
{
    klib_handler complete = bound(complete);
    klib_debug("%s: complete %p (%F), status %v\n", __func__, complete, complete, s);
    timm_dealloc(s);
    apply(complete, INVALID_ADDRESS, KLIB_LOAD_FAILED);
    closure_finish();
}

void load_klib(const char *name, klib_handler complete, status_handler sh)
{
    klib_debug("%s: \"%s\", complete %p (%F)\n", __func__, name, complete, complete);
    assert(klib_root && klib_fs);
    heap h = heap_locked(klib_kh);
    tuple md = resolve_path(klib_root, split(h, alloca_wrap_buffer(name, runtime_strlen(name)), '/'));
    if (!md) {
        apply(complete, INVALID_ADDRESS, KLIB_LOAD_FAILED);
    } else {
        filesystem_read_entire(klib_fs, md, (heap)heap_page_backed(klib_kh),
                               closure(h, load_klib_complete, name, complete, sh),
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

void *get_klib_sym(const char *name)
{
    void *p = table_find(klib_syms, sym_this(name));
    if (p == 0)
        return INVALID_ADDRESS;
    else if (p == INVALID_ADDRESS)
        return 0;
    else
        return p;
}
KLIB_EXPORT(get_klib_sym);

closure_function(1, 1, void, destruct_mapping,
                 klib, kl,
                 rmnode, n)
{
    klib_mapping km = (klib_mapping)n;
    klib_debug("   v %R, p 0x%lx, flags 0x%lx\n", km->n.r, km->phys, km->flags.w);
    unmap(km->n.r.start, range_span(km->n.r));
    deallocate(heap_locked(klib_kh), km, sizeof(struct klib_mapping));
}

void unload_klib(klib kl)
{
    klib_debug("%s: kl %s\n", __func__, kl->name);
    heap h = heap_locked(klib_kh);
    deallocate_rangemap(kl->mappings, stack_closure(destruct_mapping, kl));
    deallocate_u64((heap)klib_heap, kl->load_range.start, range_span(kl->load_range));
    deallocate_buffer(kl->elf);
    table_foreach(kl->syms, s, v) {
        table_set(klib_syms, s, 0);
    }
    deallocate_table(kl->syms);
    deallocate(h, kl, sizeof(struct klib));
    klib_debug("   unload complete\n");
}

/* this should move to hypothetical in-kernel test / diag area */
closure_function(0, 2, void, klib_test_loaded,
                 klib, kl, int, rv)
{
    if (rv != KLIB_INIT_OK)
        halt("klib test load failed (%d)\n", rv);

    rprintf("%s: klib %s\n", __func__, kl->name);
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

closure_function(3, 1, void, klibs_complete,
                 u64, pending, queue, retry_klibs, status_handler, complete,
                 status, s)
{
    queue retry_klibs = bound(retry_klibs);
    if (!queue_empty(retry_klibs))
        halt("missing klib dependencies\n");
    deallocate_queue(retry_klibs);
    apply(bound(complete), s);
    closure_finish();
}

closure_function(4, 2, void, autoload_klib_complete,
                 u64 *, pending, queue, retry_klibs, status_handler, sh, klib, kl,
                 klib, kl, int, rv)
{
    u64 pending = fetch_and_add(bound(pending), -1);
    queue retry_klibs = bound(retry_klibs);
    switch (rv) {
    case KLIB_INIT_IN_PROGRESS:
    case KLIB_INIT_OK: {
        /* Retry initialization of klibs with missing dependencies. */
        u64 qlen = queue_length(retry_klibs);
        for (u64 retry_count = 0; retry_count < qlen; retry_count++) {
            klib_handler retry = dequeue(retry_klibs);
            if (retry == INVALID_ADDRESS)
                break;
            fetch_and_add(bound(pending), 1);
            kl =  closure_member(autoload_klib_complete, retry, kl);
            apply(retry, kl, kl->ki(kl->syms, get_sym, add_sym, bound(sh)));
        }
        break;
    }
    case KLIB_MISSING_DEP:
        bound(kl) = kl;
        assert(enqueue(retry_klibs, closure_self()));
        if (pending > 1)
            /* Missing dependencies could be satisfied by pending klibs. */
            return;
        break;
    default:
        halt("klib automatic load failed (%d)\n", rv);
    }
    if (rv != KLIB_INIT_IN_PROGRESS)
        apply(bound(sh), STATUS_OK);
    closure_finish();
}

closure_function(3, 2, boolean, autoload_klib_each,
                 u64 *, pending, queue, retry_klibs, merge, m,
                 value, s, value, v)
{
    if (!is_dir(v)) {
        fetch_and_add(bound(pending), 1);
        status_handler sh = apply_merge(bound(m));
        heap h = heap_locked(klib_kh);
        klib_handler kl_complete = closure(h, autoload_klib_complete, bound(pending),
            bound(retry_klibs), sh, 0);
        assert(kl_complete != INVALID_ADDRESS);
        filesystem_read_entire(klib_fs, v, (heap)heap_linear_backed(klib_kh),
                               closure(h, load_klib_complete, "auto", kl_complete, sh),
                               closure(h, load_klib_failed, kl_complete));
    }
    return true;
}

void init_klib(kernel_heaps kh, void *fs, tuple config_root, tuple klib_md, status_handler complete)
{
    klib_debug("%s: fs %p, config_root %p, klib_md %p\n",
               __func__, fs, config_root, klib_md);
    assert(fs);
    assert(config_root);
    assert(klib_md);
    heap h = heap_locked(kh);
    klib_kh = kh;
    klib_fs = (filesystem)fs;
    export_syms = allocate_table(h, key_from_symbol, pointer_equal);
    assert(export_syms != INVALID_ADDRESS);
    klib_syms = allocate_table(h, key_from_symbol, pointer_equal);
    assert(klib_syms != INVALID_ADDRESS);

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
    klib_heap = create_id_heap(h, h, klib_heap_start, klib_heap_size, PAGESIZE, true);
    assert(klib_heap != INVALID_ADDRESS);
    tuple c = get_tuple(klib_md, sym(children));
    if (!c)
        goto done;
    klib_root = get_tuple(c, sym(klib));
    if (!klib_root)
        goto done;
    if (get(config_root, sym(klib_test))) {
        klib_debug("   loading klib test\n");
        load_klib("test/test", closure(h, klib_test_loaded), 0);
    }
    c = get_tuple(klib_root, sym(children));
    if (c) {
        queue retry_klibs = allocate_queue(h, tuple_count(c));
        assert(retry_klibs != INVALID_ADDRESS);
        status_handler kl_complete = closure(h, klibs_complete, 0, retry_klibs, complete);
        assert(kl_complete != INVALID_ADDRESS);
        merge m = allocate_merge(h, kl_complete);
        complete = apply_merge(m);
        iterate(c, stack_closure(autoload_klib_each,
            &closure_member(klibs_complete, kl_complete, pending), retry_klibs, m));
    }
  done:
    apply(complete, STATUS_OK);
}
