#include <kernel.h>
#include <elf64.h>
#include <pagecache.h>
#include <tfs.h>
#include <symtab.h>

//#define KLIB_DEBUG
#ifdef KLIB_DEBUG
#define klib_debug(x, ...) do {tprintf(sym(klib), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define klib_debug(x, ...)
#endif

typedef struct klib_autoload {
    struct list retry_klibs;
    closure_struct(status_handler, kl_complete);
    status_handler complete;
    struct spinlock lock;
    int pending;
} *klib_autoload;

BSS_RO_AFTER_INIT static kernel_heaps klib_kh;
BSS_RO_AFTER_INIT static filesystem klib_fs;
BSS_RO_AFTER_INIT static tuple klib_root;
BSS_RO_AFTER_INIT static vector klib_loaded;

static void klib_missing_deps(klib_autoload autoload);

closure_function(1, 1, boolean, klib_elf_walk,
                 klib, kl,
                 range r)
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
    klib_debug("%s: kl %b, r %R, load_range %R\n", func_ss, kl->name, r, kl->load_range);
    return true;
}

static klib_mapping add_klib_mapping(klib kl, u64 vaddr, u64 paddr, u64 size, pageflags flags)
{
    klib_mapping km = allocate(heap_locked(klib_kh), sizeof(struct klib_mapping));
    if (km == INVALID_ADDRESS)
        return km;
    km->n.r = irangel(vaddr, size);
    km->phys = paddr;
    km->flags = flags;
    klib_debug("%s: vaddr 0x%lx, paddr 0x%lx, size 0x%lx, flags 0x%lx\n",
               func_ss, vaddr, paddr, size, flags.w);
    assert(rangemap_insert(kl->mappings, &km->n));
    map(vaddr, paddr, size, flags);
    return km;
}

closure_function(2, 5, boolean, klib_elf_map,
                 klib, kl, buffer, b,
                 u64 vaddr, u64 offset, u64 data_size, u64 bss_size, pageflags flags)
{
    klib kl = bound(kl);
    klib_debug("%s: kl %b, vaddr 0x%lx, offset 0x%lx, data_size 0x%lx, bss_size 0x%lx, flags 0x%lx\n",
               func_ss, kl->name, vaddr, offset, data_size, bss_size, flags);
    u64 map_start = vaddr & ~PAGEMASK;
    data_size += vaddr & PAGEMASK;

    u64 tail_copy = bss_size > 0 ? data_size & PAGEMASK : 0;
    if (tail_copy > 0)
        data_size -= tail_copy;
    else
        data_size = pad(data_size, PAGESIZE);

    offset &= ~PAGEMASK;
    if (data_size > 0) {
        u64 paddr = physical_from_virtual(buffer_ref(bound(b), offset));
        if (add_klib_mapping(kl, map_start, paddr, data_size, flags) == INVALID_ADDRESS)
            goto alloc_fail;
        map_start += data_size;
    }
    if (bss_size > 0) {
        u64 maplen = pad(bss_size + tail_copy, PAGESIZE);
        u64 paddr = allocate_u64((heap)heap_physical(klib_kh), maplen);
        if (paddr == INVALID_PHYSICAL)
            goto alloc_fail;
        if (add_klib_mapping(kl, map_start, paddr, maplen, flags) == INVALID_ADDRESS)
            goto alloc_fail;
        if (tail_copy > 0) {
            void *src = buffer_ref(bound(b), offset + data_size);
            klib_debug("   tail copy at 0x%lx, %ld bytes, offset 0x%lx, from %p\n",
                       map_start, tail_copy, data_size, src);
            runtime_memcpy(pointer_from_u64(map_start), src, tail_copy);
        }
        klib_debug("   zero at 0x%lx, len 0x%lx\n", map_start + tail_copy, maplen - tail_copy);
        zero(pointer_from_u64(map_start + tail_copy), maplen - tail_copy);
    }
    return true;
  alloc_fail:
    msg_err("%s: failed to allocate mapping", func_ss);
    return false;
}

closure_func_basic(elf_sym_resolver, void *, klib_sym_resolve,
                   sstring name)
{
    return symtab_get_addr(name);
}

static int klib_initialize(klib kl, status_handler sh)
{
    if (elf_dyn_link(kl->elf, pointer_from_u64(kl->load_range.start),
                     stack_closure_func(elf_sym_resolver, klib_sym_resolve)))
        return kl->ki(sh);
    else
        return KLIB_MISSING_DEP;
}

closure_function(3, 1, status, load_klib_complete,
                 buffer, name, klib_handler, complete, status_handler, sh,
                 buffer b)
{
    heap h = heap_locked(klib_kh);
    klib_handler complete = bound(complete);
    klib kl = allocate(h, sizeof(struct klib));
    assert(kl != INVALID_ADDRESS);

    kl->mappings = allocate_rangemap(h);
    assert(kl->mappings != INVALID_ADDRESS);

    kl->name = clone_buffer(h, bound(name));
    kl->elf = b;

    klib_debug("%s: klib %b, read length %ld\n", func_ss, kl->name, buffer_length(b));
    kl->load_range = irange(0, 0);
    walk_elf(b, stack_closure(klib_elf_walk, kl));
    u64 where = allocate_u64(kas_heap, range_span(kl->load_range));
    assert(where != INVALID_PHYSICAL);
    kl->load_range = range_add(kl->load_range, where);

    klib_debug("   loading klib @ %R, resolving relocations\n", kl->load_range);
    elf_apply_relocs(b, where);

    klib_debug("   loading elf file\n");
    void *entry = load_elf(b, where, stack_closure(klib_elf_map, kl, b));
    assert(entry != INVALID_ADDRESS);

    klib_debug("   init entry @ %p, first word 0x%lx\n", entry, *(u64*)entry);
    kl->ki = (klib_init)entry;
    int rv = klib_initialize(kl, bound(sh));
    klib_debug("   init return value %d, applying completion\n", rv);
    apply(complete, kl, rv);
    closure_finish();
    return STATUS_OK;
}

closure_function(1, 1, void, load_klib_failed,
                 klib_handler, complete,
                 status s)
{
    klib_handler complete = bound(complete);
    klib_debug("%s: complete %p (%F), status %v\n", func_ss, complete, complete, s);
    timm_dealloc(s);
    apply(complete, INVALID_ADDRESS, KLIB_LOAD_FAILED);
    closure_finish();
}

void load_klib(buffer name, klib_handler complete, status_handler sh)
{
    klib_debug("%s: \"%s\", complete %p (%F)\n", func_ss, name, complete, complete);
    assert(klib_root && klib_fs);
    heap h = heap_locked(klib_kh);
    tuple md = resolve_path(klib_root, split(h, name, '/'));
    if (!md) {
        apply(complete, INVALID_ADDRESS, KLIB_LOAD_FAILED);
    } else {
        filesystem_read_entire(klib_fs, md, (heap)heap_page_backed(klib_kh),
                               closure(h, load_klib_complete, name, complete, sh),
                               closure(h, load_klib_failed, complete));
    }
}

closure_function(1, 1, boolean, destruct_mapping,
                 klib, kl,
                 rmnode n)
{
    klib_mapping km = (klib_mapping)n;
    klib_debug("   v %R, p 0x%lx, flags 0x%lx\n", km->n.r, km->phys, km->flags.w);
    unmap(km->n.r.start, range_span(km->n.r));
    deallocate(heap_locked(klib_kh), km, sizeof(struct klib_mapping));
    return true;
}

void unload_klib(klib kl)
{
    klib_debug("%s: kl %b\n", func_ss, kl->name);
    heap h = heap_locked(klib_kh);
    deallocate_rangemap(kl->mappings, stack_closure(destruct_mapping, kl));
    deallocate_u64(kas_heap, kl->load_range.start, range_span(kl->load_range));
    deallocate_buffer(kl->elf);
    symtab_remove_addrs(kl->load_range);
    deallocate(h, kl, sizeof(struct klib));
    klib_debug("   unload complete\n");
}

closure_func_basic(status_handler, void, klibs_complete,
                   status s)
{
    klib_autoload autoload = struct_from_closure(klib_autoload, kl_complete);
    apply(autoload->complete, s);
    deallocate(heap_locked(klib_kh), autoload, sizeof(*autoload));
}

closure_function(4, 2, void, autoload_klib_complete,
                 klib_autoload, autoload, status_handler, sh, klib, kl, struct list, l,
                 klib kl, int rv)
{
    klib_autoload autoload = bound(autoload);
    list retry_klibs = &autoload->retry_klibs;
    status s;
    switch (rv) {
    case KLIB_INIT_IN_PROGRESS:
    case KLIB_INIT_OK: {
        spin_lock(&autoload->lock);
        autoload->pending--;
        klib_debug("%p: ingesting elf symbols\n", kl);
        add_elf_syms(kl->elf, kl->load_range.start);
        vector_push(klib_loaded, kl);

        /* Retry initialization of klibs with missing dependencies. */
        klib_handler retry;
        int retry_rv = KLIB_MISSING_DEP;
        list_foreach(retry_klibs, elem) {
            retry = (klib_handler)struct_from_field(elem,
                                                    closure_struct_type(autoload_klib_complete) *,
                                                    l);
            kl =  closure_member(autoload_klib_complete, retry, kl);
            status_handler sh = closure_member(autoload_klib_complete, retry, sh);
            retry_rv = klib_initialize(kl, sh);
            if (retry_rv != KLIB_MISSING_DEP) {
                list_delete(elem);
                break;
            }
        }
        if (retry_rv != KLIB_MISSING_DEP) {
            autoload->pending++;
            spin_unlock(&autoload->lock);
            apply(retry, kl, retry_rv);
        } else if (!autoload->pending) {
            spin_unlock(&autoload->lock);
            klib_missing_deps(autoload);
        } else {
            spin_unlock(&autoload->lock);
        }
        s = STATUS_OK;
        break;
    }
    case KLIB_MISSING_DEP:
        bound(kl) = kl;
        spin_lock(&autoload->lock);
        if (autoload->pending-- > 1) {
            /* Missing dependencies could be satisfied by pending klibs. */
            list_push_back(retry_klibs, &bound(l));
            s = STATUS_OK;
        } else {
            s = timm("result", "missing dependencies for %b klib", kl->name);
        }
        spin_unlock(&autoload->lock);
        if (s == STATUS_OK)
            return;
        klib_missing_deps(autoload);
        break;
    default:
        halt("klib automatic load failed (%d)\n", rv);
    }
    if (rv != KLIB_INIT_IN_PROGRESS)
        apply(bound(sh), s);
    closure_finish();
}

closure_function(2, 2, boolean, autoload_klib_each,
                 klib_autoload, autoload, merge, m,
                 value s, value v)
{
    if (!is_dir(v)) {
        klib_autoload autoload = bound(autoload);
        autoload->pending++;
        status_handler sh = apply_merge(bound(m));
        struct list elem;
        list_init_member(&elem);
        heap h = heap_locked(klib_kh);
        klib_handler kl_complete = closure(h, autoload_klib_complete, autoload, sh, 0, elem);
        assert(kl_complete != INVALID_ADDRESS);
        filesystem_read_entire(klib_fs, v, (heap)heap_page_backed(klib_kh),
                               closure(h, load_klib_complete, symbol_string(s), kl_complete, sh),
                               closure(h, load_klib_failed, kl_complete));
    }
    return true;
}

/* Called when loaded klibs with missing dependencies cannot have their dependencies satisfied. */
static void klib_missing_deps(klib_autoload autoload)
{
    list_foreach(&autoload->retry_klibs, elem) {
        klib_handler retry = (klib_handler)struct_from_field(elem,
            closure_struct_type(autoload_klib_complete) *, l);
        klib kl = closure_member(autoload_klib_complete, retry, kl);
        status_handler sh = closure_member(autoload_klib_complete, retry, sh);
        apply(sh, timm("result", "missing dependencies for %b klib", kl->name));
        deallocate_closure(retry);
    }
}

void print_loaded_klibs(void)
{
    klib kl;
    rputs("\nloaded klibs: ");
    if (klib_loaded) {
        vector_foreach(klib_loaded, kl) {
            buffer_print(kl->name);
            rputs("@0x");
            print_u64(kl->load_range.start);
            rputs("/0x");
            buffer r = little_stack_buffer(16);
            print_number(r, range_span(kl->load_range), 16, 0, false);
            buffer_print(r);
            rputs(" ");
        }
    }
    rputs("\n");
}

void init_klib(kernel_heaps kh, void *fs, tuple config_root, status_handler complete)
{
    assert(fs);
    assert(config_root);
    tuple klib_md = filesystem_getroot(fs);
    assert(klib_md);
    klib_debug("%s: fs %p, config_root %p, klib_md %p\n",
               func_ss, fs, config_root, klib_md);
    heap h = heap_locked(kh);
    klib_kh = kh;
    klib_fs = (filesystem)fs;
    klib_loaded = allocate_vector(h, 4);
    assert(klib_loaded != INVALID_ADDRESS);

    tuple c = get_tuple(klib_md, sym(children));
    if (!c)
        goto done;
    klib_root = get_tuple(c, sym(klib));
    if (!klib_root)
        goto done;
    c = children(klib_root);
    if (get(config_root, sym(klib_test))) {
        klib_debug("   loading in-kernel tests\n");
        assert(c);
        tuple test_dir = get(c, sym(test));
        assert(test_dir);
        c = children(test_dir);
    }
    if (c) {
        klib_autoload autoload = allocate(h, sizeof(*autoload));
        assert(autoload != INVALID_ADDRESS);
        list_init(&autoload->retry_klibs);
        status_handler kl_complete = init_closure_func(&autoload->kl_complete, status_handler,
                                                       klibs_complete);
        autoload->complete = complete;
        spin_lock_init(&autoload->lock);
        autoload->pending = 0;
        merge m = allocate_merge(h, kl_complete);
        complete = apply_merge(m);
        iterate(c, stack_closure(autoload_klib_each,
                                 autoload, m));
    }
  done:
    apply(complete, STATUS_OK);
}
