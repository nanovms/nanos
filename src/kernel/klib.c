#include <kernel.h>
#include <elf64.h>
#include <pagecache.h>
#include <tfs.h>
#include <page.h>

//#define KLIB_DEBUG
#ifdef KLIB_DEBUG
#define klib_debug(x, ...) do {log_printf("KLIB", x, ##__VA_ARGS__);} while(0)
#else
#define klib_debug(x, ...)
#endif

static kernel_heaps klib_kh;
static filesystem klib_fs;
static tuple klib_root;

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

static void add_sym(void *syms, const char *s, void *p)
{
    table_set((tuple)syms, sym_this(s), p ? p : INVALID_ADDRESS); /* allow zero value */
}

closure_function(2, 1, status, load_klib_complete,
                 const char *, name, klib_handler, complete,
                 buffer, b)
{
    heap h = heap_general(klib_kh);
    klib_handler complete = bound(complete);
    klib kl = allocate(h, sizeof(struct klib));
    assert(kl != INVALID_ADDRESS);

    /* rangemap is kind of overkill...this would be a good use for variable stride vec */
    kl->mappings = allocate_rangemap(h);
    if (kl->mappings == INVALID_ADDRESS) {
        deallocate(h, kl, sizeof(struct klib));
        return INVALID_ADDRESS;
    }

    runtime_memcpy(kl->name, bound(name), MIN(runtime_strlen(bound(name)), KLIB_MAX_NAME - 1));
    kl->name[KLIB_MAX_NAME - 1] = '\0';
    kl->syms = allocate_tuple();
    kl->elf = b;

    klib_debug("%s: klib %p, read length %ld\n", __func__, kl, buffer_length(b));
    u64 where = allocate_u64((heap)heap_virtual_huge(klib_kh), HUGE_PAGESIZE);
    assert(where != INVALID_PHYSICAL);

    klib_debug("   loading elf file at 0x%lx\n", where);
    void *entry = load_elf(b, where, stack_closure(klib_elf_map, kl));

    klib_debug("   entry @ %p, first word 0x%lx\n", entry, *(u64*)entry);
    klib_init ki = (klib_init)entry;
    int rv = ki(kl->syms, add_sym);
    status s = rv == KLIB_INIT_OK ? STATUS_OK :
        timm("result", "module initialization failed with %d", rv);
    closure_finish();
    apply(complete, kl, s);
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
    // wouldn't it make more sense to just pass a buffer and status handler?
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

void unload_klib(klib kl)
{
    klib_debug("%s: kl %s\n", __func__, kl->name);
    heap h = heap_general(klib_kh);
    rangemap_foreach(kl->mappings, n) {
        klib_mapping km = (klib_mapping)n;
        klib_debug("   v %R, p 0x%lx, flags 0x%lx\n", km->n.r, km->phys, km->flags);
        unmap(km->n.r.start, range_span(km->n.r));
        deallocate(h, km, sizeof(struct klib_mapping));
    }
    deallocate_buffer(kl->elf);
    deallocate_tuple(kl->syms);
    deallocate(h, kl, sizeof(struct klib));
}

void init_klib(kernel_heaps kh, void *fs, tuple root)
{
    klib_kh = kh;
    klib_fs = (filesystem)fs;
    klib_root = root;
}
