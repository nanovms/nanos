#include <kernel.h>
#include <pci.h>
#include <pagecache.h>
#include <storage.h>
#include <tfs.h>
#include <net.h>
#include <symtab.h>
#include <drivers/console.h>
#include <serial.h>

//#define INIT_DEBUG
#ifdef INIT_DEBUG
#define init_debug(x, ...) do {rprintf("INIT: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define init_debug(x, ...)
#endif

typedef struct mm_cleaner {
    struct list l;
    mem_cleaner cleaner;
} *mm_cleaner;

BSS_RO_AFTER_INIT filesystem root_fs;
BSS_RO_AFTER_INIT halt_handler vm_halt;
BSS_RO_AFTER_INIT static kernel_heaps init_heaps;

#define SHUTDOWN_COMPLETIONS_SIZE 8

static u64 bootstrap_base = BOOTSTRAP_BASE;
BSS_RO_AFTER_INIT static u64 bootstrap_limit;
static u64 bootstrap_alloc(heap h, bytes length)
{
    u64 result = bootstrap_base;
    if ((result + length) > bootstrap_limit) {
        rputs("*** bootstrap heap overflow! ***\n");
        return INVALID_PHYSICAL;
    }
    bootstrap_base += pad(length, 8);   /* ensure 8-byte alignment for the next allocation */
    return result;
}

BSS_RO_AFTER_INIT static struct kernel_heaps heaps;
BSS_RO_AFTER_INIT static vector shutdown_completions;

u64 init_bootstrap_heap(u64 phys_length)
{
    u64 page_count = phys_length >> PAGELOG;

    /* In theory, the bootstrap heap must accommodate 1 bit per physical memory page (as needed by
     * the id heap bitmap); but due to the way buffer extension works, when a bitmap is extended its
     * internal buffer doubles its allocated memory, which may need up to double the theoretical
     * amount of memory; plus, this allocated memory needs to coexist with previously allocated
     * memory (because deallocation is not implemented); thus, the bootstrap heap needs 4 times the
     * theoretical amount of memory.
     * In addition, we need some extra space for various initial allocations. */
    u64 bootstrap_size = 4 * PAGESIZE + pad(page_count >> 1, PAGESIZE);

    bootstrap_limit = BOOTSTRAP_BASE + bootstrap_size;
    return bootstrap_size;
}

void init_kernel_heaps(void)
{
    BSS_RO_AFTER_INIT static struct heap bootstrap;
    bootstrap.alloc = bootstrap_alloc;
    bootstrap.dealloc = leak;

    heaps.physical = init_physical_id_heap(&bootstrap);
    assert(heaps.physical != INVALID_ADDRESS);

#if defined(MEMDEBUG_BACKED) || defined(MEMDEBUG_ALL)
    heaps.linear_backed = mem_debug_backed(&bootstrap, allocate_linear_backed_heap(&bootstrap, heaps.physical), PAGESIZE_2M, true);
#else
    heaps.linear_backed = allocate_linear_backed_heap(&bootstrap, heaps.physical);
#endif
    assert(heaps.linear_backed != INVALID_ADDRESS);

    boolean is_lowmem = is_low_memory_machine();
    int max_mcache_order = is_lowmem ? MAX_LOWMEM_MCACHE_ORDER : MAX_MCACHE_ORDER;
    bytes pagesize = is_lowmem ? U64_FROM_BIT(max_mcache_order + 1) : PAGESIZE_2M;
    heaps.general = allocate_mcache(&bootstrap, (heap)heaps.linear_backed, 5, max_mcache_order,
                                    pagesize);
    assert(heaps.general != INVALID_ADDRESS);

    heaps.locked = locking_heap_wrapper(heaps.general, heaps.general);
    assert(heaps.locked != INVALID_ADDRESS);

    u64 kmem_base = pad(bootstrap_limit, HUGE_PAGESIZE);
    heaps.virtual_huge = create_id_heap(heaps.general, heaps.locked, kmem_base,
                                        KMEM_LIMIT - kmem_base, HUGE_PAGESIZE, true);
    assert(heaps.virtual_huge != INVALID_ADDRESS);

    heaps.virtual_page = create_id_heap_backed(heaps.general, heaps.locked,
                                               (heap)heaps.virtual_huge, PAGESIZE, true);
    assert(heaps.virtual_page != INVALID_ADDRESS);

    heaps.page_backed = allocate_page_backed_heap(heaps.general, (heap)heaps.virtual_page,
                                                  (heap)heaps.physical, PAGESIZE, true);
    assert(heaps.page_backed != INVALID_ADDRESS);
}

closure_function(2, 1, void, offset_req_handler,
                 u64, offset, storage_req_handler, req_handler,
                 storage_req, req)
{
    assert((bound(offset) & (SECTOR_SIZE - 1)) == 0);
    u64 ds = bound(offset) >> SECTOR_OFFSET;
    req->blocks = range_add(req->blocks, ds);
    apply(bound(req_handler), req);
}

/* stage3 */
extern thunk create_init(kernel_heaps kh, tuple root, filesystem fs, merge *m);
extern filesystem_complete bootfs_handler(kernel_heaps kh, tuple root,
                                          status_handler klibs_complete, boolean klibs_in_bootfs,
                                          boolean ingest_kernel_syms);

BSS_RO_AFTER_INIT static tuple_notifier wrapped_root;

closure_function(2, 2, void, fsstarted,
                 u8 *, mbr, storage_req_handler, req_handler,
                 filesystem, fs, status, s)
{
    init_debug("%s\n", __func__);
    heap h = heap_locked(init_heaps);
    if (!is_ok(s)) {
        buffer b = allocate_buffer(h, 128);
        bprintf(b, "unable to open filesystem: ");
        print_value(b, s, 0);
        buffer_print(b);
        halt("\n");
    }

    if (root_fs)
        halt("multiple root filesystems found\n");

    u8 *mbr = bound(mbr);
    root_fs = fs;
    storage_set_root_fs(fs);

    wrapped_root = tuple_notifier_wrap(filesystem_getroot(fs));
    assert(wrapped_root != INVALID_ADDRESS);
    // XXX use wrapped_root after root fs is separate
    tuple root = filesystem_getroot(root_fs);
    tuple mounts = get_tuple(root, sym(mounts));
    if (mounts)
        storage_set_mountpoints(mounts);
    value klibs = get_string(root, sym(klibs));
    boolean klibs_in_bootfs = klibs && buffer_compare_with_cstring(klibs, "bootfs");

    merge m;
    async_apply(create_init(init_heaps, root, fs, &m));
    boolean opening_bootfs = false;
    if (mbr) {
        heap bh = (heap)heap_linear_backed(init_heaps);
        boolean ingest_kernel_syms = symtab_is_empty() &&
                (klibs || get(root, sym(ingest_kernel_symbols)));
        struct partition_entry *bootfs_part;
        if ((ingest_kernel_syms || klibs_in_bootfs) &&
            (bootfs_part = partition_get(mbr, PARTITION_BOOTFS))) {
            create_filesystem(h, SECTOR_SIZE,
                              bootfs_part->nsectors * SECTOR_SIZE,
                              closure(h, offset_req_handler,
                                      bootfs_part->lba_start * SECTOR_SIZE, bound(req_handler)),
                              true, 0, /* read-only, no label */
                              bootfs_handler(init_heaps, root, klibs ? apply_merge(m) : 0,
                                             klibs_in_bootfs, ingest_kernel_syms));
            opening_bootfs = true;
        }
        deallocate(bh, mbr, PAGESIZE);
    }

    if (klibs && !opening_bootfs)
        init_klib(init_heaps, fs, root, apply_merge(m));

    closure_finish();
    symbol booted = sym(booted);
    if (!get(root, booted))
        filesystem_write_eav((tfs)fs, root, booted, null_value, false);
    config_console(root);
}

#ifdef MM_DEBUG
#define mm_debug(x, ...) do {tprintf(sym(mm), 0, x, ##__VA_ARGS__);} while(0)
#else
#define mm_debug(x, ...) do { } while(0)
#endif

static struct list mm_cleaners;
static struct spinlock mm_lock;

static u64 mm_clean(u64 clean_bytes)
{
    s64 remain = clean_bytes;
    spin_lock(&mm_lock);
    list end = list_end(&mm_cleaners);
    list last = end->prev;
    list e = list_begin(&mm_cleaners);
    while (e != end) {
        mm_cleaner mmc = struct_from_list(e, mm_cleaner, l);
        remain -= apply(mmc->cleaner, remain);
        if (remain <= 0)
            break;

        /* This cleaner couldn't satisfy the clean request: move it to the back of the list, i.e.
         * de-prioritize it for future requests. */
        list next = e->next;
        list_delete(e);
        list_push_back(&mm_cleaners, e);

        if (e == last)
            /* any further elements down the list are cleaners that couldn't satisfy this request */
            break;
        e = next;
    }
    spin_unlock(&mm_lock);
    return clean_bytes - remain;
}

boolean mm_register_mem_cleaner(mem_cleaner cleaner)
{
    mm_cleaner mmc = allocate(heap_locked(init_heaps), sizeof(*mmc));
    if (mmc == INVALID_ADDRESS)
        return false;
    mmc->cleaner = cleaner;
    spin_lock(&mm_lock);
    list_push_back(&mm_cleaners, &mmc->l);
    spin_unlock(&mm_lock);
    return true;
}

void mm_service(void)
{
    heap phys = (heap)heap_physical(init_heaps);
    u64 total = heap_total(phys);
    u64 free = total - heap_allocated(phys);
    u64 threshold = total >> MEM_CLEAN_THRESHOLD_SHIFT;
    if (threshold < MEM_CLEAN_THRESHOLD)
        threshold = MEM_CLEAN_THRESHOLD;
    mm_debug("%s: total %ld, alloc %ld, free %ld\n", __func__,
             heap_total(phys), heap_allocated(phys), free);
    if (free < threshold) {
        u64 clean_bytes = threshold - free;
        u64 cleaned = mm_clean(clean_bytes);
        if (cleaned > 0)
            mm_debug("   cleaned %ld / %ld requested...\n", cleaned, clean_bytes);
    }
}

kernel_heaps get_kernel_heaps(void)
{
    return &heaps;
}

filesystem get_root_fs(void)
{
    return root_fs;
}

tuple get_root_tuple(void)
{
    return root_fs ? filesystem_getroot(root_fs) : 0;
}

void register_root_notify(symbol s, set_value_notify n)
{
    // XXX to be restored when root fs tuple is separated from root tuple
    tuple_notifier_register_set_notify(wrapped_root, s, n);
}

tuple get_environment(void)
{
    return get(get_root_tuple(), sym(environment));
}

boolean first_boot(void)
{
    return !get(get_root_tuple(), sym(booted));
}

static void rootfs_init(u8 *mbr, u64 offset, storage_req_handler req_handler, u64 length)
{
    init_debug("%s", __func__);
    length -= offset;
    heap h = heap_locked(init_heaps);
    create_filesystem(h,
                      SECTOR_SIZE,
                      length,
                      closure(h, offset_req_handler, offset, req_handler),
                      false,
                      false,
                      closure(h, fsstarted, mbr, req_handler));
}

closure_function(2, 2, void, volume_fs_init,
                 storage_req_handler, req_handler, u64, length,
                 boolean, readonly, filesystem_complete, complete)
{
    create_filesystem(heap_locked(init_heaps), SECTOR_SIZE, bound(length), bound(req_handler),
                      readonly, 0 /* no label */, complete);
    closure_finish();
}

closure_function(4, 1, void, mbr_read,
                 u8 *, mbr, storage_req_handler, req_handler, u64, length, int, attach_id,
                 status, s)
{
    init_debug("%s", __func__);
    if (!is_ok(s)) {
        msg_err("unable to read partitions: %v\n", s);
        goto out;
    }
    u8 *mbr = bound(mbr);
    struct partition_entry *rootfs_part = partition_get(mbr, PARTITION_ROOTFS);
    if (!rootfs_part) {
        u8 uuid[UUID_LEN];
        char label[VOLUME_LABEL_MAX_LEN];
        if (filesystem_probe(mbr, uuid, label)) {
            storage_req_handler req_handler = bound(req_handler);
            fs_init_handler fs_init = closure(heap_locked(init_heaps), volume_fs_init, req_handler,
                                              bound(length));
            if (fs_init != INVALID_ADDRESS)
                volume_add(uuid, label, req_handler, fs_init, bound(attach_id));
            else
                msg_err("failed to allocate closure, skipping volume\n");
        } else {
            init_debug("unformatted storage device, ignoring");
        }
        deallocate((heap)heap_linear_backed(init_heaps), mbr, PAGESIZE);
    } else {
        /* The on-disk kernel log dump section is immediately before the first partition. */
        struct partition_entry *first_part = partition_at(mbr, 0);
        klog_disk_setup(first_part->lba_start * SECTOR_SIZE - KLOG_DUMP_SIZE, bound(req_handler));

        rootfs_init(mbr, rootfs_part->lba_start * SECTOR_SIZE, bound(req_handler), bound(length));
    }
  out:
    closure_finish();
}

closure_function(0, 3, void, attach_storage,
                 storage_req_handler, req_handler, u64, length, int, attach_id)
{
    heap h = heap_locked(init_heaps);
    heap bh = (heap)heap_linear_backed(init_heaps);
    /* Read partition table from disk, use backed heap for guaranteed alignment */
    u8 *mbr = allocate(bh, PAGESIZE);
    if (mbr == INVALID_ADDRESS) {
        msg_err("cannot allocate memory for MBR sector\n");
        return;
    }
    status_handler sh = closure(h, mbr_read, mbr, req_handler, length, attach_id);
    if (sh == INVALID_ADDRESS) {
        msg_err("cannot allocate MBR read closure\n");
        deallocate(bh, mbr, PAGESIZE);
        return;
    }
    struct storage_req req = {
        .op = STORAGE_OP_READ,
        .blocks = irange(0, 1),
        .data = mbr,
        .completion = sh,
    };
    apply(req_handler, &req);
}

closure_function(0, 1, u64, mm_pagecache_cleaner,
                 u64, clean_bytes)
{
    return pagecache_drain(clean_bytes);
}

void kernel_runtime_init(kernel_heaps kh)
{
    heap misc = heap_general(kh);
    heap locked = heap_locked(kh);
    init_heaps = kh;

    /* runtime and console init */
#ifdef INIT_DEBUG
    early_debug("kernel_runtime_init\n");
#endif
    init_runtime(misc, locked);
    init_sg(locked);
    list_init(&mm_cleaners);
    spin_lock_init(&mm_lock);
    init_pagecache(locked, reserve_heap_wrapper(misc, (heap)heap_linear_backed(kh), PAGECACHE_MEMORY_RESERVE),
               reserve_heap_wrapper(misc, (heap)heap_physical(kh), PAGECACHE_MEMORY_RESERVE), PAGESIZE);
    mem_cleaner pc_cleaner = closure(misc, mm_pagecache_cleaner);
    assert(pc_cleaner != INVALID_ADDRESS);
    assert(mm_register_mem_cleaner(pc_cleaner));
    unmap(0, PAGESIZE);         /* unmap zero page */
    init_extra_prints();
    init_pci(kh);
    init_console(kh);
    init_platform_devices(kh);
    init_symtab(kh);
    read_kernel_syms();
    reclaim_regions();          /* for pc: no accessing regions after this point */
    shutdown_completions = allocate_vector(locked, SHUTDOWN_COMPLETIONS_SIZE);

    init_debug("init_kernel_contexts");
    init_kernel_contexts((heap)heap_linear_backed(kh));

    init_debug("init_interrupts");
    init_interrupts(kh);

    init_debug("clock");
    init_clock();

    init_debug("init_scheduler");
    init_scheduler(locked);

    /* platform detection and early init */
    init_debug("probing for hypervisor platform");
    detect_hypervisor(kh);

    /* RNG, stack canaries */
    init_debug("RNG");
    init_random(locked);
    __stack_chk_guard_init();

    /* networking */
    init_debug("LWIP init");
    init_net(kh);

    init_debug("start_secondary_cores");
    count_cpus_present();
    init_scheduler_cpus(misc);
    start_secondary_cores(kh);

#ifdef CONFIG_TRACELOG
    init_debug("init_tracelog");
    init_tracelog(locked);
#endif

    init_debug("probe fs, register storage drivers");
    init_volumes(locked);

    storage_attach sa = closure(misc, attach_storage);

    init_debug("detect_devices");
    detect_devices(kh, sa);

    init_debug("pci_discover (for other devices)");
    pci_discover();
    init_debug("discover done");

    init_debug("starting runloop");
    runloop();
}

void add_shutdown_completion(shutdown_handler h)
{
    vector_push(shutdown_completions, h);
}

closure_function(1, 1, void, sync_complete,
                 u8, code,
                 status, s)
{
    vm_exit(bound(code));
    closure_finish();
}

closure_function(0, 2, void, storage_shutdown, int, status, merge, m)
{
    if (status != 0)
        klog_save(status, apply_merge(m));
    storage_sync(apply_merge(m));
}

extern boolean shutting_down;
void __attribute__((noreturn)) kernel_shutdown(int status)
{
    heap locked = heap_locked(init_heaps);
    status_handler completion = closure(locked, sync_complete, status);
    merge m = allocate_merge(locked, completion);
    status_handler sh = apply_merge(m);
    shutdown_handler h;

    shutting_down = true;

    if (root_fs)
        vector_push(shutdown_completions,
                    closure(locked, storage_shutdown));

    if (vector_length(shutdown_completions) > 0) {
        cpuinfo ci = current_cpu();
        vector_foreach(shutdown_completions, h)
            apply(h, status, m);
        apply(sh, STATUS_OK);
        if (ci->state == cpu_interrupt) {
            interrupt_exit();
            context c = get_current_context(ci);
            c->frame[FRAME_FULL] = false;
        }
        runloop();
    }
    apply(sh, STATUS_OK);
    while(1);
}

void vm_exit(u8 code)
{
#ifdef SMP_DUMP_FRAME_RETURN_COUNT
    rprintf("cpu\tframe returns\n");
    cpuinfo ci;
    vector_foreach(cpuinfos, ci) {
        if (ci->frcount)
            rprintf("%d\t%ld\n", ci->id, ci->frcount);
    }
#endif

#ifdef DUMP_MEM_STATS
    buffer b = allocate_buffer(heap_locked(get_kernel_heaps()), 512);
    if (b != INVALID_ADDRESS) {
        extern void dump_mem_stats(buffer b);
        dump_mem_stats(b);
        buffer_print(b);
    }
#endif

    tuple root = get_root_tuple();
    if (root) {
        value expected = get(root, sym(expected_exit_code));
        if (expected) {
            u64 expected_code;
            if ((is_string(expected) || is_integer(expected)) &&
                u64_from_value(expected, &expected_code) &&
                expected_code == code) {
                code = 0;               
            } else if (is_tuple(expected)) {
                for (int i = 0; get_u64(expected, intern_u64(i), &expected_code); i++) {
                    if (expected_code == code) {
                        code = 0;
                        break;
                    }
                }
            }
        }
        if ((code != 0) && get(root, sym(reboot_on_exit)))
            vm_reset();
        if ((code == 0) && get(root, sym(idle_on_exit))) {
            send_ipi(TARGET_EXCLUSIVE_BROADCAST, shutdown_vector);
            machine_halt();
        }
    }
    if (vm_halt && (!root || !get(root, sym(debug_exit))))
        apply(vm_halt, code);
    vm_shutdown(code);
}

static char *hex_digits="0123456789abcdef";

void early_debug(const char *s)
{
    while (*s != '\0')
        serial_putchar(*s++);
}

void early_debug_u64(u64 n)
{
    for (int x = 60; x >= 0; x -= 4)
        serial_putchar(hex_digits[(n >> x) & 0xf]);
}

void early_dump(void *p, unsigned long length)
{
    void *end = p + length;
    for (; p < end; p += 16) {
        early_debug_u64((unsigned long)p);
        early_debug(": ");

        for (int j = 0; j < 16; j++) {
            u8 b = *((u8 *)p + j);
            serial_putchar(hex_digits[(b >> 4) & 0xf]);
            serial_putchar(hex_digits[b & 0xf]);
            serial_putchar(b);
            serial_putchar(' ');
        }

        early_debug("| ");
        for (int j = 0; j < 16; j++) {
            char c = *((u8 *)p + j);
            serial_putchar((c >= ' ' && c < '~') ? c : '.');
        }
        early_debug(" |\n");
    }
    early_debug("\n");
}
