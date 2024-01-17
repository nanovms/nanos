#include <kernel.h>
#include <pagecache.h>
#include <tfs.h>
#include <unix.h>
#include <net.h>
#include <http.h>
#include <gdb.h>
#include <storage.h>
#include <symtab.h>
#include <virtio/virtio.h>
#include <elf64.h>

closure_function(3, 1, void, program_start,
                 process, kp, string, path, boolean, exec_started,
                 status, s)
{
    if (!is_ok(s))
        halt("program startup failed %s exec: %v\n", bound(exec_started) ? ss("on") : ss("before"),
             s);
    else if (bound(exec_started)) {
        closure_finish();
        return;
    }

    /* Set mapping flags to read-only for data that has been initialized during boot and should not
     * be modified afterwards. */
    extern void *ro_after_init_start, *ro_after_init_end;
    extern void *bss_ro_after_init_start, *bss_ro_after_init_end;
    update_map_flags(u64_from_pointer(&ro_after_init_start),
                     &ro_after_init_end - &ro_after_init_start,
                     pageflags_memory());
    update_map_flags(u64_from_pointer(&bss_ro_after_init_start),
                     &bss_ro_after_init_end - &bss_ro_after_init_start,
                     pageflags_memory());
    bound(exec_started) = true;
    exec_elf(bound(kp), bound(path), (status_handler)closure_self());
}

static void init_kernel_heaps_management(tuple root)
{
    kernel_heaps kh = get_kernel_heaps();
    tuple heaps = allocate_tuple();
    assert(heaps);
    /* TODO: This should become hierarchical, with child heaps registering with parents. */
    set(heaps, sym(virtual_huge), heap_management((heap)heap_virtual_huge(kh)));
    set(heaps, sym(virtual_page), heap_management((heap)heap_virtual_page(kh)));
    set(heaps, sym(physical), heap_management((heap)heap_physical(kh)));
    set(heaps, sym(general), heap_management((heap)heap_general(kh)));
    set(heaps, sym(locked), heap_management((heap)heap_locked(kh)));
    set(root, sym(heaps), heaps);
}

closure_function(6, 0, void, startup,
                 kernel_heaps, kh, tuple, root, filesystem, fs, merge, m, status_handler, start, status_handler, completion)
{
    status s = STATUS_OK;
    kernel_heaps kh = bound(kh);
    tuple root = bound(root);
    filesystem fs = bound(fs);

#ifdef CONFIG_TRACELOG
    init_tracelog_config(root);
#endif

    /* kernel process is used as a handle for unix */
    process kp = init_unix(kh, root, fs);
    if (kp == INVALID_ADDRESS) {
	s = timm("result", "unable to initialize unix instance");
        goto out;
    }
    status_handler start = bound(start);
    closure_member(program_start, start, kp) = kp;
    heap general = heap_locked(kh);

    /* register root tuple with management and kick off interfaces, if any */
    init_management_root(root);
    init_kernel_heaps_management(root);
    if (get(root, sym(readonly_rootfs)))
        filesystem_set_readonly(fs);
    value p = get(root, sym(program));
    assert(p && is_string(p));
    tuple pro = resolve_path(filesystem_getroot(fs), split(general, p, '/'));
    if (!pro)
        halt("unable to resolve program path \"%b\"\n", p);
    program_set_perms(root, pro);
    init_network_iface(root, bound(m));
    closure_member(program_start, start, path) = (string)p;
    if (trace_get_flags(get(root, sym(trace))) & TRACE_OTHER) {
        rprintf("read program complete: %p ", root);
        rprintf("gitversion: %s\n", gitversion);
    }
    storage_when_ready(apply_merge(bound(m)));
  out:
    apply(bound(completion), s);
    closure_finish();
}

thunk create_init(kernel_heaps kh, tuple root, filesystem fs, merge *m)
{
    heap h = heap_locked(kh);
    status_handler start = closure(h, program_start, 0, 0, false);
    *m = allocate_merge(h, start);
    return closure(h, startup, kh, root, fs, *m, start, apply_merge(*m));
}

closure_function(5, 1, status, kernel_read_complete,
                 kernel_heaps, kh, filesystem, fs, filesystem, klib_fs, status_handler, klibs_complete, tuple, root,
                 buffer, b)
{
    add_elf_syms(b, 0);
    deallocate_buffer(b);
    filesystem fs = bound(fs);
    filesystem klib_fs = bound(klib_fs);
    status_handler klibs_complete = bound(klibs_complete);
    if (klibs_complete)
        init_klib(bound(kh), klib_fs, bound(root), klibs_complete);
    if (fs != klib_fs)
        destroy_filesystem(fs);
    closure_finish();
    return STATUS_OK;
}

closure_function(5, 2, void, bootfs_complete,
                 kernel_heaps, kh, tuple, root, status_handler, klibs_complete, boolean, klibs_in_bootfs, boolean, ingest_kernel_syms,
                 filesystem, fs, status, s)
{
    tuple boot_root = filesystem_getroot(fs);
    tuple c = children(boot_root);
    assert(c);
    tuple root = bound(root);
    filesystem klib_fs = bound(klibs_in_bootfs) ? fs : get_root_fs();
    status_handler klibs_complete = bound(klibs_complete);

    if (bound(ingest_kernel_syms)) {
        tuple v = get_tuple(c, sym(kernel));
        if (v) {
            kernel_heaps kh = bound(kh);
            filesystem_read_entire(fs, v, (heap)heap_page_backed(kh),
                                   closure(heap_locked(kh), kernel_read_complete, kh, fs, klib_fs,
                                           klibs_complete, root),
                                   ignore_status);
        }
    } else {
        init_klib(bound(kh), klib_fs, root, klibs_complete);
    }
    closure_finish();
}

filesystem_complete bootfs_handler(kernel_heaps kh, tuple root,
                                   status_handler klibs_complete, boolean klibs_in_bootfs,
                                   boolean ingest_kernel_syms)
{
    return closure(heap_locked(kh), bootfs_complete,
                   kh, root, klibs_complete, klibs_in_bootfs, ingest_kernel_syms);
}
