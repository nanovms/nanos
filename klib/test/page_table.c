#include <kernel.h>

closure_function(1, 3, boolean, pt_test_entry_handler,
                 boolean, writable,
                 int level, u64 vaddr, pteptr entry)
{
    pte e = pte_from_pteptr(entry);
    if (!pte_is_mapping(level, e))
            return true;
    pageflags flags = pageflags_from_pte(e);
    boolean writable = bound(writable);
    return pte_is_present(e) && (pageflags_is_writable(flags) == writable) &&
            (pageflags_is_readonly(flags) != writable) && pageflags_is_noexec(flags);
}

static void pt_test_update_flags(heap vh, heap ph)
{
    heap h = heap_locked(get_kernel_heaps());
    pageflags ro_flags = pageflags_memory();
    pageflags rw_flags = pageflags_writable(ro_flags);
    vector virt = allocate_vector(h, 64);
    assert(virt != INVALID_ADDRESS);
    u64 p, v;
    u64 size = PAGESIZE;
    while ((p = allocate_u64(ph, size)) != INVALID_PHYSICAL) {
        v = allocate_u64(vh, size);
        assert(v != INVALID_PHYSICAL);

        /* read-only mapping */
        assert(map_with_complete(v, p, size, ro_flags, 0) == p);
        assert(physical_from_virtual(pointer_from_u64(v)) == p);
        ((volatile u8 *)v)[0];
        ((volatile u8 *)v)[size - 1];
        assert(traverse_ptes(v, size, stack_closure(pt_test_entry_handler, false)));

        /* read-write mapping */
        update_map_flags(v, size, rw_flags);
        ((u8 *)v)[0] = 0;
        ((u8 *)v)[size - 1] = 0;
        assert(traverse_ptes(v, size, stack_closure(pt_test_entry_handler, true)));

        /* back to read-only mapping */
        update_map_flags(v, size, ro_flags);
        assert(traverse_ptes(v, size, stack_closure(pt_test_entry_handler, false)));

        unmap(v, size);
        deallocate_u64(ph, p, size);
        vector_push(virt, pointer_from_u64(v));
        size *= 3;
    }
    size = PAGESIZE;
    void *ptr;
    vector_foreach(virt, ptr) {
        deallocate(vh, ptr, size);
        size *= 3;
    }
    deallocate_vector(virt);
}

static void pt_test_remap(heap vh, heap ph)
{
    heap h = heap_locked(get_kernel_heaps());
    pageflags flags = pageflags_writable(pageflags_memory());
    vector virt = allocate_vector(h, 64);
    assert(virt != INVALID_ADDRESS);
    u64 p, v;
    u64 size = PAGESIZE;
    while ((p = allocate_u64(ph, size)) != INVALID_PHYSICAL) {
        v = allocate_u64(vh, 2 * size);
        assert(v != INVALID_PHYSICAL);
        map(v, p, size, flags);
        assert(traverse_ptes(v, size, stack_closure(pt_test_entry_handler, true)));

        /* Write values to first virtual address range, then remap from first to second range and
         * check written values in second range. */
        u64 r1 = random_u64();
        u64 r2 = random_u64();
        ((u64 *)v)[0] = r1;
        ((u64 *)v)[size / sizeof(u64) - 1] = r2;
        remap_pages(v + size, v, size);
        assert(((u64 *)v)[size / sizeof(u64)] == r1);
        assert(((u64 *)v)[2 * size / sizeof(u64) - 1] == r2);

        assert(traverse_ptes(v + size, size, stack_closure(pt_test_entry_handler, true)));
        assert(physical_from_virtual(pointer_from_u64(v + size)) == p);
        unmap(v + size, size);
        deallocate_u64(ph, p, size);
        vector_push(virt, pointer_from_u64(v));
        size *= 3;
    }
    size = PAGESIZE;
    void *ptr;
    vector_foreach(virt, ptr) {
        deallocate(vh, ptr, 2 * size);
        size *= 3;
    }
    deallocate_vector(virt);
}

int init(status_handler complete)
{
    kernel_heaps kh = get_kernel_heaps();
    heap vh = (heap)heap_virtual_page(kh);
    heap ph = (heap)heap_physical(kh);
    pt_test_update_flags(vh, ph);
    pt_test_remap(vh, ph);
    rprintf("Page table test OK\n");
    return KLIB_INIT_OK;
}
