/* A repository of heaps used by the kernel

   Though the temptation is to retrieve these heaps from tuple space,
   they are needed before tuples are available and are accessed
   frequently.

   The wrappers may seem redundant, but they provide a place to add
   log or other debuging code, install wrapper heaps, etc.
*/

typedef struct kernel_heaps {
    /* Allocations of physical address space outside of pages are made
       from the physical id heap. Accesses are protected by spinlock. */
    id_heap physical;

    /* These two id heaps manage virtual address space aside from
       pages and tagged regions. virtual_huge allocations are 2^32
       sized, whereas virtual_page (whose parent is virtual_huge) is
       for page-sized allocations. Protected by spinlock. */
    id_heap virtual_huge;
    id_heap virtual_page;

    /* page_backed heap allocations allocate from physical, returning the mapped
       (with writable and no-exec protection) virtual address. Protected by spinlock.
       Do not use for DMA memory. */
    backed_heap page_backed;

    /* The linear_backed heap serves physical allocations via a large, linear
       mapping of the entire physical memory (up to LINEAR_BACKED_PHYSLIMIT)
       that is made on initialization. As such, it avoids both allocations
       from a virtual heap and the need to (un)map pages on (de)allocation. It
       uses the largest page mappings provided by the architecture, minimizing
       TLB use. This heap should be used for physically-backed, contiguous allocations
       of DMA memory. */
    backed_heap linear_backed;

    /* Caching heap for allocations of single pages. Avoids complete exhaustion of physical memory,
     * and minimizes memory fragmentation. */
    caching_heap pages;

    /* The general heap is an mcache used for allocations of arbitrary
       sizes from 32B to 1MB. It is the heap that is closest to being
       a general-purpose allocator. Compatible with a malloc/free
       interface, deallocations do not require a size (but will
       attempt to verify one if given, so use -1ull to indicate an
       unspecified size). Not protected by spinlock; likely to be replaced by
       the locked heap. Do not use for DMA memory. */
    heap general;

    /* Like general, but protected by a spinlock. While heap operations from
       interrupt handlers are generally discouraged, they should be safe on
       the locked heap. */
    heap locked;

    /* mcache for "malloc-style" allocations, i.e. to be used by vendor code where deallocation
     * requests are made without a size argument. Protected by spinlock. */
    heap malloc;

    /* mcache for allocations of DMA memory. Protected by spinlock. */
    heap dma;
} *kernel_heaps;

static inline id_heap heap_physical(kernel_heaps heaps)
{
    return heaps->physical;
}

static inline id_heap heap_virtual_huge(kernel_heaps heaps)
{
    return heaps->virtual_huge;
}

static inline id_heap heap_virtual_page(kernel_heaps heaps)
{
    return heaps->virtual_page;
}

static inline backed_heap heap_page_backed(kernel_heaps heaps)
{
    return heaps->page_backed;
}

static inline backed_heap heap_linear_backed(kernel_heaps heaps)
{
    return heaps->linear_backed;
}

static inline heap heap_general(kernel_heaps heaps)
{
    return heaps->general;
}

static inline heap heap_locked(kernel_heaps heaps)
{
    return heaps->locked;
}
