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

    /* Backed heap allocations in turn allocate from both virtual_page
       and physical, mapping the results together and returning the
       virtual address. Deallocations remove the mapping and return
       the spaces to their respective heaps. This is presently the
       go-to source for ready-to-use, mapped pages. Accesses are
       protect via locking wrapper. */
    heap backed;

    /* The general heap is an mcache used for allocations of arbitrary
       sizes from 32B to 1MB. It is the heap that is closest to being
       a general-purpose allocator. Compatible with a malloc/free
       interface, deallocations do not require a size (but will
       attempt to verify one if given, so use -1ull to indicate an
       unspecified size). Not protected by spinlock. */
    heap general;

    /* Like general, but protected by a spinlock. Primarily for uses
       outside of the domain of the kernel lock (e.g. bhqueue
       processing). While heap operations from interrupt handlers are
       generally discouraged, they should be safe on the locked heap. */
    heap locked;
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

static inline heap heap_backed(kernel_heaps heaps)
{
    return heaps->backed;
}

static inline heap heap_general(kernel_heaps heaps)
{
    return heaps->general;
}

static inline heap heap_locked(kernel_heaps heaps)
{
    return heaps->locked;
}
