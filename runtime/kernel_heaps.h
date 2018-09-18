/* A repository of heaps used by the kernel

   Though the temptation is to retrieve these heaps from tuple space,
   they are needed before tuples are available and are accessed
   frequently.

   The wrappers may seem redundant, but they provide a place to add
   log or other debuging code, install wrapper heaps, etc.
*/

typedef struct kernel_heaps {
    heap pages;
    heap physical;
    heap virtual_huge;
    heap virtual_page;
    heap backed;
    heap general;
} *kernel_heaps;

static inline heap heap_general(kernel_heaps heaps)
{
    return heaps->general;
}

static inline heap heap_pages(kernel_heaps heaps)
{
    return heaps->pages;
}

static inline heap heap_physical(kernel_heaps heaps)
{
    return heaps->physical;
}

static inline heap heap_virtual_huge(kernel_heaps heaps)
{
    return heaps->virtual_huge;
}

static inline heap heap_virtual_page(kernel_heaps heaps)
{
    return heaps->virtual_page;
}

static inline heap heap_backed(kernel_heaps heaps)
{
    return heaps->backed;
}
