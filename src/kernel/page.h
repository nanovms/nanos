/* Though page flags are just a u64, we hide it behind this type to
   emphasize that page flags should be composed using helpers with
   clear semantics, not architecture bits. This is to avoid mistakes
   due to a union of PAGE_* constants on one architecture meaning
   something entirely different on another. */

typedef struct pageflags {
    u64 w;                      /* _PAGE_* flags, keep private to page.[hc] */
} pageflags;

void init_page_initial_map(void *initial_map, range phys);
void init_page_tables(heap pageheap);

/* tlb shootdown */
void init_flush(heap);
flush_entry get_page_flush_entry();
void page_invalidate(flush_entry f, u64 address);
void page_invalidate_sync(flush_entry f, thunk completion);
void page_invalidate_flush();

/* mapping and flag update */
void map(u64 virtual, physical p, u64 length, pageflags flags);
void update_map_flags(u64 vaddr, u64 length, pageflags flags);
void zero_mapped_pages(u64 vaddr, u64 length);
void remap_pages(u64 vaddr_new, u64 vaddr_old, u64 length);
void unmap(u64 virtual, u64 length);
void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh);

static inline void unmap_pages(u64 virtual, u64 length)
{
    unmap_pages_with_handler(virtual, length, 0);
}

#include <page_machine.h>

/* table traversal */
typedef closure_type(entry_handler, boolean /* success */, int /* level */,
                     u64 /* vaddr */, pteptr /* entry */);
boolean traverse_ptes(u64 vaddr, u64 length, entry_handler eh);
void dump_ptes(void *x);

/* internal use */
void *allocate_table_page(u64 *phys);
