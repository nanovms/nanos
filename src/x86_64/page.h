#define INITIAL_MAP_SIZE (0xa000)

#define PAGE_NO_EXEC       U64_FROM_BIT(63)
#define PAGE_NO_FAT        0x0200 /* AVL[0] */
#define PAGE_2M_SIZE       0x0080
#define PAGE_DIRTY         0x0040
#define PAGE_ACCESSED      0x0020
#define PAGE_CACHE_DISABLE 0x0010
#define PAGE_WRITETHROUGH  0x0008
#define PAGE_USER          0x0004
#define PAGE_WRITABLE      0x0002
#define PAGE_PRESENT       0x0001

#define PAGEMASK           MASK(PAGELOG)
#define PAGE_FLAGS_MASK    (PAGE_NO_EXEC | PAGEMASK)
#define PAGE_PROT_FLAGS    (PAGE_NO_EXEC | PAGE_USER | PAGE_WRITABLE)
#define PAGE_DEV_FLAGS     (PAGE_WRITABLE | PAGE_CACHE_DISABLE | PAGE_NO_EXEC)

typedef u64 *page;

static inline u64 phys_from_pte(u64 pte)
{
    /* page directory pointer base address [51:12] */
    return pte & (MASK(52) & ~PAGEMASK);
}

static inline page page_from_pte(u64 pte)
{
    return (page)pointer_from_u64(phys_from_pte(pte));
}

static inline u64 flags_from_pte(u64 pte)
{
    return pte & PAGE_FLAGS_MASK;
}

static inline u64 pindex(u64 x, u64 offset)
{
    return ((x >> offset) & MASK(9));
}

static inline boolean pt_entry_is_present(u64 entry)
{
    return (entry & PAGE_PRESENT) != 0;
}

static inline boolean pt_entry_is_fat(int level, u64 entry)
{
    return level == 3 && (entry & PAGE_2M_SIZE) != 0;
}

static inline boolean pt_entry_is_pte(int level, u64 entry)
{
    return level == 4 || pt_entry_is_fat(level, entry);
}

#ifndef physical_from_virtual
physical physical_from_virtual(void *x);
#endif

void map(u64 virtual, physical p, u64 length, u64 flags, heap h);
void unmap(u64 virtual, u64 length, heap h);
void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh);
void unmap_and_free_phys(u64 virtual, u64 length);

static inline void unmap_pages(u64 virtual, u64 length)
{
    unmap_pages_with_handler(virtual, length, 0);
}

void update_map_flags(u64 vaddr, u64 length, u64 flags);
void zero_mapped_pages(u64 vaddr, u64 length);
void remap_pages(u64 vaddr_new, u64 vaddr_old, u64 length, heap h);

void dump_ptes(void *x);

typedef closure_type(entry_handler, boolean /* success */, int /* level */,
        u64 /* vaddr */, u64 * /* entry */);
boolean traverse_ptes(u64 vaddr, u64 length, entry_handler eh);
void page_invalidate(u64 p, thunk completion);
void flush_tlb();
void init_flush();
id_heap init_page_tables(heap h, id_heap physical);
