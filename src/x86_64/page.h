#define INITIAL_MAP_SIZE (0xa000)

#define _PAGE_NO_EXEC       U64_FROM_BIT(63)
#define _PAGE_NO_FAT        0x0200 /* AVL[0] */
#define _PAGE_2M_SIZE       0x0080
#define _PAGE_DIRTY         0x0040
#define _PAGE_ACCESSED      0x0020
#define _PAGE_CACHE_DISABLE 0x0010
#define _PAGE_WRITETHROUGH  0x0008
#define _PAGE_USER          0x0004
#define _PAGE_READONLY      0
#define _PAGE_WRITABLE      0x0002
#define _PAGE_PRESENT       0x0001

#define PAGEMASK           MASK(PAGELOG)
#define PAGEMASK_2M        MASK(PAGELOG_2M)
#define _PAGE_FLAGS_MASK    (_PAGE_NO_EXEC | PAGEMASK)
#define _PAGE_PROT_FLAGS    (_PAGE_NO_EXEC | _PAGE_USER | _PAGE_WRITABLE)
#define _PAGE_DEV_FLAGS     (_PAGE_WRITABLE | _PAGE_CACHE_DISABLE | _PAGE_NO_EXEC)
#define _PAGE_BACKED_FLAGS  (_PAGE_WRITABLE | _PAGE_NO_EXEC)

/* Though page flags are just a u64, we hide it behind this type to
   emphasize that page flags should be composed using helpers with
   clear semantics, not architecture bits. This is to avoid mistakes
   due to a union of PAGE_* constants on one architecture meaning
   something entirely different on another. */

typedef struct pageflags {
    u64 w;                      /* _PAGE_* flags, keep private to page.[hc] */
} pageflags;

/* Page flags default to minimum permissions:
   - read-only
   - no user access
   - no execute
*/
#define _PAGE_DEFAULT_PERMISSIONS (_PAGE_READONLY | _PAGE_NO_EXEC)

static inline pageflags pageflags_memory(void)
{
    return (pageflags){w: _PAGE_DEFAULT_PERMISSIONS};
}

static inline pageflags pageflags_memory_writethrough(void)
{
    return (pageflags){w: _PAGE_DEFAULT_PERMISSIONS | _PAGE_WRITETHROUGH};
}

static inline pageflags pageflags_device(void)
{
    return (pageflags){w: _PAGE_DEFAULT_PERMISSIONS | _PAGE_CACHE_DISABLE};
}

static inline pageflags pageflags_writable(pageflags flags)
{
    return (pageflags){w: flags.w | _PAGE_WRITABLE};
}

static inline pageflags pageflags_readonly(pageflags flags)
{
    return (pageflags){w: flags.w & ~_PAGE_WRITABLE};
}

static inline pageflags pageflags_user(pageflags flags)
{
    return (pageflags){w: flags.w | _PAGE_USER};
}

static inline pageflags pageflags_noexec(pageflags flags)
{
    return (pageflags){w: flags.w | _PAGE_NO_EXEC};
}

static inline pageflags pageflags_exec(pageflags flags)
{
    return (pageflags){w: flags.w & ~_PAGE_NO_EXEC};
}

static inline boolean pageflags_is_writable(pageflags flags)
{
    return (flags.w & _PAGE_WRITABLE) != 0;
}

static inline boolean pageflags_is_readonly(pageflags flags)
{
    return !pageflags_is_writable(flags);
}

static inline boolean pageflags_is_noexec(pageflags flags)
{
    return (flags.w & _PAGE_NO_EXEC) != 0;
}

static inline boolean pageflags_is_exec(pageflags flags)
{
    return !pageflags_is_noexec(flags);
}

typedef u64 pte;
typedef volatile pte *pteptr;

static inline pte pte_from_pteptr(pteptr pp)
{
    return *pp;
}

static inline void pte_set(pteptr pp, pte p)
{
    *pp = p;
}

static inline boolean pte_is_present(pte entry)
{
    return (entry & _PAGE_PRESENT) != 0;
}

static inline boolean pte_is_2M(int level, pte entry)
{
    return level == 3 && (entry & _PAGE_2M_SIZE) != 0;
}

static inline u64 pte_map_size(int level, pte entry)
{
    if (pte_is_2M(level, entry))
        return PAGESIZE_2M;
    else
        return level == 4 ? PAGESIZE : INVALID_PHYSICAL;
}

static inline boolean pte_is_mapping(int level, pte entry)
{
    return level == 4 || pte_is_2M(level, entry);
}

static inline boolean pte_is_dirty(pte entry)
{
    return (entry & _PAGE_DIRTY) != 0;
}

static inline u64 page_from_pte(pte p)
{
    /* page directory pointer base address [51:12] */
    return p & (MASK(52) & ~PAGEMASK);
}

static inline void pt_pte_clean(pteptr pp)
{
    *pp &= ~_PAGE_DIRTY;
}

#ifndef physical_from_virtual
physical physical_from_virtual(void *x);
#endif
typedef struct flush_entry *flush_entry;

void map(u64 virtual, physical p, u64 length, pageflags flags);
void unmap(u64 virtual, u64 length);
void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh);
void unmap_and_free_phys(u64 virtual, u64 length);

static inline void unmap_pages(u64 virtual, u64 length)
{
    unmap_pages_with_handler(virtual, length, 0);
}

void update_map_flags(u64 vaddr, u64 length, pageflags flags);
void zero_mapped_pages(u64 vaddr, u64 length);
void remap_pages(u64 vaddr_new, u64 vaddr_old, u64 length);
void dump_ptes(void *x);

static inline void map_and_zero(u64 v, physical p, u64 length, pageflags flags)
{
    /* proc configured to trap on not writeable only when in cpl 3 */
    assert((v & MASK(PAGELOG)) == 0);
    assert((p & MASK(PAGELOG)) == 0);
    map(v, p, length, flags);
    zero(pointer_from_u64(v), length);
}

typedef closure_type(entry_handler, boolean /* success */, int /* level */,
        u64 /* vaddr */, pteptr /* entry */);
boolean traverse_ptes(u64 vaddr, u64 length, entry_handler eh);
void page_invalidate(flush_entry f, u64 p);
void page_invalidate_sync(flush_entry f, thunk completion);
flush_entry get_page_flush_entry();
void page_invalidate_flush();
void flush_tlb();
void init_flush(heap);
void *bootstrap_page_tables(heap initial);
#ifdef KERNEL
void map_setup_2mbpages(u64 v, physical p, int pages, pageflags flags,
                        u64 *pdpt, u64 *pdt);
void init_page_tables(heap h, id_heap physical, range initial_map);
#else
void init_page_tables(heap initial);
#endif
