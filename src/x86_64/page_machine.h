#define INITIAL_MAP_SIZE (0xa000)

#define PAGE_NO_EXEC       U64_FROM_BIT(63)
#define PAGE_NO_PS         0x0200 /* AVL[0] */
#define PAGE_PS            0x0080
#define PAGE_DIRTY         0x0040
#define PAGE_ACCESSED      0x0020
#define PAGE_CACHE_DISABLE 0x0010
#define PAGE_WRITETHROUGH  0x0008
#define PAGE_USER          0x0004
#define PAGE_READONLY      0
#define PAGE_WRITABLE      0x0002
#define PAGE_PRESENT       0x0001

#define PAGEMASK           MASK(PAGELOG)
#define PAGEMASK_2M        MASK(PAGELOG_2M)
#define PAGE_FLAGS_MASK    (PAGE_NO_EXEC | PAGEMASK)
#define PAGE_PROT_FLAGS    (PAGE_NO_EXEC | PAGE_USER | PAGE_WRITABLE)
#define PAGE_DEV_FLAGS     (PAGE_WRITABLE | PAGE_CACHE_DISABLE | PAGE_NO_EXEC)
#define PAGE_BACKED_FLAGS  (PAGE_WRITABLE | PAGE_NO_EXEC)

/* Page flags default to minimum permissions:
   - read-only
   - no user access
   - no execute
*/
#define PAGE_DEFAULT_PERMISSIONS (PAGE_READONLY | PAGE_NO_EXEC)

#define PT_FIRST_LEVEL 1
#define PT_PTE_LEVEL   4

#define PT_SHIFT_L1 39
#define PT_SHIFT_L2 30
#define PT_SHIFT_L3 21
#define PT_SHIFT_L4 12

static inline pageflags pageflags_memory(void)
{
    return (pageflags){.w = PAGE_DEFAULT_PERMISSIONS};
}

static inline pageflags pageflags_memory_writethrough(void)
{
    return (pageflags){.w = PAGE_DEFAULT_PERMISSIONS | PAGE_WRITETHROUGH};
}

static inline pageflags pageflags_device(void)
{
    return (pageflags){.w = PAGE_DEFAULT_PERMISSIONS | PAGE_CACHE_DISABLE};
}

static inline pageflags pageflags_writable(pageflags flags)
{
    return (pageflags){.w = flags.w | PAGE_WRITABLE};
}

static inline pageflags pageflags_readonly(pageflags flags)
{
    return (pageflags){.w = flags.w & ~PAGE_WRITABLE};
}

static inline pageflags pageflags_user(pageflags flags)
{
    return (pageflags){.w = flags.w | PAGE_USER};
}

static inline pageflags pageflags_noexec(pageflags flags)
{
    return (pageflags){.w = flags.w | PAGE_NO_EXEC};
}

static inline pageflags pageflags_exec(pageflags flags)
{
    return (pageflags){.w = flags.w & ~PAGE_NO_EXEC};
}

static inline pageflags pageflags_minpage(pageflags flags)
{
    return (pageflags){.w = flags.w | PAGE_NO_PS};
}

static inline pageflags pageflags_no_minpage(pageflags flags)
{
    return (pageflags){.w = flags.w & ~PAGE_NO_PS};
}

/* no-exec, read-only */
static inline pageflags pageflags_default_user(void)
{
    return pageflags_user(pageflags_minpage(pageflags_memory()));
}

static inline boolean pageflags_is_present(pageflags flags)
{
    return (flags.w & PAGE_PRESENT) != 0;
}

static inline boolean pageflags_is_writable(pageflags flags)
{
    return (flags.w & PAGE_WRITABLE) != 0;
}

static inline boolean pageflags_is_readonly(pageflags flags)
{
    return !pageflags_is_writable(flags);
}

static inline boolean pageflags_is_noexec(pageflags flags)
{
    return (flags.w & PAGE_NO_EXEC) != 0;
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
    return (entry & PAGE_PRESENT) != 0;
}

static inline boolean pte_is_block_mapping(pte entry)
{
    return (entry & PAGE_PS) != 0;
}

static inline u64 flags_from_pte(u64 pte)
{
    return pte & PAGE_FLAGS_MASK;
}

static inline pageflags pageflags_from_pte(pte pte)
{
    return (pageflags){.w = flags_from_pte(pte)};
}

static inline u64 page_pte(u64 phys, u64 flags)
{
    return phys | (flags & ~PAGE_NO_PS) | PAGE_PRESENT;
}

static inline u64 block_pte(u64 phys, u64 flags)
{
    return phys | flags | PAGE_PRESENT | PAGE_PS;
}

static inline u64 new_level_pte(u64 tp_phys)
{
    return tp_phys | PAGE_WRITABLE | PAGE_USER | PAGE_PRESENT;
}

static inline boolean flags_has_minpage(u64 flags)
{
    return (flags & PAGE_NO_PS) != 0;
}

extern u64 pagebase;
static inline u64 get_pagetable_base(u64 vaddr)
{
    return pagebase;
}

u64 *pointer_from_pteaddr(u64 pa);

static inline int pt_level_shift(int level)
{
    switch (level) {
    case 1:
        return PT_SHIFT_L1;
    case 2:
        return PT_SHIFT_L2;
    case 3:
        return PT_SHIFT_L3;
    case 4:
        return PT_SHIFT_L4;
    }
    return 0;
}

/* log of mapping size (block or page) if valid leaf, else 0 */
static inline int pte_order(int level, pte entry)
{
    assert(level > 0 && level < 5);
    if (level == 1 || !pte_is_present(entry) ||
        (level != 4 && !(entry & PAGE_PS)))
        return 0;
    return pt_level_shift(level);
}

static inline u64 pte_map_size(int level, pte entry)
{
    int order = pte_order(level, entry);
    return order ? U64_FROM_BIT(order) : INVALID_PHYSICAL;
}

static inline boolean pte_is_mapping(int level, pte entry)
{
    return pte_map_size(level, entry) != INVALID_PHYSICAL;
}

static inline boolean pte_is_dirty(pte entry)
{
    return (entry & PAGE_DIRTY) != 0;
}

static inline u64 page_from_pte(pte p)
{
    /* page directory pointer base address [51:12] */
    return p & (MASK(52) & ~PAGEMASK);
}

static inline void pt_pte_clean(pteptr pp)
{
    *pp &= ~PAGE_DIRTY;
}

#ifndef physical_from_virtual
static inline u64 pte_lookup_phys(u64 table, u64 vaddr, int offset)
{
    return table + (((vaddr >> offset) & MASK(9)) << 3);
}

static inline u64 *pte_lookup_ptr(u64 table, u64 vaddr, int offset)
{
    return pointer_from_pteaddr(pte_lookup_phys(table, vaddr, offset));
}

#define _pfv_level(table, vaddr, level)                                  \
    u64 *l ## level = pte_lookup_ptr(table, vaddr, PT_SHIFT_L ## level); \
    if (!(*l ## level & 1))                                              \
        return INVALID_PHYSICAL;

#define _pfv_check_ps(level, vaddr)                                      \
    if (*l ## level & PAGE_PS)                                           \
        return page_from_pte(*l ## level) | (vaddr & MASK(PT_SHIFT_L ## level));

static inline physical __physical_from_virtual_locked(void *x)
{
    u64 xt = u64_from_pointer(x);
    _pfv_level(pagebase, xt, 1);
    _pfv_level(page_from_pte(*l1), xt, 2);
    _pfv_check_ps(2, xt);
    _pfv_level(page_from_pte(*l2), xt, 3);
    _pfv_check_ps(3, xt);
    _pfv_level(page_from_pte(*l3), xt, 4);
    return page_from_pte(*l4) | (xt & MASK(PT_SHIFT_L4));
}

physical physical_from_virtual(void *x);
#endif

void *bootstrap_page_tables(heap initial);
#ifdef KERNEL
void map_setup_2mbpages(u64 v, physical p, int pages, pageflags flags,
                        u64 *pdpt, u64 *pdt);
void init_mmu(void);
#else
void init_mmu(heap initial);
#endif

