extern u64 tablebase;

static inline u64 get_pagetable_base(u64 vaddr)
{
    return tablebase;
}

/* Page flags default to minimum permissions:
   - read-only
   - no user access
   - no execute
*/
#define PAGE_VALID      U64_FROM_BIT(0)
#define PAGE_READABLE   U64_FROM_BIT(1)
#define PAGE_WRITABLE   U64_FROM_BIT(2)
#define PAGE_EXEC       U64_FROM_BIT(3)
#define PAGE_USER       U64_FROM_BIT(4)
#define PAGE_GLOBAL     U64_FROM_BIT(5)
#define PAGE_ACCESSED   U64_FROM_BIT(6)
#define PAGE_DIRTY      U64_FROM_BIT(7)
#define PAGE_NO_BLOCK   U64_FROM_BIT(8) // RSW[0]
#define PAGE_DEFAULT_PERMISSIONS (PAGE_READABLE)
#define PAGE_PROT_FLAGS (PAGE_USER | PAGE_EXEC | PAGE_WRITABLE)

#define PAGE_FLAGS_MASK 0x3ff

#define PT_FIRST_LEVEL 0
#define PT_PTE_LEVEL   3

#define PAGE_NLEVELS 4

#define PT_SHIFT_L0 39
#define PT_SHIFT_L1 30
#define PT_SHIFT_L2 21
#define PT_SHIFT_L3 12

#define Sv39 (8ull<<60)
#define Sv48 (9ull<<60)

#define IS_LEAF(e) (((e) & (PAGE_EXEC|PAGE_READABLE)) != 0)

static inline pageflags pageflags_memory(void)
{
    return (pageflags){.w = PAGE_DEFAULT_PERMISSIONS};
}

static inline pageflags pageflags_memory_writethrough(void)
{
    return (pageflags){.w = PAGE_DEFAULT_PERMISSIONS}; // PMAs are hardwired
}

static inline pageflags pageflags_device(void)
{
    return (pageflags){.w = PAGE_DEFAULT_PERMISSIONS}; // PMAs are hardwired
}

static inline pageflags pageflags_dma(void)
{
    return (pageflags){.w = PAGE_DEFAULT_PERMISSIONS | PAGE_WRITABLE};
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
    return (pageflags){.w = flags.w & ~PAGE_EXEC };
}

static inline pageflags pageflags_exec(pageflags flags)
{
    return (pageflags){.w = flags.w | PAGE_EXEC};
}

static inline pageflags pageflags_minpage(pageflags flags)
{
    return (pageflags){.w = flags.w | PAGE_NO_BLOCK};
}

static inline pageflags pageflags_no_minpage(pageflags flags)
{
    return (pageflags){.w = flags.w & ~PAGE_NO_BLOCK};
}

/* no-exec, read-only */
static inline pageflags pageflags_default_user(void)
{
    return pageflags_user(pageflags_memory());
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
    return (flags.w & PAGE_EXEC) == 0;
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
    return (entry & PAGE_VALID) != 0;
}

static inline int pt_level_shift(int level)
{
    switch (level) {
    case 0:
        return PT_SHIFT_L0;
    case 1:
        return PT_SHIFT_L1;
    case 2:
        return PT_SHIFT_L2;
    case 3:
        return PT_SHIFT_L3;
    default:
        assert(0);
    }
    return 0;
}

/* log of mapping size (block or page) if valid leaf, else 0 */
static inline int pte_order(int level, pte entry)
{
    assert(level < PAGE_NLEVELS);
    if (level == 0 || !pte_is_present(entry) ||
        !IS_LEAF(entry))
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
    // XXX is leaf?
    return pte_is_present(entry) && IS_LEAF(entry);
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
    // XXX?
    return (phys>>2) | flags | PAGE_VALID;
}

static inline u64 block_pte(u64 phys, u64 flags)
{
    // XXX?
    return (phys>>2) | flags | PAGE_VALID;
}

static inline u64 new_level_pte(u64 tp_phys)
{
    return (tp_phys>>2) | PAGE_VALID;
}

static inline boolean flags_has_minpage(u64 flags)
{
    return (flags & PAGE_NO_BLOCK) != 0;
}

static inline boolean pte_is_dirty(pte entry)
{
    return (entry & PAGE_DIRTY) != 0;
}

static inline boolean pte_is_accessed(pte entry)
{
    return (entry & PAGE_ACCESSED) != 0;
}

static inline void pt_pte_clean(pteptr pte)
{
    *pte &= ~PAGE_DIRTY;
}

static inline boolean pte_clear_accessed(pteptr pp)
{
    boolean accessed = !!(*pp & PAGE_ACCESSED);
    *pp &= ~PAGE_ACCESSED;
    return accessed;
}

static inline u64 page_from_pte(pte pte)
{
    return (pte & (MASK(54) & ~PAGE_FLAGS_MASK))<<2;
}

u64 *pointer_from_pteaddr(u64 pa);

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

#define _pfv_check_leaf(level, vaddr, e)                                    \
    if (IS_LEAF(*l ## level)) {                                          \
        if (e) *e = *l ## level;                                                \
        return page_from_pte(*l ## level) | (vaddr & MASK(PT_SHIFT_L ## level)); \
    }

static inline physical __physical_and_pte_from_virtual_locked(u64 xt, pte *e)
{
    _pfv_level(tablebase, xt, 0);
    _pfv_check_leaf(0, xt, e);
    _pfv_level(page_from_pte(*l0), xt, 1);
    _pfv_check_leaf(1, xt, e);
    _pfv_level(page_from_pte(*l1), xt, 2);
    _pfv_check_leaf(2, xt, e);
    _pfv_level(page_from_pte(*l2), xt, 3);
    _pfv_check_leaf(3, xt, e);
    assert(0); // should not get here
}

static inline physical __physical_from_virtual_locked(void *x)
{
    return __physical_and_pte_from_virtual_locked(u64_from_pointer(x), 0);
}

physical physical_from_virtual(void *x);

#define table_from_pte page_from_pte

void init_mmu(range init_pt, u64 vtarget, void *dtb);

