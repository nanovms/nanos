#define PAGEMASK MASK(PAGELOG)

#define PAGE_L0_3_DESC_VALID                      0x1
#define PAGE_L0_2_DESC_TABLE                      0x2 /* vs block */
#define PAGE_L1_4K_BLOCK_DESC_OUT_ADDR_SHIFT      30
#define PAGE_L1_4K_BLOCK_DESC_OUT_ADDR_BITS       18
#define PAGE_L2_4K_BLOCK_DESC_OUT_ADDR_SHIFT      21
#define PAGE_L2_4K_BLOCK_DESC_OUT_ADDR_BITS       27
#define PAGE_4K_TABLE_NEXT_LEVEL_TABLE_ADDR_SHIFT 12
#define PAGE_4K_TABLE_NEXT_LEVEL_TABLE_ADDR_BITS  36

#define PAGE_TABLE_NS  U64_FROM_BIT(62)
#define PAGE_TABLE_AP  U64_FROM_BIT(61)
#define PAGE_TABLE_XN  U64_FROM_BIT(60)
#define PAGE_TABLE_PXN U64_FROM_BIT(59)

#define PAGE_L1_2_BLOCK_DESC_LOWER_ATTR_SHIFT 2
#define PAGE_L1_2_BLOCK_DESC_LOWER_ATTR_BITS  10
#define PAGE_L1_2_BLOCK_DESC_LOWER_NT         0x10000
#define PAGE_L1_2_BLOCK_DESC_UPPER_ATTR_SHIFT 50
#define PAGE_L1_2_BLOCK_DESC_UPPER_ATTR_BITS  14

#define PAGE_L3_DESC_PAGE              0x2
#define PAGE_L3_4K_DESC_OUT_ADDR_SHIFT 12
#define PAGE_L3_4K_DESC_OUT_ADDR_BITS  36

#define PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK (MASK(48) & ~MASK(12))

#define PAGE_ATTR_PBHA_SHIFT     59
#define PAGE_ATTR_PBHA_BITS      16
#define PAGE_ATTR_UXN_XN         U64_FROM_BIT(54)
#define PAGE_ATTR_PXN            U64_FROM_BIT(53)
#define PAGE_ATTR_CONTIGUOUS     U64_FROM_BIT(52)
#define PAGE_ATTR_DBM            U64_FROM_BIT(51)
#define PAGE_ATTR_GP             U64_FROM_BIT(50)
#define PAGE_ATTR_nT             U64_FROM_BIT(16)
#define PAGE_ATTR_nG             U64_FROM_BIT(11)
#define PAGE_ATTR_AF             U64_FROM_BIT(10)
#define PAGE_ATTR_SH_SHIFT       8
#define PAGE_ATTR_SH_BITS        2
#define PAGE_ATTR_SH_NON         0
#define PAGE_ATTR_SH_RESV        1
#define PAGE_ATTR_SH_OUTER       2
#define PAGE_ATTR_SH_INNER       3
#define PAGE_ATTR_AP_2_1_SHIFT   6
#define PAGE_ATTR_AP_2_1_BITS    2
#define PAGE_ATTR_NS             U64_FROM_BIT(5)
#define PAGE_ATTR_ATTRINDX_SHIFT 2
#define PAGE_ATTR_ATTRINDX_BITS  3

#define PAGE_ATTR_AP_2_1_RO 2
#define PAGE_ATTR_AP_2_1_E0 1

#define PAGE_ATTR_AP_2_1_RW_NO_E0 0
#define PAGE_ATTR_AP_2_1_RW_ALL_E 1
#define PAGE_ATTR_AP_2_1_RO_NO_E0 2
#define PAGE_ATTR_AP_2_1_RO_ALL_E 3
    
#define ID_AA64MMFR0_EL1_TGran4_SHIFT 28
#define ID_AA64MMFR0_EL1_TGran4_BITS  4

#define TCR_EL1_TCMA1     U64_FROM_BIT(58)
#define TCR_EL1_TCMA0     U64_FROM_BIT(57)
#define TCR_EL1_E0PD1     U64_FROM_BIT(56)
#define TCR_EL1_E0PD0     U64_FROM_BIT(55)
#define TCR_EL1_NFD1      U64_FROM_BIT(54)
#define TCR_EL1_NFD0      U64_FROM_BIT(53)
#define TCR_EL1_TBID1     U64_FROM_BIT(52)
#define TCR_EL1_TBID0     U64_FROM_BIT(51)
#define TCR_EL1_HWU162    U64_FROM_BIT(50)
#define TCR_EL1_HWU161    U64_FROM_BIT(49)
#define TCR_EL1_HWU160    U64_FROM_BIT(48)
#define TCR_EL1_HWU159    U64_FROM_BIT(47)
#define TCR_EL1_HWU062    U64_FROM_BIT(46)
#define TCR_EL1_HWU061    U64_FROM_BIT(45)
#define TCR_EL1_HWU060    U64_FROM_BIT(44)
#define TCR_EL1_HWU059    U64_FROM_BIT(43)
#define TCR_EL1_HPD1      U64_FROM_BIT(42)
#define TCR_EL1_HPD0      U64_FROM_BIT(41)
#define TCR_EL1_HD        U64_FROM_BIT(40)
#define TCR_EL1_HA        U64_FROM_BIT(39)
#define TCR_EL1_TBI1      U64_FROM_BIT(38) /* top byte ignored - for tags */
#define TCR_EL1_TBI0      U64_FROM_BIT(37)
#define TCR_EL1_AS        U64_FROM_BIT(36)
#define TCR_EL1_IPS_SHIFT 32
#define TCR_EL1_IPS_BITS  3

#define TCR_EL1_TG1_16KB     1
#define TCR_EL1_TG1_4KB      2
#define TCR_EL1_TG1_64KB     3

#define TCR_EL1_TG0_4KB      0
#define TCR_EL1_TG0_64KB     1
#define TCR_EL1_TG0_16KB     2

#define TCR_EL1_SH_NOSHARE  0
#define TCR_EL1_SH_OUTER    2
#define TCR_EL1_SH_INNER    3

#define TCR_EL1_xRGN_NOCACHE  0
#define TCR_EL1_xRGN_WB       1
#define TCR_EL1_xRGN_WT_NOWA  2
#define TCR_EL1_xRGN_WB_NOWA  3

/* for TTBR1_EL1 */
#define TCR_EL1_TG1_SHIFT   30
#define TCR_EL1_TG1_BITS    2
#define TCR_EL1_SH1_SHIFT   28
#define TCR_EL1_SH1_BITS    2
#define TCR_EL1_ORGN1_SHIFT 26
#define TCR_EL1_ORGN1_BITS  2
#define TCR_EL1_IRGN1_SHIFT 24
#define TCR_EL1_IRGN1_BITS  2
#define TCR_EL1_EPD1        U64_FROM_BIT(23)
#define TCR_EL1_A1          U64_FROM_BIT(22)
#define TCR_EL1_T1SZ_SHIFT  16  /* region size = 2 ^ (64 - T1SZ) */
#define TCR_EL1_T1SZ_BITS   6

/* for TTBR0_EL0 */
#define TCR_EL1_TG0_SHIFT   14
#define TCR_EL1_TG0_BITS    2
#define TCR_EL1_SH0_SHIFT   12
#define TCR_EL1_SH0_BITS    2
#define TCR_EL1_ORGN0_SHIFT 10
#define TCR_EL1_ORGN0_BITS  2
#define TCR_EL1_IRGN0_SHIFT 8
#define TCR_EL1_IRGN0_BITS  2
#define TCR_EL1_EPD0        U64_FROM_BIT(7)
#define TCR_EL1_T0SZ_SHIFT  0   /* region size = 2 ^ (64 - T0SZ) */
#define TCR_EL1_T0SZ_BITS   5

/* memory attributes */
#define MAIR_EL1_DEV_nGnRnE 0x0
#define MAIR_EL1_DEV_nGnRE  0x4
#define MAIR_EL1_DEV_nGRE   0x8
#define MAIR_EL1_DEV_GRE    0xc

#define MAIR_EL1_NORM_NC    0x44
#define MAIR_EL1_NORM       0xff
#define MAIR_EL1_NORM_WT    0xbb

#define _PAGE_MEMATTR_SHIFT      2
#define _PAGE_MEMATTR_BITS       4
#define _PAGE_MEMATTR_DEV_nGnRnE 0
#define _PAGE_MEMATTR_DEV_nGnRE  1
#define _PAGE_MEMATTR_DEV_GRE    2
#define _PAGE_MEMATTR_NORM_NC    3
#define _PAGE_MEMATTR_NORM       4
#define _PAGE_MEMATTR_NORM_WT    5

#define MAIR_EL1(i, v)  (((u64)v) << ((i) * 8))
#define MAIR_EL1_INIT (MAIR_EL1(_PAGE_MEMATTR_DEV_nGnRnE, MAIR_EL1_DEV_nGnRnE) | \
                       MAIR_EL1(_PAGE_MEMATTR_DEV_nGnRE, MAIR_EL1_DEV_nGnRE) | \
                       MAIR_EL1(_PAGE_MEMATTR_DEV_GRE, MAIR_EL1_DEV_GRE) | \
                       MAIR_EL1(_PAGE_MEMATTR_NORM_NC, MAIR_EL1_NORM_NC) | \
                       MAIR_EL1(_PAGE_MEMATTR_NORM, MAIR_EL1_NORM) | \
                       MAIR_EL1(_PAGE_MEMATTR_NORM_WT, MAIR_EL1_NORM_WT))

/* Though page flags are just a u64, we hide it behind this type to
   emphasize that page flags should be composed using helpers with
   clear semantics, not architecture bits. This is to avoid mistakes
   due to a union of PAGE_* constants on one architecture meaning
   something entirely different on another. */

typedef struct pageflags {
    u64 w;                      /* _PAGE_* flags, keep private to page.[hc] */
} pageflags;

// XXX clean up underbar cruft
#define _PAGE_NO_EXEC      PAGE_ATTR_UXN_XN
#define _PAGE_WRITABLE     0
#define _PAGE_READONLY     u64_from_field(PAGE_ATTR_AP_2_1, PAGE_ATTR_AP_2_1_RO)
#define _PAGE_USER         u64_from_field(PAGE_ATTR_AP_2_1, PAGE_ATTR_AP_2_1_E0)
#define _PAGE_FLAGS_MASK   0xfffc000000000fffull
#define _PAGE_PROT_FLAGS   (_PAGE_NO_EXEC | _PAGE_USER | _PAGE_READONLY)

#define _PAGE_ATTRS        (PAGE_ATTR_UXN_XN | PAGE_ATTR_PXN) /* AP[2:1] == 0 */
#define _PAGE_NLEVELS      4
#define _LEVEL_MASK_4K     MASK(9)   /* would be array for certain granule sizes? */


// XXX kernel addr, also should return INVALID_PHYSICAL if PAR_EL1.F is set
#define physical_from_virtual(v) ({                                     \
            register u64 __r;                                           \
            register u64 __x = u64_from_pointer(v);                     \
            asm volatile("at S1E1R, %1; mrs %0, PAR_EL1" : "=r"(__r) : "r"(__x)); \
            (__r & (MASK(47) & ~MASK(12))) | (__x & MASK(12));})

extern const int page_level_shifts_4K[_PAGE_NLEVELS];

/* Page flags default to minimum permissions:
   - read-only
   - no user access
   - no execute
*/
#define _PAGE_DEFAULT_PERMISSIONS (_PAGE_READONLY | _PAGE_NO_EXEC)

static inline pageflags pageflags_memory(void)
{
    return (pageflags){.w = u64_from_field(_PAGE_MEMATTR, _PAGE_MEMATTR_NORM)
            | u64_from_field(PAGE_ATTR_SH, PAGE_ATTR_SH_INNER)
            | _PAGE_DEFAULT_PERMISSIONS};
}

static inline pageflags pageflags_memory_writethrough(void)
{
    return (pageflags){.w = u64_from_field(_PAGE_MEMATTR, _PAGE_MEMATTR_NORM_WT)
            | u64_from_field(PAGE_ATTR_SH, PAGE_ATTR_SH_INNER)
            | _PAGE_DEFAULT_PERMISSIONS};
}

static inline pageflags pageflags_device(void)
{
    return (pageflags){.w = u64_from_field(_PAGE_MEMATTR, _PAGE_MEMATTR_DEV_nGnRnE)
            | _PAGE_DEFAULT_PERMISSIONS};
}

static inline pageflags pageflags_writable(pageflags flags)
{
    return (pageflags){.w = flags.w & ~_PAGE_READONLY};
}

static inline pageflags pageflags_readonly(pageflags flags)
{
    return (pageflags){.w = flags.w | _PAGE_READONLY};
}

static inline pageflags pageflags_user(pageflags flags)
{
    return (pageflags){.w = flags.w | _PAGE_USER};
}

static inline pageflags pageflags_noexec(pageflags flags)
{
    return (pageflags){.w = flags.w | PAGE_ATTR_UXN_XN};
}

static inline pageflags pageflags_exec(pageflags flags)
{
    return (pageflags){.w = flags.w & ~PAGE_ATTR_UXN_XN};
}

static inline boolean pageflags_is_writable(pageflags flags)
{
    return (flags.w & _PAGE_READONLY) == 0;
}

static inline boolean pageflags_is_readonly(pageflags flags)
{
    return !pageflags_is_writable(flags);
}

static inline boolean pageflags_is_noexec(pageflags flags)
{
    return (flags.w & PAGE_ATTR_UXN_XN) != 0;
}

static inline boolean pageflags_is_exec(pageflags flags)
{
    return !pageflags_is_noexec(flags);
}

extern const int page_level_shifts_4K[_PAGE_NLEVELS];

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
    return (entry & PAGE_L0_3_DESC_VALID) != 0;
}

/* log of mapping size (block or page) if valid leaf, else 0 */
static inline int pte_order(unsigned int level, pte entry)
{
    assert(level < _PAGE_NLEVELS);
    if (level == 0 || !pte_is_present(entry) ||
        (level != 3 && (entry & PAGE_L0_2_DESC_TABLE)))
        return 0;
    return page_level_shifts_4K[level];
}

static inline u64 pte_map_size(int level, pte entry)
{
    int order = pte_order(level, entry);
    return order ? U64_FROM_BIT(order) : INVALID_PHYSICAL;
}

static inline boolean pte_is_mapping(int level, pte entry)
{
    return ((level == 1 || level == 2) && (entry & PAGE_L0_2_DESC_TABLE) == 0) ||
        level == 3;
}

/* TODO: While the cpu type used under qemu is armv8.1-a, a read of
   ID_AA64MMFR1_EL1 does not indicate that hardware management of
   dirty pages is available (e.g. HD and HA bits are zero). If we
   can't depend on this feature, we'll need to set shared pages to
   read-only and track dirty state via a protection exception.
*/

static inline boolean pte_is_dirty(pte entry)
{
    // XXX TODO
    return false;
}

static inline void pt_pte_clean(pteptr pte)
{
    // XXX TODO
}

static inline u64 page_from_pte(pte pte)
{
    return pte & PAGE_4K_NEXT_TABLE_OR_PAGE_OUT_MASK;
}

#define table_from_pte page_from_pte

typedef closure_type(entry_handler, boolean /* success */, int /* level */,
        u64 /* vaddr */, pteptr /* entry */);

static inline pageflags pageflags_from_pteptr(pteptr pp)
{
    return (pageflags){.w = _PAGE_FLAGS_MASK & *pp};
}

void page_init_mmu(range init_pt, u64 vtarget);
void page_heap_init(heap locked, id_heap physical);
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
boolean traverse_ptes(u64 vaddr, u64 length, entry_handler eh);

flush_entry get_page_flush_entry(void);
void page_invalidate_sync(flush_entry f, thunk completion);
void page_invalidate(flush_entry f, u64 address);
void page_invalidate_flush(void);

void dump_ptes(void *vaddr);

static inline void map_and_zero(u64 v, physical p, u64 length, pageflags flags)
{
    assert((v & MASK(PAGELOG)) == 0);
    assert((p & MASK(PAGELOG)) == 0);
    if (pageflags_is_readonly(flags)) {
        map(v, p, length, pageflags_writable(flags));
        zero(pointer_from_u64(v), length);
        update_map_flags(v, length, flags);
    } else {
        map(v, p, length, flags);
        zero(pointer_from_u64(v), length);
    }
}
