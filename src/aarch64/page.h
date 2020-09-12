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
#define PAGE_ATTR_AP_2_1_SHIFT   6
#define PAGE_ATTR_AP_2_1_BITS    2
#define PAGE_ATTR_NS             U64_FROM_BIT(5)
#define PAGE_ATTR_ATTRINDX_SHIFT 2
#define PAGE_ATTR_ATTRINDX_BITS  3

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

#define MAIR_EL1(i, v)  (((u64)v) << ((i) * 8))
#define MAIR_EL1_INIT (MAIR_EL1(0, MAIR_EL1_DEV_nGnRnE) |       \
                       MAIR_EL1(1, MAIR_EL1_DEV_nGnRE) |        \
                       MAIR_EL1(2, MAIR_EL1_DEV_GRE) |          \
                       MAIR_EL1(3, MAIR_EL1_NORM_NC) |          \
                       MAIR_EL1(4, MAIR_EL1_NORM) |             \
                       MAIR_EL1(5, MAIR_EL1_NORM_WT))

/* XXX TODO revisit */
#define PAGE_BACKED_FLAGS 0
#define PAGE_DEV_FLAGS 0
#define PAGE_NO_EXEC 0
#define PAGE_WRITABLE 0

void page_init_mmu(range init_pt, u64 vtarget);
void map(u64 virtual, physical p, u64 length, u64 flags);
void unmap(u64 virtual, u64 length);
