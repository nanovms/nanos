#define GIC_SGI_INTS_START 0
#define GIC_SGI_INTS_END   16
#define GIC_PPI_INTS_START 16
#define GIC_PPI_INTS_END   32
#define GIC_SPI_INTS_START 32
#define GIC_SPI_INTS_END   1019
#define GIC_MAX_INT        GIC_SPI_INTS_END
#define GIC_MAX_PRIO       16
#define GIC_TIMER_IRQ      27

#define ICC_PMR_EL1     "S3_0_C4_C6_0"
#define ICC_IAR0_EL1    "S3_0_C12_C8_0"
#define ICC_EOIR0_EL1   "S3_0_C12_C8_1"
#define ICC_HPPIR0_EL1  "S3_0_C12_C8_2"
#define ICC_BPR0_EL1    "S3_0_C12_C8_3"
//#define ICC_AP0R<n>_EL1
//#define ICC_AP1R<n>_EL1
#define ICC_DIR_EL1     "S3_0_C12_C11_1"
#define ICC_RPR_EL1     "S3_0_C12_C11_3"
#define ICC_SGI1R_EL1   "S3_0_C12_C11_5"
#define ICC_ASGI1R_EL1  "S3_0_C12_C11_6"
#define ICC_SGI0R_EL1   "S3_0_C12_C11_7"
#define ICC_IAR1_EL1    "S3_0_C12_C12_0"
#define ICC_EOIR1_EL1   "S3_0_C12_C12_1"
#define ICC_HPPIR1_EL1  "S3_0_C12_C12_2"
#define ICC_BPR1_EL1    "S3_0_C12_C12_3"
#define ICC_CTLR_EL1    "S3_0_C12_C12_4"
#define ICC_SRE_EL1     "S3_0_C12_C12_5"
#define ICC_IGRPEN0_EL1 "S3_0_C12_C12_6"
#define ICC_IGRPEN1_EL1 "S3_0_C12_C12_7"
#define ICC_SRE_EL2     "S3_4_C12_C9_5"
#define ICC_CTLR_EL3    "S3_6_C12_C12_4"
#define ICC_SRE_EL3     "S3_6_C12_C12_5"
#define ICC_IGRPEN1_EL3 "S3_6_C12_C12_7"

#define ICC_CTLR_EL1_ExtRange      U64_FROM_BIT(19)
#define ICC_CTLR_EL1_RSS           U64_FROM_BIT(18)
#define ICC_CTLR_EL1_A3V           U64_FROM_BIT(15)
#define ICC_CTLR_EL1_SEIS          U64_FROM_BIT(14)
#define ICC_CTLR_EL1_IDbits_BITS   3
#define ICC_CTLR_EL1_IDbits_SHIFT  11
#define ICC_CTLR_EL1_IDbits_16     0
#define ICC_CTLR_EL1_IDbits_24     1
#define ICC_CTLR_EL1_PRIbits_BITS  3
#define ICC_CTLR_EL1_PRIbits_SHIFT 8
#define ICC_CTLR_EL1_EOImode       U64_FROM_BIT(1)
#define ICC_CTLR_EL1_CBPR          U64_FROM_BIT(0)

#define ICC_IGRPENx_ENABLE 1

#define INTID_NO_PENDING 1023

/* GIC Distributor */
#define GICD_CTLR          (*(volatile u32 *)(dev_base_pointer(GIC_DIST)))
#define GICD_CTLR_DISABLE    0
#define GICD_CTLR_ENABLEGRP0 1
#define GICD_CTLR_ENABLEGRP1 2
#define GICD_TYPER         (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0004))
#define GICD_ITLinesNumber_BITS  5
#define GICD_ITLinesNumber_SHIFT 0
#define GICD_IIDR          (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0008))
#define GICD_TYPER2        (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x000c))
#define GICD_STATUSR       (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0010))
#define GICD_SETSPI_NSR    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0040))
#define GICD_CLRSPI_NSR    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0048))
#define GICD_SETSPI_SR     (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0050))
#define GICD_CLRSPI_SR     (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0058))
#define GICD_IGROUPR(n)    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0080 + 4 * (n)))
#define GICD_INTS_PER_IGROUP_REG 32
#define GICD_ISENABLER(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0100 + 4 * (n)))
#define GICD_ICENABLER(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0180 + 4 * (n)))
#define GICD_INTS_PER_IENABLE_REG 32
#define GICD_ISPENDR(n)    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0200 + 4 * (n)))
#define GICD_ICPENDR(n)    (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0280 + 4 * (n)))
#define GICD_INTS_PER_IPEND_REG 32
#define GICD_ISACTIVER(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0300 + 4 * (n)))
#define GICD_ICACTIVER(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0380 + 4 * (n)))
#define GICD_IPRIORITYR(n) (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0400 + 4 * (n)))
#define GICD_INTS_PER_IPRIORITY_REG 4
#define GICD_ITARGETSR(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0800 + 4 * (n)))
#define GICD_INTS_PER_ITARGETS_REG 4
#define GICD_ICFGR(n)      (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0c00 + 4 * (n)))
#define GICD_INTS_PER_ICFG_REG 16

#define GICD_ICFGR_LEVEL 0
#define GICD_ICFGR_EDGE  2
#define GICD_IGRPMODR(n)   (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0d00))
#define GICD_NSACR(n)      (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0e00))
#define GICD_SGIR          (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f00))
#define GICD_CPENDSGIR(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f10))
#define GICD_SPENDSGIR(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f20))

#define _GICR_OFFSET (dev_base_pointer(GIC_REDIST) + 0x10000)
#define GICR_IGROUPR       (*(volatile u32 *)(_GICR_OFFSET + 0x0080))
#define GICR_INTS_PER_IGROUP_REG 32
#define GICR_ISENABLER     (*(volatile u32 *)(_GICR_OFFSET + 0x0100))
#define GICR_ICENABLER     (*(volatile u32 *)(_GICR_OFFSET + 0x0180))
#define GICR_INTS_PER_IENABLE_REG 32
#define GICR_ISPENDR       (*(volatile u32 *)(_GICR_OFFSET + 0x0200))
#define GICR_ICPENDR       (*(volatile u32 *)(_GICR_OFFSET + 0x0280))
#define GICR_INTS_PER_IPEND_REG 32
#define GICR_ISACTIVER     (*(volatile u32 *)(_GICR_OFFSET + 0x0300))
#define GICR_ICACTIVER     (*(volatile u32 *)(_GICR_OFFSET + 0x0380))
#define GICR_IPRIORITYR    (*(volatile u32 *)(_GICR_OFFSET + 0x0400))
#define GICR_INTS_PER_IPRIORITY_REG 4
#define GICR_ITARGETSR     (*(volatile u32 *)(_GICR_OFFSET + 0x0800))
#define GICR_INTS_PER_ITARGETS_REG 4
#define GICR_ICFGR         (*(volatile u32 *)(_GICR_OFFSET + 0x0c00))
#define GICR_INTS_PER_ICFG_REG 16

#define GICR_ICFGR_LEVEL 0
#define GICR_ICFGR_EDGE  2

/* Legacy (<v3) GICC interface */
#define GIC_CPU_REG(offset)  (*(volatile u32 *)(dev_base_pointer(GIC_CPU + (offset))))
#define GICC_CTLR            GIC_CPU_REG(0x0000)
#define GICC_CTLR_EOImode    0x100
#define GICC_CTLR_AckCtl     0x004
#define GICC_CTLR_EnableGrp1 0x002
#define GICC_CTLR_EnableGrp0 0x001
#define GICC_PMR             GIC_CPU_REG(0x0004)
#define GICC_BPR             GIC_CPU_REG(0x0008)
#define GICC_IAR             GIC_CPU_REG(0x000c)
#define GICC_EOIR            GIC_CPU_REG(0x0010)
#define GICC_RPR             GIC_CPU_REG(0x0014)
#define GICC_HPPIR           GIC_CPU_REG(0x0018)
#define GICC_ABPR            GIC_CPU_REG(0x001c)
#define GICC_AIAR            GIC_CPU_REG(0x0020)
#define GICC_AEOIR           GIC_CPU_REG(0x0024)
#define GICC_AHPPIR          GIC_CPU_REG(0x0028)
#define GICC_APR(n)          GIC_CPU_REG(0x00d0 + 4 * (n))
#define GICC_NSAPR(n)        GIC_CPU_REG(0x00e0 + 4 * (n))
#define GICC_IIDR            GIC_CPU_REG(0x00fc)
#define GICC_IIDR_ProductID_BITS             12
#define GICC_IIDR_ProductID_SHIFT            20
#define GICC_IIDR_Architecture_version_BITS  4
#define GICC_IIDR_Architecture_version_SHIFT 16
#define GICC_IIDR_Revision_BITS              4
#define GICC_IIDR_Revision_SHIFT             12
#define GICC_IIDR_Implementer_BITS           12
#define GICC_IIDR_Implementer_SHIFT          0
#define GICC_DIR             GIC_CPU_REG(0x1000)

#define GIC_V2M_MSI_TYPER            0x8
#define GIC_V2M_MSI_TYPER_BASE_BITS  11
#define GIC_V2M_MSI_TYPER_BASE_SHIFT 16
#define GIC_V2M_MSI_TYPER_NUM_BITS   11
#define GIC_V2M_MSI_TYPER_NUM_SHIFT  0
#define GIC_V2M_MSI_SETSPI_NS        0x40
#define GIC_V2M_MSI_IIDR             0xfcc

void gic_disable_int(int irq);
void gic_enable_int(int irq);
void gic_clear_pending_int(int irq);
void gic_set_int_priority(int irq, u32 pri);
void gic_set_int_config(int irq, u32 cfg);
boolean gic_int_is_pending(int irq);
u64 gic_dispatch_int(void);
void gic_eoi(int irq);
void init_gic(void);

#define _GIC_SET_INTFIELD(name, type) void gic_set_int_##name(int irq, u32 v);
_GIC_SET_INTFIELD(priority, IPRIORITY)
_GIC_SET_INTFIELD(config, ICFG)
_GIC_SET_INTFIELD(target, ITARGETS)
#undef _GIC_SET_INTFIELD
