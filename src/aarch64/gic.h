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
#define GICD_IGRPMODR(n)   (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0d00 + 4 * (n)))
#define GICD_NSACR(n)      (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0e00 + 4 * (n)))
#define GICD_SGIR          (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f00))
#define GICD_CPENDSGIR(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f10 + 4 * (n)))
#define GICD_SPENDSGIR(n)  (*(volatile u32 *)(dev_base_pointer(GIC_DIST) + 0x0f20 + 4 * (n)))

void gic_disable_int(int irq);
void gic_enable_int(int irq);
void gic_clear_pending_int(int irq);
void gic_set_int_priority(int irq, u32 pri);
void gic_set_int_config(int irq, u32 cfg);
boolean gic_int_is_pending(int irq);
u64 gic_dispatch_int(void);
void gic_eoi(int irq);
void init_gic(void);
