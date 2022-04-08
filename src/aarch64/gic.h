#define GIC_SGI_INTS_START 0
#define GIC_SGI_INTS_END   16
#define GIC_PPI_INTS_START 16
#define GIC_PPI_INTS_END   32
#define GIC_SPI_INTS_START 32
#define GIC_SPI_INTS_END   (GIC_SPI_INTS_START + 256) /* virt */
#define GIC_LPI_INTS_START 8192
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

#define ICC_SGIxR_EL1_AFF3_SHIFT    48
#define ICC_SGIxR_EL1_RS_SHIFT      44
#define ICC_SGIxR_EL1_IRM           U64_FROM_BIT(40)
#define ICC_SGIxR_EL1_AFF2_SHIFT    32
#define ICC_SGIxR_EL1_INTID_SHIFT   24
#define ICC_SGIxR_EL1_AFF1_SHIFT    16

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
#define GICD_CTLR                   0x0000
#define GICD_CTLR_DISABLE           0
#define GICD_CTLR_ENABLEGRP0        1
#define GICD_CTLR_ENABLEGRP1        2
#define GICD_TYPER                  0x0004
#define GICD_IDbits_BITS            5
#define GICD_IDbits_SHIFT           19
#define GICD_num_LPIs_BITS          5
#define GICD_num_LPIs_SHIFT         11
#define GICD_ITLinesNumber_BITS     5
#define GICD_ITLinesNumber_SHIFT    0
#define GICD_IIDR                   0x0008
#define GICD_TYPER2                 0x000c
#define GICD_STATUSR                0x0010
#define GICD_SETSPI_NSR             0x0040
#define GICD_CLRSPI_NSR             0x0048
#define GICD_SETSPI_SR              0x0050
#define GICD_CLRSPI_SR              0x0058
#define GICD_IGROUPR(n)             (0x0080 + 4 * (n))
#define GICD_INTS_PER_IGROUP_REG    32
#define GICD_ISENABLER(n)           (0x0100 + 4 * (n))
#define GICD_ICENABLER(n)           (0x0180 + 4 * (n))
#define GICD_INTS_PER_IENABLE_REG   32
#define GICD_ISPENDR(n)             (0x0200 + 4 * (n))
#define GICD_ICPENDR(n)             (0x0280 + 4 * (n))
#define GICD_INTS_PER_IPEND_REG     32
#define GICD_ISACTIVER(n)           (0x0300 + 4 * (n))
#define GICD_ICACTIVER(n)           (0x0380 + 4 * (n))
#define GICD_IPRIORITYR(n)          (0x0400 + 4 * (n))
#define GICD_INTS_PER_IPRIORITY_REG 4
#define GICD_ITARGETSR(n)           (0x0800 + 4 * (n))
#define GICD_INTS_PER_ITARGETS_REG  4
#define GICD_ICFGR(n)               (0x0c00 + 4 * (n))
#define GICD_INTS_PER_ICFG_REG      16
#define GICD_ICFGR_LEVEL            0
#define GICD_ICFGR_EDGE             2
#define GICD_IGRPMODR(n)            0x0d00
#define GICD_NSACR(n)               0x0e00
#define GICD_SGIR                   0x0f00
#define GICD_TargetList_BCAST       U64_FROM_BIT(24)
#define GICD_CPUTargetList_SHIFT    16
#define GICD_SGIR_NSATT             U64_FROM_BIT(15)
#define GICD_CPENDSGIR(n)           0x0f10
#define GICD_SPENDSGIR(n)           0x0f20

#define GICR_CTLR                   0x0000
#define GICR_CTLR_EnableLPIs            U64_FROM_BIT(0)
#define GICR_IIDR                   0x0004
#define GICR_TYPER                  0x0008
#define GICR_TYPER_AFF3(type)           (((type) & 0xff00000000000000) >> 56)
#define GICR_TYPER_AFF2(type)           (((type) & 0x00ff000000000000) >> 48)
#define GICR_TYPER_AFF1(type)           (((type) & 0x0000ff0000000000) >> 40)
#define GICR_TYPER_AFF0(type)           (((type) & 0x000000ff00000000) >> 32)
#define GICR_TYPER_LAST                 U64_FROM_BIT(4)
#define GICR_TYPER_VLPIS                U64_FROM_BIT(1)
#define GICR_TYPER_PROC_NUM(type)       (((type) & 0xffff00) >> 8)
#define GICR_STATUSR                0x0010
#define GICR_WAKER                  0x0014
#define GICR_MPAMIDR                0x0018
#define GICR_PARTIDR                0x001c
#define GICR_SETLPIR                0x0040
#define GICR_CLRLPIR                0x0048
#define GICR_PROPBASER              0x0070
#define GICR_PENDBASER              0x0078
#define GICR_PENDBASER_PTZ              U64_FROM_BIT(62)
#define GICR_INVLPIR                0x00a0
#define GICR_INVALLR                0x00b0
#define GICR_SYNCR                  0x00c0

#define _GICR_OFFSET                0x10000
#define GICR_IGROUPR                (_GICR_OFFSET + 0x0080)
#define GICR_INTS_PER_IGROUP_REG    32
#define GICR_ISENABLER              (_GICR_OFFSET + 0x0100)
#define GICR_ICENABLER              (_GICR_OFFSET + 0x0180)
#define GICR_INTS_PER_IENABLE_REG   32
#define GICR_ISPENDR                (_GICR_OFFSET + 0x0200)
#define GICR_ICPENDR                (_GICR_OFFSET + 0x0280)
#define GICR_INTS_PER_IPEND_REG     32
#define GICR_ISACTIVER              (_GICR_OFFSET + 0x0300)
#define GICR_ICACTIVER              (_GICR_OFFSET + 0x0380)
#define GICR_IPRIORITYR(n)          (_GICR_OFFSET + 0x0400 + 4 * (n))
#define GICR_INTS_PER_IPRIORITY_REG 4
#define GICR_ICFGR(n)               (_GICR_OFFSET + 0x0c00 + 4 * (n))
#define GICR_INTS_PER_ICFG_REG      16

#define GICR_ICFGR_LEVEL 0
#define GICR_ICFGR_EDGE  2

/* Legacy (<v3) GICC interface */
#define GIC_CPU_REG(offset)                  (mmio_base_addr(GIC_CPU + (offset)))
#define GICC_CTLR                            GIC_CPU_REG(0x0000)
#define GICC_CTLR_EOImode                    0x100
#define GICC_CTLR_AckCtl                     0x004
#define GICC_CTLR_EnableGrp1                 0x002
#define GICC_CTLR_EnableGrp0                 0x001
#define GICC_PMR                             GIC_CPU_REG(0x0004)
#define GICC_BPR                             GIC_CPU_REG(0x0008)
#define GICC_IAR                             GIC_CPU_REG(0x000c)
#define GICC_EOIR                            GIC_CPU_REG(0x0010)
#define GICC_RPR                             GIC_CPU_REG(0x0014)
#define GICC_HPPIR                           GIC_CPU_REG(0x0018)
#define GICC_ABPR                            GIC_CPU_REG(0x001c)
#define GICC_AIAR                            GIC_CPU_REG(0x0020)
#define GICC_AEOIR                           GIC_CPU_REG(0x0024)
#define GICC_AHPPIR                          GIC_CPU_REG(0x0028)
#define GICC_APR(n)                          GIC_CPU_REG(0x00d0 + 4 * (n))
#define GICC_NSAPR(n)                        GIC_CPU_REG(0x00e0 + 4 * (n))
#define GICC_IIDR                            GIC_CPU_REG(0x00fc)
#define GICC_IIDR_ProductID_BITS             12
#define GICC_IIDR_ProductID_SHIFT            20
#define GICC_IIDR_Architecture_version_BITS  4
#define GICC_IIDR_Architecture_version_SHIFT 16
#define GICC_IIDR_Revision_BITS              4
#define GICC_IIDR_Revision_SHIFT             12
#define GICC_IIDR_Implementer_BITS           12
#define GICC_IIDR_Implementer_SHIFT          0
#define GICC_DIR                             GIC_CPU_REG(0x1000)

#define GIC_V2M_REG(offset)          (mmio_base_addr(GIC_V2M + (offset)))
#define GIC_V2M_MSI_TYPER            GIC_V2M_REG(0x8)
#define GIC_V2M_MSI_TYPER_BASE_BITS  11
#define GIC_V2M_MSI_TYPER_BASE_SHIFT 16
#define GIC_V2M_MSI_TYPER_NUM_BITS   11
#define GIC_V2M_MSI_TYPER_NUM_SHIFT  0
#define GIC_V2M_MSI_SETSPI_NS        0x40
#define GIC_V2M_MSI_IIDR             GIC_V2M_REG(0xfcc)

/* Interrupt Translation Service */

#define GITS_CTLR       0x0000
#define GITS_CTRL_ENABLED   U64_FROM_BIT(0)
#define GITS_IIDR       0x0004
#define GITS_TYPER      0x0008
#define GITS_TYPER_PTA              U64_FROM_BIT(19)
#define GITS_ITT_entry_size(type)   (((type) & 0xf0) >> 4)
#define GITS_MPAMIDR    0x0010
#define GITS_PARTIDR    0x0014
#define GITS_MPIDR      0x0018
#define GITS_STATUSR    0x0040
#define GITS_UMSIR      0x0048
#define GITS_CBASER     0x0080
#define GITS_CBASER_VALID   U64_FROM_BIT(63)
#define GITS_CWRITER    0x0088
#define GITS_CREADR     0x0090
#define GITS_CREADR_STALLED U64_FROM_BIT(0)
#define GITS_BASER(n)   (0x0100 + (n) * 8)
#define GITS_BASER_VALID                U64_FROM_BIT(63)
#define GITS_TABLE_TYPE(baser)          (((baser) & 0x700000000000000ull) >> 56)
#define GITS_TABLE_ENTRY_SIZE(baser)    (((baser) & 0x1f000000000000ull) >> 48)
#define GITS_TABLE_DEVICES              0b001
#define GITS_TABLE_COLLECTIONS          0b100
#define GITS_BASE_PA_MASK               0xfffffffff000
#define GITS_PAGE_SIZE(baser)           (((baser) & 0x300) >> 8)
#define GITS_PGSZ_4K                    0b00
#define GITS_PGSZ_16K                   0b01
#define GITS_PGSZ_64K                   0b10

#define GITS_TRANSLATER 0x10040

#define ITS_CMD_CLEAR   0x04
#define ITS_CMD_DISCARD 0x0f
#define ITS_CMD_INT     0x03
#define ITS_CMD_INV     0x0c
#define ITS_CMD_INVALL  0x0d
#define ITS_CMD_MAPC    0x09
#define ITS_MAPC_V          U64_FROM_BIT(63)
#define ITS_CMD_MAPD    0x08
#define ITS_MAPD_V          U64_FROM_BIT(63)
#define ITS_CMD_MAPI    0x0b
#define ITS_CMD_MAPTI   0x0a
#define ITS_CMD_MOVALL  0x0e
#define ITS_CMD_MOVI    0x01
#define ITS_CMD_SYNC    0x05

extern u16 gic_msi_vector_base;
extern u16 gic_msi_vector_num;

void gic_disable_int(int irq);
void gic_enable_int(int irq);
void gic_clear_pending_int(int irq);
void gic_set_int_priority(int irq, u32 pri);
void gic_set_int_config(int irq, u32 cfg);
boolean gic_int_is_pending(int irq);
u64 gic_dispatch_int(void);
void gic_eoi(int irq);
int init_gic(void);
void gic_percpu_init(void);

#define _GIC_SET_INTFIELD(name, type) void gic_set_int_##name(int irq, u32 v);
_GIC_SET_INTFIELD(priority, IPRIORITY)
_GIC_SET_INTFIELD(config, ICFG)
#undef _GIC_SET_INTFIELD
