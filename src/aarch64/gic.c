#include <kernel.h>
#include <gic.h>

#define ICC_PMR_EL1     "S3_0_C4_C6_0"
#define ICC_IAR0_EL1    "S3_0_C12_C8_0"
#define ICC_EOIR0_EL1   "S3_0_C12_C8_1"
#define ICC_HPPIR0_EL1  "S3_0_C12_C8_2"
#define ICC_BPR0_EL1    "S3_0_C12_C8_3"
//#define ICC_AP0R<n>_EL1 32 4-7 RW, <n> = Op2 -4
//#define ICC_AP1R<n>_EL1 32 9 0-3 RW, <n> = Op2
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

#if 0
#define make_sreg(op0, op1, crn, crm, op2) \
    (((op0) << 19) | ((op1) << 16) | ((crn) << 12) | ((crm) << 8) | ((op2) << 5))

#define ICC_PMR_EL1     make_sreg(3, 0, 4, 6, 0)
#define ICC_IAR0_EL1    make_sreg(3, 0, 12, 8, 0)
#define ICC_EOIR0_EL1   make_sreg(3, 0, 12, 8, 1)
#define ICC_HPPIR0_EL1  make_sreg(3, 0, 12, 8, 2)
#define ICC_BPR0_EL1    make_sreg(3, 0, 12, 8, 3)
//#define ICC_AP0R<n>_EL1 32 4-7 RW, <n> = Op2 -4
//#define ICC_AP1R<n>_EL1 32 9 0-3 RW, <n> = Op2
#define ICC_DIR_EL1     make_sreg(3, 0, 12, 11, 1)
#define ICC_RPR_EL1     make_sreg(3, 0, 12, 11, 3)
#define ICC_SGI1R_EL1   make_sreg(3, 0, 12, 11, 5)
#define ICC_ASGI1R_EL1  make_sreg(3, 0, 12, 11, 6)
#define ICC_SGI0R_EL1   make_sreg(3, 0, 12, 11, 7)
#define ICC_IAR1_EL1    make_sreg(3, 0, 12, 12, 0)
#define ICC_EOIR1_EL1   make_sreg(3, 0, 12, 12, 1)
#define ICC_HPPIR1_EL1  make_sreg(3, 0, 12, 12, 2)
#define ICC_BPR1_EL1    make_sreg(3, 0, 12, 12, 3)
#define ICC_CTLR_EL1    make_sreg(3, 0, 12, 12, 4)
#define ICC_SRE_EL1     make_sreg(3, 0, 12, 12, 5)
#define ICC_IGRPEN0_EL1 make_sreg(3, 0, 12, 12, 6)
#define ICC_IGRPEN1_EL1 make_sreg(3, 0, 12, 12, 7)
#define ICC_SRE_EL2     make_sreg(3, 4, 12, 9, 5)
#define ICC_CTLR_EL3    make_sreg(3, 6, 12, 12, 4)
#define ICC_SRE_EL3     make_sreg(3, 6, 12, 12, 5)
#define ICC_IGRPEN1_EL3 make_sreg(3, 6, 12, 12, 7)
#endif

/* v3 / v4 only */

static boolean intid_24bit;

// set target cpu (mask)

// set priority

// config irq

static inline void disable_int(int irq)
{
    GICD_ICENABLER(irq / GICD_INTS_PER_IENABLE_REG) =
        U32_FROM_BIT(irq & (GICD_INTS_PER_IENABLE_REG - 1));
}

static inline void enable_int(int irq)
{
    GICD_ISENABLER(irq / GICD_INTS_PER_IENABLE_REG) =
        U32_FROM_BIT(irq & (GICD_INTS_PER_IENABLE_REG - 1));
}

static inline void clear_pending_int(int irq)
{
    GICD_ICPENDR(irq / GICD_INTS_PER_IPEND_REG) =
        U32_FROM_BIT(irq & (GICD_INTS_PER_IPEND_REG - 1));
}

static inline boolean int_is_pending(int irq)
{
    return (GICD_ISPENDR(irq / GICD_INTS_PER_IPEND_REG) &
            U32_FROM_BIT(irq & (GICD_INTS_PER_IPEND_REG - 1))) != 0;
}

static inline u64 dispatch_int(void)
{
    return read_psr_s(ICC_IAR1_EL1) & (intid_24bit ? MASK(24) : MASK(16));
}

void gic_eoi(int irq)
{
    clear_pending_int(irq);
}

void init_gicd(void)
{
    GICD_CTLR = GICD_CTLR_DISABLE;

    /* disable and clear pending */
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IENABLE_REG; i++)
        GICD_ICENABLER(i) = MASK(32);
    
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IPEND_REG; i++)
        GICD_ICPENDR(i) = MASK(32);

    /* set all to low priority */
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IPRIORITY_REG; i++)
        GICD_IPRIORITYR(i) = MASK(32); /* low priority */

    /* shared periph target cpu0 */
    for (int i = GIC_SPI_INTS_START / GICD_INTS_PER_ITARGET_REG;
         i < GIC_SPI_INTS_END / GICD_INTS_PER_ITARGET_REG; i++)
        GICD_ITARGETSR(i) = 0x01010101; /* int target cpu0 */

    /* set all to level triggered */
    for (int i = GIC_PPI_INTS_START / GICD_INTS_PER_ICFG_REG;
         i < GIC_PPI_INTS_END / GICD_INTS_PER_ICFG_REG; i++)
        GICD_ICFGR(i) = 0; /* all level */
    
    /* enable */
    GICD_CTLR = GICD_CTLR_ENABLEGRP0;
}

void init_gicc(void)
{
    /* disable all interrupt groups */
    write_psr_s(ICC_IGRPEN0_EL1, 0);
    write_psr_s(ICC_IGRPEN1_EL1, 0);
    
    /* GICC_PMR - lowest pri? revisit */
    write_psr_s(ICC_PMR_EL1, 0xff);

    /* GICC_BPR - no group? */
    write_psr_s(ICC_BPR0_EL1, 0); /*  */

    /* clear active */
    while (dispatch_int() != INTID_NO_PENDING);

    /* enable */
    write_psr_s(ICC_IGRPEN0_EL1, 1);
}

void init_gic(void)
{
    u64 icc_ctlr = read_psr_s(ICC_CTLR_EL1);
    intid_24bit = (field_from_u64(icc_ctlr, ICC_CTLR_EL1_IDbits) ==
                   ICC_CTLR_EL1_IDbits_24);
    init_gicd();
    init_gicc();

    // config timer irq

}
