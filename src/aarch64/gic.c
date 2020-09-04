#include <kernel.h>
#include <gic.h>

/* v3 / v4 only */

boolean gic_intid_24bit;

// TODO
// set target cpu (mask)
// set priority
// config timer irq

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
    while (gic_dispatch_int() != INTID_NO_PENDING);

    /* enable */
    write_psr_s(ICC_IGRPEN0_EL1, 1);
}

void init_gic(void)
{
    u64 icc_ctlr = read_psr_s(ICC_CTLR_EL1);
    gic_intid_24bit = (field_from_u64(icc_ctlr, ICC_CTLR_EL1_IDbits) ==
                       ICC_CTLR_EL1_IDbits_24);
    init_gicd();
    init_gicc();
}
