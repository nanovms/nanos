#include <kernel.h>
#include <gic.h>

/* v3 / v4 only */

//#define GIC_DEBUG
#ifdef GIC_DEBUG
#define gic_debug(x, ...) do {rprintf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define gic_debug(x, ...)
#endif

static boolean gic_intid_24bit;

void gic_disable_int(int irq)
{
    gic_debug("irq %d\n", irq);
    GICD_ICENABLER(irq / GICD_INTS_PER_IENABLE_REG) =
        U32_FROM_BIT(irq & (GICD_INTS_PER_IENABLE_REG - 1));
}

void gic_enable_int(int irq)
{
    gic_debug("irq %d\n", irq);
    GICD_ISENABLER(irq / GICD_INTS_PER_IENABLE_REG) =
        U32_FROM_BIT(irq & (GICD_INTS_PER_IENABLE_REG - 1));
}

void gic_clear_pending_int(int irq)
{
    gic_debug("irq %d\n", irq);
    u32 v = U32_FROM_BIT(irq & (GICD_INTS_PER_IPEND_REG - 1));
    gic_debug("   v 0x%x, %p\n", v, & GICD_ICPENDR(irq / GICD_INTS_PER_IPEND_REG));
    GICD_ICPENDR(irq / GICD_INTS_PER_IPEND_REG) = v;
}

#define GIC_SET_INTFIELD(name, type)                                    \
    void gic_set_int_##name(int irq, u32 v)                             \
    {                                                                   \
        int w = 32 / GICD_INTS_PER_ ## type ## _REG;                    \
        int r = irq / GICD_INTS_PER_ ## type ## _REG;                   \
        u32 i = GICD_ ## type ## R(r);                                  \
        int s = (irq % GICD_INTS_PER_ ## type ## _REG) * w;             \
        u32 n = (i & ~(MASK32(w) << s)) | (v << s);                     \
        GICD_ ## type ## R(r) = n;                                      \
        gic_debug("irq %d, v %d, reg was 0x%x, now 0x%x\n", irq, v, i, n); \
    }

GIC_SET_INTFIELD(priority, IPRIORITY)
GIC_SET_INTFIELD(config, ICFG)
GIC_SET_INTFIELD(target, ITARGETS)

boolean gic_int_is_pending(int irq)
{
    boolean pending = (GICD_ISPENDR(irq / GICD_INTS_PER_IPEND_REG) &
                       U32_FROM_BIT(irq & (GICD_INTS_PER_IPEND_REG - 1))) != 0;
    gic_debug("irq %d, pending %d\n", irq, pending);
    return pending;
}

u64 gic_dispatch_int(void)
{
    u64 v = read_psr_s(ICC_IAR1_EL1) & (gic_intid_24bit ? MASK(24) : MASK(16));
    gic_debug("intid %ld\n", v);
    return v;
}

void gic_eoi(int irq)
{
    gic_debug("irq\n", irq);
    write_psr_s(ICC_EOIR1_EL1, irq);
    gic_clear_pending_int(irq);
}

// TODO
// set target cpu (mask)

static void init_gicd(void)
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

    /* set all to group 1, non-secure */
    for (int i = GIC_SPI_INTS_START / GICD_INTS_PER_IGROUP_REG;
         i < GIC_SPI_INTS_END / GICD_INTS_PER_IGROUP_REG; i++)
        GICD_IGROUPR(i) = MASK(32);

    /* shared periph target cpu0 */
    for (int i = GIC_SPI_INTS_START / GICD_INTS_PER_ITARGETS_REG;
         i < GIC_SPI_INTS_END / GICD_INTS_PER_ITARGETS_REG; i++)
        GICD_ITARGETSR(i) = 0x01010101; /* int target cpu0 */

    /* set all to level triggered, active low */
    for (int i = GIC_PPI_INTS_START / GICD_INTS_PER_ICFG_REG;
         i < GIC_PPI_INTS_END / GICD_INTS_PER_ICFG_REG; i++)
        GICD_ICFGR(i) = 0; /* all level */
    
    /* enable
       XXX - turn on affinity routing (ARE)? */
    GICD_CTLR = GICD_CTLR_ENABLEGRP1;
}

static void init_gicc(void)
{
    /* disable all interrupt groups */
    write_psr_s(ICC_IGRPEN0_EL1, 0);
    write_psr_s(ICC_IGRPEN1_EL1, 0);
    
    /* GICC_PMR - lowest pri? revisit */
    write_psr_s(ICC_PMR_EL1, 0xfc);

    /* GICC_BPR - no group? */
    write_psr_s(ICC_BPR0_EL1, 0);

    /* no EOI mode */
    u64 v = read_psr_s(ICC_CTLR_EL1);
    write_psr_s(ICC_CTLR_EL1, v & ~ICC_CTLR_EL1_EOImode);

    /* clear active */
    while (gic_dispatch_int() != INTID_NO_PENDING);

    /* enable */
    write_psr_s(ICC_IGRPEN1_EL1, ICC_IGRPENx_ENABLE);
}

void init_gic(void)
{
    u64 icc_ctlr = read_psr_s(ICC_CTLR_EL1);
    gic_intid_24bit = (field_from_u64(icc_ctlr, ICC_CTLR_EL1_IDbits) ==
                       ICC_CTLR_EL1_IDbits_24);
    init_gicd();
    init_gicc();
}
