#include <kernel.h>
#include <gic.h>

//#define GIC_DEBUG
#ifdef GIC_DEBUG
#define gic_debug(x, ...) do {rprintf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define gic_debug(x, ...)
#endif

static boolean gicc_v3_iface;
static u32 gic_intid_mask;

void gic_disable_int(int irq)
{
    int w = irq / GICD_INTS_PER_IENABLE_REG;
    u64 a = (!gicc_v3_iface || w) ? GICD_ICENABLER(w) : GICR_ICENABLER;
    u32 x = U32_FROM_BIT(irq & (GICD_INTS_PER_IENABLE_REG - 1)); /* same as redist */
    gic_debug("irq %d, a 0x%lx, x 0x%x, before 0x%x\n", irq, a, x, mmio_read_32(a));
    mmio_write_32(a, x);
}

void gic_enable_int(int irq)
{
    int w = irq / GICD_INTS_PER_IENABLE_REG;
    u64 a = (!gicc_v3_iface || w) ? GICD_ISENABLER(w) : GICR_ISENABLER;
    u32 x = U32_FROM_BIT(irq & (GICD_INTS_PER_IENABLE_REG - 1));
    gic_debug("irq %d, x 0x%lx, x 0x%x, before 0x%x\n", irq, a, x, mmio_read_32(a));
    mmio_write_32(a, x);
}

void gic_clear_pending_int(int irq)
{
    int w = irq / GICD_INTS_PER_IPEND_REG;
    u64 a = (!gicc_v3_iface || w) ? GICD_ICPENDR(w) : GICR_ICPENDR;
    u32 x = U32_FROM_BIT(irq & (GICD_INTS_PER_IPEND_REG - 1));
    gic_debug("irq %d, a 0x%lx, x 0x%x, before 0x%x\n", irq, a, x, mmio_read_32(a));
    mmio_write_32(a, x);
}

#define GIC_SET_INTFIELD(name, type)                                    \
    void gic_set_int_##name(int irq, u32 v)                             \
    {                                                                   \
        int w = 32 / GICD_INTS_PER_ ## type ## _REG;                    \
        int r = irq / GICD_INTS_PER_ ## type ## _REG;                   \
        u32 i;                                                          \
        if (!gicc_v3_iface || r)                                        \
            i = mmio_read_32(GICD_ ## type ## R(r));                    \
        else                                                            \
            i = mmio_read_32(GICR_ ## type ## R);                       \
        int s = (irq % GICD_INTS_PER_ ## type ## _REG) * w;             \
        u32 n = (i & ~(MASK32(w) << s)) | (v << s);                     \
        if (!gicc_v3_iface || r)                                        \
            mmio_write_32(GICD_ ## type ## R(r), n);                    \
        else                                                            \
            mmio_write_32(GICR_ ## type ## R, n);                       \
        gic_debug("irq %d, v %d, reg was 0x%x, now 0x%x\n", irq, v, i, n); \
    }

GIC_SET_INTFIELD(priority, IPRIORITY)
GIC_SET_INTFIELD(config, ICFG)
GIC_SET_INTFIELD(target, ITARGETS)

boolean gic_int_is_pending(int irq)
{
    int w = irq / GICD_INTS_PER_IPEND_REG;
    u64 a = (!gicc_v3_iface || w) ? GICD_ISPENDR(w) : GICR_ISPENDR;
    boolean pending = (mmio_read_32(a) & U32_FROM_BIT(irq & (GICD_INTS_PER_IPEND_REG - 1))) != 0;
    gic_debug("irq %d, pending %d\n", irq, pending);
    return pending;
}

static void init_gicd(void)
{
    mmio_write_32(GICD_CTLR, GICD_CTLR_DISABLE);

    /* disable and clear pending */
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IENABLE_REG; i++)
        mmio_write_32(GICD_ICENABLER(i), MASK(32));
    
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IPEND_REG; i++)
        mmio_write_32(GICD_ICPENDR(i), MASK(32));

    /* set all to low priority */
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IPRIORITY_REG; i++)
        mmio_write_32(GICD_IPRIORITYR(i), MASK(32));

    /* set all to group 1, non-secure */
    if (gicc_v3_iface)
        mmio_write_32(GICR_IGROUPR, MASK(32));
    else
        mmio_write_32(GICD_IGROUPR(0), MASK(32));
    for (int i = GIC_SPI_INTS_START / GICD_INTS_PER_IGROUP_REG;
         i < GIC_SPI_INTS_END / GICD_INTS_PER_IGROUP_REG; i++)
        mmio_write_32(GICD_IGROUPR(i), MASK(32));

    /* shared periph target cpu0 */
    for (int i = GIC_SPI_INTS_START / GICD_INTS_PER_ITARGETS_REG;
         i < GIC_SPI_INTS_END / GICD_INTS_PER_ITARGETS_REG; i++)
        mmio_write_32(GICD_ITARGETSR(i), 0x01010101);

    /* set all to level triggered, active low */
    for (int i = GIC_PPI_INTS_START / GICD_INTS_PER_ICFG_REG;
         i < GIC_PPI_INTS_END / GICD_INTS_PER_ICFG_REG; i++)
        mmio_write_32(GICD_ICFGR(i), 0); /* all level */
    
    /* enable
       XXX - turn on affinity routing (ARE)? */

    /* Kludge: We seem to have one gicv2 variant (qemu w/ noaccel) that honors
       bit 1 as GRP1 enable, and another (qemu w/ kvm on bcm2711) which
       doesn't, so set both for now until the variants can be sorted
       out. (This may be due to the presence of GIC Security Extensions. */
    mmio_write_32(GICD_CTLR, GICD_CTLR_ENABLEGRP1 | GICD_CTLR_ENABLEGRP0);
}

/* aliases for macro use */
#define GICC_BPR0 GICC_BPR
#define GICC_IAR1 GICC_IAR
#define GICC_EOIR1 GICC_EOIR

#define gicc_read(reg) (gicc_v3_iface ? read_psr_s(ICC_ ## reg ## _EL1) : (GICC_ ## reg))
#define gicc_write(reg, v) do { if (gicc_v3_iface) write_psr_s(ICC_ ## reg ## _EL1, (v)); \
        else mmio_write_32(GICC_ ## reg, v); } while (0)
#define gicc_set(reg, v) do { gicc_write(reg, gicc_read(reg) | (v)); } while(0)
#define gicc_clear(reg, v) do { gicc_write(reg, gicc_read(reg) & ~(v)); } while(0)

u64 gic_dispatch_int(void)
{
    u64 v = (gicc_v3_iface ? read_psr_s(ICC_IAR1_EL1) : mmio_read_32(GICC_IAR)) & gic_intid_mask;
    gic_debug("intid %ld\n", v);
    return v;
}

void gic_eoi(int irq)
{
    gic_debug("irq %d\n", irq);
    gicc_write(EOIR1, irq);
}

void msi_format(u32 *address, u32 *data, int vector)
{
    *address = DEV_BASE_GIC_V2M + GIC_V2M_MSI_SETSPI_NS;
    *data = vector;
}

static void init_gicc(void)
{
    /* disable all interrupt groups */
    if (gicc_v3_iface) {
        write_psr_s(ICC_IGRPEN0_EL1, 0);
        write_psr_s(ICC_IGRPEN1_EL1, 0);
    } else {
        /* XXX Not seeing issues yet, but this is another register whose
           bitfields get shuffled when GIC Security Extensions are
           enabled. These bit values may need revisiting. */
        mmio_write_32(GICC_CTLR, mmio_read_32(GICC_CTLR) & ~(GICC_CTLR_EnableGrp1 | GICC_CTLR_EnableGrp0));
    }
    
    /* GICC_PMR - lowest pri? revisit */
    gicc_write(PMR, 0xfc);

    /* GICC_BPR - no group? */
    gicc_write(BPR0, 0);

    /* no EOI mode */
    gicc_clear(CTLR, gicc_v3_iface ? ICC_CTLR_EL1_EOImode : GICC_CTLR_EOImode);

    /* clear active */
    while (gic_dispatch_int() != INTID_NO_PENDING);

    /* enable */
    if (gicc_v3_iface)
        write_psr_s(ICC_IGRPEN1_EL1, ICC_IGRPENx_ENABLE);
    else {
        /* XXX see comment above */
        mmio_write_32(GICC_CTLR, mmio_read_32(GICC_CTLR) |
                     (GICC_CTLR_EnableGrp1 | GICC_CTLR_AckCtl));
    }
}

u16 gic_msi_vector_base;
u16 gic_msi_vector_num;

void init_gic(void)
{
    u32 iidr = mmio_read_32(GICC_IIDR);
    int version = field_from_u64(iidr, GICC_IIDR_Architecture_version);
    gic_debug("%s: iidr 0x%x (version %d)\n", __func__, iidr, version);
    gicc_v3_iface = version >= 3;
    if (gicc_v3_iface) {
        u64 icc_ctlr = read_psr_s(ICC_CTLR_EL1);
        gic_intid_mask = (field_from_u64(icc_ctlr, ICC_CTLR_EL1_IDbits) ==
                          ICC_CTLR_EL1_IDbits_24) ? MASK(24) : MASK(16);
    } else {
        gic_intid_mask = MASK(10);

        /* virt is currently the only aarch64 platform, so we trust that gicv2
           implies v2m - but really this should consult the dev tree or acpi
           before probing. */
        u64 typer = mmio_read_32(GIC_V2M_MSI_TYPER);
        gic_msi_vector_base = field_from_u64(typer, GIC_V2M_MSI_TYPER_BASE);
        gic_msi_vector_num = field_from_u64(typer, GIC_V2M_MSI_TYPER_NUM);
    }

    init_gicd();
    init_gicc();
}
