#include <kernel.h>
#include <drivers/acpi.h>
#include <gic.h>

#define GIC_LPI_ENABLE  0x01

//#define GIC_DEBUG
#ifdef GIC_DEBUG
#define gic_debug(x, ...) do {rprintf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define gic_debug(x, ...)
#endif

#define GIC_ICID    0   /* a single interrupt collection is being used */

/* The physical address of the command queue must be aligned to 64 KB. */
#define GIC_CMD_QUEUE_SIZE  (64 * KB)

static struct {
    boolean v3_iface;
    u32 intid_mask;
    u64 dist_base;
    struct {
        u64 base;
        u64 rdbase;
    } redist;   /* redistributor associated to CPU 0 */
    u64 its_base;
    u8 *lpi_cfg_table;
    u64 its_typer;
    u32 dev_id_limit;
    void *its_cmd_queue;
    struct list devices;
} gic;

typedef struct its_dev {
    struct list l;
    u32 id;
    void *itt;
} *its_dev;

#define gicd_read_32(reg)           mmio_read_32(gic.dist_base + GICD_ ## reg)
#define gicd_write_32(reg, value)   mmio_write_32(gic.dist_base + GICD_ ## reg, value)

#define gicr_read_32(reg)           mmio_read_32(gic.redist.base + GICR_ ## reg)
#define gicr_read_64(reg)           mmio_read_64(gic.redist.base + GICR_ ## reg)
#define gicr_write_32(reg, value)   mmio_write_32(gic.redist.base + GICR_ ## reg, value)
#define gicr_write_64(reg, value)   mmio_write_64(gic.redist.base + GICR_ ## reg, value)

#define gits_read_64(reg)           mmio_read_64(gic.its_base + GITS_ ## reg)
#define gits_write_32(reg, value)   mmio_write_32(gic.its_base + GITS_ ## reg, value)
#define gits_write_64(reg, value)   mmio_write_64(gic.its_base + GITS_ ## reg, value)

static void gic_its_cmd(u64 dw0, u64 dw1, u64 dw2, u64 dw3)
{
    u64 cwrite = gits_read_64(CWRITER);
    u64 cread = gits_read_64(CREADR);
    gic_debug("cread 0x%lx, cwrite 0x%lx\n", cread, cwrite);
    while (cread == cwrite + 32) {  /* command queue full */
        kern_pause();
        cread = gits_read_64(CREADR);
        assert(!(cread & GITS_CREADR_STALLED));
    }
    u64 *cmd = gic.its_cmd_queue + cwrite;
    cmd[0] = dw0;
    cmd[1] = dw1;
    cmd[2] = dw2;
    cmd[3] = dw3;
    cwrite += 32;
    if (cwrite == GIC_CMD_QUEUE_SIZE)
        cwrite = 0;
    gits_write_64(CWRITER, cwrite);
}

void gic_disable_int(int irq)
{
    if (irq < GIC_LPI_INTS_START) {
        int w = irq / GICD_INTS_PER_IENABLE_REG;
        boolean redist = gic.v3_iface && (w == 0);
        u32 x = U32_FROM_BIT(irq & (GICD_INTS_PER_IENABLE_REG - 1)); /* same as redist */
        if (!redist) {
            gic_debug("irq %d, x 0x%x, before 0x%x\n", irq, x, gicd_read_32(ICENABLER(w)));
            gicd_write_32(ICENABLER(w), x);
        } else {
            gic_debug("irq %d, x 0x%x, before 0x%x\n", irq, x, gicr_read_32(ICENABLER));
            gicr_write_32(ICENABLER, x);
        }
    } else {
        gic.lpi_cfg_table[irq - GIC_LPI_INTS_START] &= ~GIC_LPI_ENABLE;
    }
}

void gic_enable_int(int irq)
{
    if (irq < GIC_LPI_INTS_START) {
        int w = irq / GICD_INTS_PER_IENABLE_REG;
        boolean redist = gic.v3_iface && (w == 0);
        u32 x = U32_FROM_BIT(irq & (GICD_INTS_PER_IENABLE_REG - 1));
        if (!redist) {
            gic_debug("irq %d, x 0x%x, before 0x%x\n", irq, x, gicd_read_32(ISENABLER(w)));
            gicd_write_32(ISENABLER(w), x);
        } else {
            gic_debug("irq %d, x 0x%x, before 0x%x\n", irq, x, gicr_read_32(ISENABLER));
            gicr_write_32(ISENABLER, x);
        }
    } else {
        gic.lpi_cfg_table[irq - GIC_LPI_INTS_START] |= GIC_LPI_ENABLE;
    }
}

void gic_clear_pending_int(int irq)
{
    if (irq < GIC_LPI_INTS_START) {
        int w = irq / GICD_INTS_PER_IPEND_REG;
        boolean redist = gic.v3_iface && (w == 0);
        u32 x = U32_FROM_BIT(irq & (GICD_INTS_PER_IPEND_REG - 1));
        if (!redist) {
            gic_debug("irq %d, x 0x%x, before 0x%x\n", irq, x, gicd_read_32(ICPENDR(w)));
            gicd_write_32(ICPENDR(w), x);
        } else {
            gic_debug("irq %d, x 0x%x, before 0x%x\n", irq, x, gicr_read_32(ICPENDR));
            gicr_write_32(ICPENDR, x);
        }
    }
}

#define GIC_SET_INTFIELD(name, type)                                    \
    void gic_set_int_##name(int irq, u32 v)                             \
    {                                                                   \
        if (irq >= GIC_LPI_INTS_START)                                  \
            return;                                                     \
        int w = 32 / GICD_INTS_PER_ ## type ## _REG;                    \
        int r = irq / GICD_INTS_PER_ ## type ## _REG;                   \
        boolean redist = gic.v3_iface && (irq < GIC_PPI_INTS_END);      \
        u32 i;                                                          \
        if (!redist)                                                    \
            i = gicd_read_32(type ## R(r));                             \
        else                                                            \
            i = gicr_read_32(type ## R(r));                             \
        int s = (irq % GICD_INTS_PER_ ## type ## _REG) * w;             \
        u32 n = (i & ~(MASK32(w) << s)) | (v << s);                     \
        if (!redist)                                                    \
            gicd_write_32(type ## R(r), n);                             \
        else                                                            \
            gicr_write_32(type ## R(r), n);                             \
        gic_debug("irq %d, v %d, reg was 0x%x, now 0x%x\n", irq, v, i, n); \
    }

GIC_SET_INTFIELD(priority, IPRIORITY)
GIC_SET_INTFIELD(config, ICFG)

boolean gic_int_is_pending(int irq)
{
    int w = irq / GICD_INTS_PER_IPEND_REG;
    u64 v = (!gic.v3_iface || w) ? gicd_read_32(ISPENDR(w)) : gicr_read_32(ISPENDR);
    boolean pending = (v & U32_FROM_BIT(irq & (GICD_INTS_PER_IPEND_REG - 1))) != 0;
    gic_debug("irq %d, pending %d\n", irq, pending);
    return pending;
}

static void init_gicd(void)
{
    gicd_write_32(CTLR, GICD_CTLR_DISABLE);

    /* disable and clear pending */
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IENABLE_REG; i++)
        gicd_write_32(ICENABLER(i), MASK(32));
    
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IPEND_REG; i++)
        gicd_write_32(ICPENDR(i), MASK(32));

    /* set all to low priority */
    for (int i = 0; i < GIC_MAX_INT / GICD_INTS_PER_IPRIORITY_REG; i++)
        gicd_write_32(IPRIORITYR(i), MASK(32));

    /* set all to group 1, non-secure */
    if (gic.v3_iface)
        gicr_write_32(IGROUPR, MASK(32));
    else
        gicd_write_32(IGROUPR(0), MASK(32));
    for (int i = GIC_SPI_INTS_START / GICD_INTS_PER_IGROUP_REG;
         i < GIC_SPI_INTS_END / GICD_INTS_PER_IGROUP_REG; i++)
        gicd_write_32(IGROUPR(i), MASK(32));

    /* shared periph target cpu0 */
    for (int i = GIC_SPI_INTS_START / GICD_INTS_PER_ITARGETS_REG;
         i < GIC_SPI_INTS_END / GICD_INTS_PER_ITARGETS_REG; i++)
        gicd_write_32(ITARGETSR(i), 0x01010101);

    /* set all to level triggered, active low */
    for (int i = GIC_PPI_INTS_START / GICD_INTS_PER_ICFG_REG;
         i < GIC_PPI_INTS_END / GICD_INTS_PER_ICFG_REG; i++)
        gicd_write_32(ICFGR(i), 0); /* all level */
    
    /* enable
       XXX - turn on affinity routing (ARE)? */

    /* Kludge: We seem to have one gicv2 variant (qemu w/ noaccel) that honors
       bit 1 as GRP1 enable, and another (qemu w/ kvm on bcm2711) which
       doesn't, so set both for now until the variants can be sorted
       out. (This may be due to the presence of GIC Security Extensions. */
    gicd_write_32(CTLR, GICD_CTLR_ENABLEGRP1 | GICD_CTLR_ENABLEGRP0);
}

/* aliases for macro use */
#define GICC_BPR0 GICC_BPR
#define GICC_IAR1 GICC_IAR
#define GICC_EOIR1 GICC_EOIR

#define gicc_read(reg) (gic.v3_iface ? read_psr_s(ICC_ ## reg ## _EL1) : (GICC_ ## reg))
#define gicc_write(reg, v) do { if (gic.v3_iface) write_psr_s(ICC_ ## reg ## _EL1, (v)); \
        else mmio_write_32(GICC_ ## reg, v); } while (0)
#define gicc_set(reg, v) do { gicc_write(reg, gicc_read(reg) | (v)); } while(0)
#define gicc_clear(reg, v) do { gicc_write(reg, gicc_read(reg) & ~(v)); } while(0)

u64 gic_dispatch_int(void)
{
    u64 v = (gic.v3_iface ? read_psr_s(ICC_IAR1_EL1) : mmio_read_32(GICC_IAR)) & gic.intid_mask;
    gic_debug("intid %ld\n", v);
    return v;
}

void gic_eoi(int irq)
{
    gic_debug("irq %d\n", irq);
    gicc_write(EOIR1, irq);
}

boolean dev_irq_enable(u32 dev_id, int vector)
{
    gic_debug("dev 0x%x, irq %d\n", dev_id, vector);
    if ((vector >= gic_msi_vector_base) && gic.its_base) {
        its_dev dev = 0;
        list_foreach(&gic.devices, l) {
            its_dev d = struct_from_list(l, its_dev, l);
            if (d->id == dev_id) {
                dev = d;
                break;
            }
        }
        if (!dev) {
            assert(dev_id < gic.dev_id_limit);
            kernel_heaps kh = get_kernel_heaps();
            dev = allocate(heap_locked(kh), sizeof(*dev));
            if (dev == INVALID_ADDRESS)
                return false;

            /* The number of interrupt table entries must be a power of 2. */
            u64 ite_num = U64_FROM_BIT(find_order(gic_msi_vector_num));
            u64 itt_size = ite_num * (GITS_ITT_entry_size(gic.its_typer) + 1);
            itt_size = MAX(itt_size, U64_FROM_BIT(8));  /* ensure 256-byte alignment */
            gic_debug("creating ITT with %ld entries (%ld bytes)\n", ite_num, itt_size);
            u64 pa;
            dev->itt = alloc_map(heap_page_backed(kh), itt_size, &pa);
            if (dev->itt == INVALID_ADDRESS) {
                deallocate(heap_locked(kh), dev, sizeof(*dev));
                return false;
            }

            zero(dev->itt, itt_size);
            dev->id = dev_id;
            list_insert_before(list_begin(&gic.devices), &dev->l);
            gic_its_cmd(((u64)dev_id << 32) | ITS_CMD_MAPD, find_order(ite_num) - 1,
                        ITS_MAPD_V | pa, 0);
        }
        u32 event_id = vector - gic_msi_vector_base;
        gic_its_cmd(((u64)dev_id << 32) | ITS_CMD_MAPTI, ((u64)vector << 32) | event_id,
                    GIC_ICID, 0);
        gic_its_cmd(((u64)dev_id << 32) | ITS_CMD_INV, event_id, 0, 0);
        gic_its_cmd(ITS_CMD_SYNC, 0, gic.redist.rdbase << 16, 0);
    }
    return true;
}

void dev_irq_disable(u32 dev_id, int vector)
{
    gic_debug("dev 0x%x, irq %d\n", dev_id, vector);
    if ((vector >= gic_msi_vector_base) && gic.its_base) {
        u32 event_id = vector - gic_msi_vector_base;
        gic_its_cmd(((u64)dev_id << 32) | ITS_CMD_DISCARD, event_id, 0, 0);
        gic_its_cmd(((u64)dev_id << 32) | ITS_CMD_INV, event_id, 0, 0);
        gic_its_cmd(ITS_CMD_SYNC, 0, gic.redist.rdbase << 16, 0);
    }
}

void msi_format(u32 *address, u32 *data, int vector)
{
    if (gic.its_base) {
        *address = gic.its_base + GITS_TRANSLATER - DEVICE_BASE;
        *data = vector - gic_msi_vector_base;
    } else {
        *address = DEV_BASE_GIC_V2M + GIC_V2M_MSI_SETSPI_NS;
        *data = vector;
    }
}

static void init_gicc(void)
{
    /* disable all interrupt groups */
    if (gic.v3_iface) {
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
    gicc_clear(CTLR, gic.v3_iface ? ICC_CTLR_EL1_EOImode : GICC_CTLR_EOImode);

    /* clear active */
    while (gic_dispatch_int() != INTID_NO_PENDING);

    /* enable */
    if (gic.v3_iface)
        write_psr_s(ICC_IGRPEN1_EL1, ICC_IGRPENx_ENABLE);
    else {
        /* XXX see comment above */
        mmio_write_32(GICC_CTLR, mmio_read_32(GICC_CTLR) |
                     (GICC_CTLR_EnableGrp1 | GICC_CTLR_AckCtl));
    }
}

static void init_gits(kernel_heaps kh)
{
    gic.its_typer = gits_read_64(TYPER);
    gic_debug("typer 0x%lx\n", gic.its_typer);
    if (gic.its_typer & GITS_TYPER_PTA)
        gic.redist.rdbase = gic.redist.base >> 16;
    else
        gic.redist.rdbase = GICR_TYPER_PROC_NUM(gicr_read_64(TYPER));
    u64 pa;
    for (int n = 0; n < 8; n++) {
        u64 base = gits_read_64(BASER(n));
        u64 page_size;
        void *table;
        switch (GITS_TABLE_TYPE(base)) {
        case GITS_TABLE_DEVICES:
        case GITS_TABLE_COLLECTIONS:
            switch (GITS_PAGE_SIZE(base)) {
            case GITS_PGSZ_4K:
                page_size = 4 * KB;
                break;
            case GITS_PGSZ_16K:
                page_size = 16 * KB;
                break;
            default:
                page_size = 64 * KB;
                break;
            }

            /* Allocate a single (flat) table. This will need to be revised for the device table if
             * we hit the device ID limit. */
            gic_debug("allocating table type %d (entry size %d, page size %d)\n",
                      GITS_TABLE_TYPE(base), GITS_TABLE_ENTRY_SIZE(base) + 1, page_size);
            if (GITS_TABLE_TYPE(base) == GITS_TABLE_DEVICES)
                gic.dev_id_limit = page_size / (GITS_TABLE_ENTRY_SIZE(base) + 1);
            table = alloc_map(heap_page_backed(kh), page_size, &pa);
            assert(table != INVALID_ADDRESS);
            zero(table, page_size);
            base = (base & ~GITS_BASE_PA_MASK) | pa;
            gits_write_64(BASER(n), GITS_BASER_VALID | base);
            break;
        }
    }
    list_init(&gic.devices);

    /* Set up the command queue. */
    gic.its_cmd_queue = alloc_map(heap_page_backed(kh), GIC_CMD_QUEUE_SIZE, &pa);
    assert(gic.its_cmd_queue != INVALID_ADDRESS);
    gits_write_64(CBASER, GITS_CBASER_VALID | pa | (GIC_CMD_QUEUE_SIZE / PAGESIZE));
    gits_write_64(CWRITER, 0);

    gits_write_32(CTLR, GITS_CTRL_ENABLED); /* Enable the ITS. */

    /* Map an interrupt collection to the redistributor associated to CPU 0. */
    gic_its_cmd(ITS_CMD_MAPC, 0, ITS_MAPC_V | (gic.redist.rdbase << 16) | GIC_ICID, 0);
}

BSS_RO_AFTER_INIT u16 gic_msi_vector_base;
BSS_RO_AFTER_INIT u16 gic_msi_vector_num;

closure_function(0, 2, void, gic_madt_handler,
                 u8, type, void *, p)
{
    switch (type) {
    case ACPI_MADT_GEN_DIST:
        gic.dist_base = DEVICE_BASE + ((acpi_gen_dist)p)->base_address;
        break;
    case ACPI_MADT_GEN_RDIST:
        gic.redist.base = DEVICE_BASE + ((acpi_gen_redist)p)->base_address;
        break;
    case ACPI_MADT_GEN_TRANS:
        gic.its_base = DEVICE_BASE + ((acpi_gen_trans)p)->base_address;
        break;
    }
}

int init_gic(void)
{
    acpi_walk_madt(stack_closure(gic_madt_handler));
    if (!gic.dist_base)
        gic.dist_base = mmio_base_addr(GIC_DIST);
    if (!gic.redist.base)
        gic.redist.base = mmio_base_addr(GIC_REDIST);
    gic_debug("dist %p, redist %p, its %p\n", gic.dist_base, gic.redist.base, gic.its_base);
    u64 aa64pfr0 = read_psr(ID_AA64PFR0_EL1);
    u8 gic_iface = field_from_u64(aa64pfr0, ID_AA64PFR0_EL1_GIC);
    switch (gic_iface) {
    case ID_AA64PFR0_EL1_GIC_GICC_SYSREG_NONE:
        break;
    case ID_AA64PFR0_EL1_GIC_GICC_SYSREG_3_0_4_0:
        gic.v3_iface = true;
        break;
    default:
        halt("%s: gic type %d from ID_AA64PFR0_EL1 not supported\n", __func__, gic_iface);
    }

    if (gic.v3_iface) {
        u64 icc_ctlr = read_psr_s(ICC_CTLR_EL1);
        gic.intid_mask = (field_from_u64(icc_ctlr, ICC_CTLR_EL1_IDbits) ==
                          ICC_CTLR_EL1_IDbits_24) ? MASK(24) : MASK(16);
        gic_msi_vector_base = GIC_LPI_INTS_START;
        u64 typer = gicd_read_32(TYPER);
        u8 num_lpis = field_from_u64(typer, GICD_num_LPIs);
        if (num_lpis == 0)
            gic_msi_vector_num = U32_FROM_BIT(field_from_u64(typer, GICD_IDbits) + 1) -
                                 gic_msi_vector_base;
        else
            gic_msi_vector_num = U32_FROM_BIT(num_lpis + 1);

        /* Set up a page-sized LPI configuration table. */
        gic_msi_vector_num = MAX(gic_msi_vector_num, PAGESIZE); /* 1 byte per LPI */
        kernel_heaps kh = get_kernel_heaps();
        u64 pa;
        gic.lpi_cfg_table = alloc_map(heap_page_backed(kh), PAGESIZE, &pa);
        assert(gic.lpi_cfg_table != INVALID_ADDRESS);
        zero(gic.lpi_cfg_table, PAGESIZE);
        u64 id_bits = find_order(gic_msi_vector_base + gic_msi_vector_num) - 1;
        gicr_write_64(PROPBASER, pa | id_bits);

        /* Set up LPI pending table, which must be aligned to 64 KB. */
        void *lpi_pending_table = alloc_map(heap_page_backed(kh), 64 * KB, &pa);
        assert(lpi_pending_table != INVALID_ADDRESS);
        zero(lpi_pending_table, 64 * KB);
        gicr_write_64(PENDBASER, GICR_PENDBASER_PTZ | pa);

        gicr_write_32(CTLR, GICR_CTLR_EnableLPIs);
        if (gic.its_base)
            init_gits(kh);
    } else {
        gic.intid_mask = MASK(10);

        /* virt is currently the only aarch64 platform, so we trust that gicv2
           implies v2m - but really this should consult the dev tree or acpi
           before probing. */
        u64 typer = mmio_read_32(GIC_V2M_MSI_TYPER);
        gic_msi_vector_base = field_from_u64(typer, GIC_V2M_MSI_TYPER_BASE);
        gic_msi_vector_num = field_from_u64(typer, GIC_V2M_MSI_TYPER_NUM);
    }

    init_gicd();
    init_gicc();
    return (gic.v3_iface ? gic_msi_vector_base + gic_msi_vector_num : GIC_MAX_INT);
}

void send_ipi(u64 cpu, u8 vector)
{
}
