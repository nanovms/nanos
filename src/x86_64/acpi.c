#include <kernel.h>
#include <apic.h>
#include <drivers/acpi.h>
#include <pci.h>
#include <region.h>
#include <page.h>

#define INTEL_PCI_VENDORID  0x8086

#define PIIX4ACPI_PCI_DEVICEID 0x7113

#define PIIX4ACPI_PM_BAR    12  /* Non-standard BAR address 0x40 */

#define PIIX4ACPI_PMREGMISC_R   0x80

/* PMREGMISC register */
#define PIIX4ACPI_PMIOSE    (1 << 0)

#define PIIX4ACPI_SLP_TYP_SOFF      0
#define PIIX4ACPI_SLP_TYP_STR       1
#define PIIX4ACPI_SLP_TYP_POSCL     2
#define PIIX4ACPI_SUS_TYP_POSCCL    3
#define PIIX4ACPI_SUS_TYP_POS       4
#define PIIX4ACPI_SUS_TYP_WORK      5

//#define ACPI_DEBUG
#ifdef ACPI_DEBUG
#define acpi_debug(x, ...) rprintf("ACPI: " x "\n", ##__VA_ARGS__)
#else
#define acpi_debug(x, ...)
#endif

static acpi_rsdt rsdt;
static table acpi_tables;

declare_closure_struct(1, 0, void, piix4acpi_irq,
                       struct piix4acpi *, dev);
declare_closure_struct(1, 1, void, piix4acpi_powerdown,
                       struct piix4acpi *, dev,
                       int, status);

typedef struct piix4acpi {
    pci_dev d;
    struct pci_bar pm_bar;
    closure_struct(piix4acpi_irq, irq_handler);
    closure_struct(piix4acpi_powerdown, powerdown_handler);
} *piix4acpi;

define_closure_function(1, 1, void, piix4acpi_powerdown,
                        piix4acpi, dev,
                        int, status)
{
    acpi_debug("%s", __func__);
    piix4acpi dev = bound(dev);
    pci_bar_write_2(&dev->pm_bar, ACPI_PM1_CNT,
                    ACPI_PM1_SLP_EN | ACPI_PM1_SLP_TYP(PIIX4ACPI_SLP_TYP_SOFF));
}

define_closure_function(1, 0, void, piix4acpi_irq,
                        piix4acpi, dev)
{
    piix4acpi dev = bound(dev);
    u16 sts = pci_bar_read_2(&dev->pm_bar, ACPI_PM1_STS);
    acpi_debug("%s: sts 0x%04x", __func__, sts);
    pci_bar_write_2(&dev->pm_bar, ACPI_PM1_STS, sts);   /* clear status bits */
    if (sts & ACPI_PM1_PWRBTN_STS)
        kernel_shutdown(0);
}

closure_function(1, 1, boolean, piix4acpi_probe,
                 heap, h,
                 pci_dev, d)
{
    if ((pci_get_vendor(d) != INTEL_PCI_VENDORID) || (pci_get_device(d) != PIIX4ACPI_PCI_DEVICEID))
        return false;
    piix4acpi dev = allocate(bound(h), sizeof(struct piix4acpi));
    if (dev == INVALID_ADDRESS)
        return false;
    dev->d = d;
    u64 irq = allocate_interrupt();
    assert(irq != INVALID_PHYSICAL);
    acpi_debug("%s: irq %d", __func__, irq);
    register_interrupt(irq, init_closure(&dev->irq_handler, piix4acpi_irq, dev), "PIIX4 ACPI");
    ioapic_set_int(ACPI_SCI_IRQ, irq);
    pci_bar_init(dev->d, &dev->pm_bar, PIIX4ACPI_PM_BAR, 0, 0);
    pci_cfgwrite(dev->d, PIIX4ACPI_PMREGMISC_R, 1, PIIX4ACPI_PMIOSE);
    pci_bar_write_2(&dev->pm_bar, ACPI_PM1_EN, ACPI_PM1_PWRBTN_EN);
    pci_bar_write_2(&dev->pm_bar, ACPI_PM1_CNT, ACPI_PM1_SCI_EN);
    vm_halt = init_closure(&dev->powerdown_handler, piix4acpi_powerdown, dev);
    return true;
}

static void *map_acpi_table(kernel_heaps kh, u64 paddr, u64 plen)
{
    u64 off, base, len, v;
    heap vh = (heap)heap_virtual_page(kh);

    off = paddr & PAGEMASK;
    base = paddr & ~PAGEMASK;
again:
    len = pad(paddr + plen - base, PAGESIZE);
    v = allocate_u64(vh, len);
    map(v, base, len, 0);
    u32 *t = pointer_from_u64(v + off);
    u32 tlen = *(t + 1);

    /* The table actual length may be longer than requested length,
     * so repeat the mapping process if necessary */
    if (v + len - off < tlen) {
        unmap(v, len);
        deallocate_u64(vh, v, len);
        plen = tlen;
        goto again;
    }
    return pointer_from_u64(v + off);
}

void init_acpi(kernel_heaps kh)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, piix4acpi_probe, h));
    acpi_tables = allocate_table(h, identity_key, pointer_equal);
    for_regions(e) {
        if (e->type != REGION_ACPI_RSDT)
            continue;
        rsdt = map_acpi_table(kh, e->base, e->length);
        break;
    }
    u32 *t, *te;
    t = (u32 *)(rsdt + 1);
    te = pointer_from_u64(u64_from_pointer(rsdt) + rsdt->h.length);
    for (; t < te; t++) {
        u32 *tp = map_acpi_table(kh, *t, PAGESIZE);
        table_set(acpi_tables, pointer_from_u64((u64)*tp), tp);
    }
}

void *acpi_get_table(u32 sig)
{
    return table_find(acpi_tables, pointer_from_u64((u64)sig));
}
