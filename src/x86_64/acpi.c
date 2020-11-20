#include <kernel.h>
#include <apic.h>
#include <drivers/acpi.h>
#include <pci.h>

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

declare_closure_struct(1, 0, void, piix4acpi_irq,
                       struct piix4acpi *, dev);
declare_closure_struct(1, 1, void, piix4acpi_powerdown,
                       struct piix4acpi *, dev,
                       status, s);

typedef struct piix4acpi {
    pci_dev d;
    struct pci_bar pm_bar;
    closure_struct(piix4acpi_irq, irq_handler);
    closure_struct(piix4acpi_powerdown, powerdown_handler);
} *piix4acpi;

define_closure_function(1, 1, void, piix4acpi_powerdown,
                        piix4acpi, dev,
                        status, s)
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
        kernel_shutdown_ex(init_closure(&dev->powerdown_handler, piix4acpi_powerdown, dev));
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
    return true;
}

void init_acpi(kernel_heaps kh)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, piix4acpi_probe, h));
}
