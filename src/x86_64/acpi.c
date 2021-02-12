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
    map(v, base, len, pageflags_memory());
    u32 *t = pointer_from_u64(v + off);
    u32 tlen = t[1]; /* length of table stored in the second u32 */

    /* The table actual length may be longer than requested length,
     * so repeat the mapping process if necessary */
    if (len - off < tlen) {
        unmap(v, len);
        deallocate_u64(vh, v, len);
        plen = tlen;
        goto again;
    }
    return pointer_from_u64(v + off);
}

static u64 find_rsdt_addr(u64 va, u64 len)
{
    assert((va & MASK(4)) == 0);
    for (u64 i = va; i < va + len; i += 16) {
        acpi_rsdp rsdp = pointer_from_u64(i);
        if (runtime_memcmp(&rsdp->sig, "RSD PTR ", sizeof(rsdp->sig)) != 0)
            continue;
        if (!acpi_checksum(rsdp, 20)) {
            acpi_debug("%s: RSDP failed checksum", __func__);
            continue;
        }
        return rsdp->rsdt_addr;
    }
    return INVALID_PHYSICAL;
}

/* ACPI spec says the RSDP is found in the first KB of EBDA or
 * in the BIOS ROM space between 0xe0000 and 0xfffff */
#define BIOS_SEARCH_LENGTH (128*KB)
#define BIOS_SEARCH_ADDR 0xe0000
#define EDBA_SEARCH_LENGTH (1*KB)
static boolean find_rsdt(kernel_heaps kh)
{
    u64 va, edba_pa, rsdt_pa;
    heap vh = (heap)heap_virtual_page(kh);

    va = allocate_u64(vh, BIOS_SEARCH_LENGTH);
    assert(va != INVALID_PHYSICAL);

    /* Search BIOS ROM */
    map(va, BIOS_SEARCH_ADDR, BIOS_SEARCH_LENGTH, pageflags_memory());
    rsdt_pa = find_rsdt_addr(va, BIOS_SEARCH_LENGTH);
    unmap(va, BIOS_SEARCH_LENGTH);
    if (rsdt_pa != INVALID_PHYSICAL)
        goto found;

    /* Search EDBA as a backup. The EDBA segment location is found at
     * 40:0Eh per ACPI spec */
    map(va, 0, PAGESIZE, pageflags_memory());
    edba_pa = (*(u16 *)(va + 0x40e))<<4;
    unmap(va, PAGESIZE);
    u64 edba_pa_map = edba_pa & ~PAGEMASK;
    u64 edba_map_len = pad((edba_pa - edba_pa_map) + EDBA_SEARCH_LENGTH, PAGESIZE);
    map(va, edba_pa_map, edba_map_len, pageflags_memory());
    rsdt_pa = find_rsdt_addr(va + (edba_pa - edba_pa_map), EDBA_SEARCH_LENGTH);
    unmap(va, edba_map_len);
    if (rsdt_pa == INVALID_PHYSICAL)
        goto out;
found:
    rsdt = map_acpi_table(kh, rsdt_pa, PAGESIZE);
    if (runtime_memcmp(rsdt->h.sig, "RSDT", 4) != 0) {
        acpi_debug("%s: RSDT has invalid signature\n", __func__);
        rsdt = 0;
        goto out;
    }
    if (!acpi_checksum(rsdt, rsdt->h.length)) {
        acpi_debug("%s: RSDT failed checksum", __func__);
        rsdt = 0;
        goto out;
    }
out:
    deallocate_u64(vh, va, BIOS_SEARCH_LENGTH);
    if (rsdt) {
        acpi_debug("%s: mapped RSDT at %p", __func__, rsdt);
        return true;
    } else {
        acpi_debug("%s: could not find valid RSDT", __func__);
        return false;
    }
}

void acpi_walk_madt(acpi_madt madt, madt_handler mh)
{
    u8 *p = (u8 *)(madt + 1);
    u8 *pe = (u8 *)madt + madt->h.length;
    for (; p < pe; p += p[1])
        apply(mh, p[0], p);
}

void *acpi_get_table(u32 sig)
{
    return table_find(acpi_tables, pointer_from_u64((u64)sig));
}

void init_acpi(kernel_heaps kh)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, piix4acpi_probe, h));
    acpi_tables = allocate_table(h, identity_key, pointer_equal);
    if (find_rsdt(kh)) {
        u32 *t, *te;
        t = (u32 *)(rsdt + 1);
        te = pointer_from_u64(u64_from_pointer(rsdt) + rsdt->h.length);
        for (; t < te; t++) {
            u32 *tp = map_acpi_table(kh, *t, PAGESIZE);
            table_set(acpi_tables, pointer_from_u64((u64)*tp), tp);
            acpi_debug("%s: mapped acpi table %.4s at %p", __func__, tp, tp);
        }
    }
}
