#include <kernel.h>
#include <pci.h>
#include <gic.h>
#include <drivers/console.h>

//#define PCI_PLATFORM_DEBUG
#ifdef PCI_PLATFORM_DEBUG
#define pci_plat_debug rprintf
#else
#define pci_plat_debug(...) do { } while(0)
#endif

#define PIO_DATA (mmio_base_addr(PCIE_PIO))
#define pio_in8(port) mmio_read_8(PIO_DATA + port)
#define pio_in16(port) mmio_read_16(PIO_DATA + port)
#define pio_in32(port) mmio_read_32(PIO_DATA + port)
#define pio_out8(port, source) mmio_write_8(PIO_DATA + port, source)
#define pio_out16(port, source) mmio_write_16(PIO_DATA + port, source)
#define pio_out32(port, source) mmio_write_32(PIO_DATA + port, source)

/* stub ... really shouldn't be hardwired into console.c */
void vga_pci_register(kernel_heaps kh, console_attach a)
{
}

/* ECAM */
u32 pci_cfgread(pci_dev dev, int reg, int bytes)
{
    u32 data = -1;
    u64 base = mmio_base_addr(PCIE_ECAM)
        + (dev->bus << 20) + (dev->slot << 15) + (dev->function << 12) + reg;
    pci_plat_debug("%s:  dev %p, bus %d, reg 0x%02x, bytes %d, base 0x%lx: ", __func__,
              dev, dev->bus, reg, bytes, base);
    switch (bytes) {
    case 1:
        data = mmio_read_8(base);
        break;
    case 2:
        data = mmio_read_16(base);
        break;
    case 4:
        data = mmio_read_32(base);
        break;
    }
    pci_plat_debug("0x%x\n", data);
    return data;
}

void pci_cfgwrite(pci_dev dev, int reg, int bytes, u32 source)
{
    u64 base = mmio_base_addr(PCIE_ECAM)
        + (dev->bus << 20) + (dev->slot << 15) + (dev->function << 12) + reg;
    pci_plat_debug("%s: dev %p, bus %d, reg 0x%02x, bytes %d, base 0x%lx= 0x%x\n",
                   __func__, dev, dev->bus, reg, bytes, base, source);
    switch (bytes) {
    case 1:
        mmio_write_8(base, source);
        break;
    case 2:
        mmio_write_16(base, source);
        break;
    case 4:
        mmio_write_32(base, source);
        break;
    }
}

#define MK_PCI_BAR_READ(BYTES, BITS)                                    \
    u##BITS pci_bar_read_##BYTES(struct pci_bar *b, u64 offset)         \
    {                                                                   \
        pci_plat_debug("%s:  bar %p, %s addr + offset 0x%lx: ", __func__, b, \
                       b->type == PCI_BAR_MEMORY ? "memory" : "ioport", \
                       b->addr + offset);                               \
        u##BITS rv = b->type == PCI_BAR_MEMORY ? mmio_read_##BITS(b->addr + offset) : \
            pio_in##BITS(b->addr + offset);                             \
        pci_plat_debug("0x%x\n", rv);                                   \
        return rv;                                                      \
    }

#define MK_PCI_BAR_WRITE(BYTES, BITS)                                   \
    void pci_bar_write_##BYTES(struct pci_bar *b, u64 offset, u##BITS val) \
    {                                                                   \
        pci_plat_debug("%s: bar %p, %s addr + offset 0x%lx= 0x%x\n", __func__, b, \
                       b->type == PCI_BAR_MEMORY ? "memory" : "ioport", \
                       b->addr + offset, val);                          \
        if (b->type == PCI_BAR_MEMORY)                                  \
            mmio_write_##BITS(b->addr + offset, val);                   \
        else                                                            \
            pio_out##BITS(b->addr + offset, val);                       \
    }

MK_PCI_BAR_READ(1, 8)
MK_PCI_BAR_READ(2, 16)
MK_PCI_BAR_READ(4, 32)

MK_PCI_BAR_WRITE(1, 8)
MK_PCI_BAR_WRITE(2, 16)
MK_PCI_BAR_WRITE(4, 32)

void pci_setup_non_msi_irq(pci_dev dev, int idx, thunk h, const char *name)
{
    /* queue index ignored; virtio ints are shared */
    u64 v = GIC_SPI_INTS_START + VIRT_PCIE_IRQ_BASE + (dev->slot % 4);
    pci_plat_debug("%s: dev %p, idx %d, irq %d, handler %F, name %s\n",
                   __func__, dev, idx, v, h, name);
    reserve_interrupt(v); /* failure ok if shared int */
    register_interrupt(v, h, name);
}

void pci_platform_init_bar(pci_dev dev)
{
    /* XXX consts */
    u64 base = 0x1000 + ((dev->bus << 12) | (dev->slot << 8) | (dev->function << 6));
    pci_plat_debug("%s: dev %d:%d:%d, base 0x%x\n", __func__, dev->bus, dev->slot, dev->function, base);
    pci_cfgwrite(dev, PCIR_BAR(0), 4, base);
}
