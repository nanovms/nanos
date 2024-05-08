#include <kernel.h>
#include <pci.h>

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

u32 pci_cfgread(pci_dev dev, int reg, int bytes)
{
    u32 data = -1;
    u64 base = mmio_base_addr(PCIE_ECAM)
        + (dev->bus << 20) + (dev->slot << 15) + (dev->function << 12) + reg;
    pci_plat_debug("%s:  dev %p, bus %d, reg 0x%02x, bytes %d, base 0x%lx: ", func_ss,
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
                   func_ss, dev, dev->bus, reg, bytes, base, source);
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
        pci_plat_debug("%s: bar %p, %s addr + offset 0x%lx: ", func_ss, b,            \
                       b->type == PCI_BAR_MEMORY ? ss("memory") : ss("ioport"),       \
                       b->addr + offset);                               \
        u##BITS rv = b->type == PCI_BAR_MEMORY ? mmio_read_##BITS(b->addr + offset) : \
            pio_in##BITS(b->addr + offset);                             \
        pci_plat_debug("0x%x\n", rv);                                   \
        return rv;                                                      \
    }

#define MK_PCI_BAR_WRITE(BYTES, BITS)                                   \
    void pci_bar_write_##BYTES(struct pci_bar *b, u64 offset, u##BITS val) \
    {                                                                   \
        pci_plat_debug("%s: bar %p, %s addr + offset 0x%lx= 0x%x\n", func_ss, b,    \
                       b->type == PCI_BAR_MEMORY ? ss("memory") : ss("ioport"),     \
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

void pci_setup_irq_aff(pci_dev dev, thunk h, sstring name, range cpu_affinity)
{
    /* To mimic the interrupt assignment swizzle we need to know the 
       device/slot and interrupt pin assignment: 
         0x20 + (slot + pin) % 4 */
    u64 irq = 0x20 + (dev->slot + (pci_cfgread(dev, PCIR_INT_PIN, 1)-1)) % 4;
    pci_plat_debug("%s: bus %d slot %d func %d pin %d irq 0x%x\n", func_ss,
                   dev->bus, dev->slot, dev->function, pci_cfgread(dev, PCIR_INT_PIN, 1), irq);
    irq_register_handler(irq, h, name, cpu_affinity);
}

/* Rudimentary resource allocation based on fixed offests for virt
   This could be replaced with generic PCI resource allocation. */
void pci_platform_init_bar(pci_dev dev, int bar_idx)
{
    pci_plat_debug("%s: dev %p, %d:%d:%d, bar_idx %d\n", func_ss,
                   dev, dev->bus, dev->slot, dev->function, bar_idx);
    u32 bar = pci_cfgread(dev, PCIR_BAR(bar_idx), 4);
    pci_plat_debug("   bar before 0x%x\n", bar);
    boolean is_io = (bar & 1) != 0;
    u32 base = bar & (is_io ? ~3 : ~15);
    if (base == 0) {
        if (is_io) {
            base = ((dev->bus + 1) << 12) | (dev->slot << 8) |
                (dev->function << 6) | (bar << 3) | 1;
        } else {
            base = DEV_BASE_PCIE_MMIO + ((dev->bus + 1) << 18) + (dev->slot << 12) +
                (dev->function << 8) + (bar << 4);
        }
        pci_plat_debug("%s: dev %d:%d:%d, base 0x%x\n", func_ss, dev->bus, dev->slot, dev->function, base);
        pci_cfgwrite(dev, PCIR_BAR(bar_idx), 4, base);
    }
}

u64 pci_platform_allocate_msi(pci_dev dev, thunk h, sstring name, u32 target_cpu,
                              u32 *address, u32 *data)
{
    u64 v = allocate_msi_interrupt();
    if (v == INVALID_PHYSICAL)
        return v;
    register_interrupt(v, h, name);
    msi_format(address, data, v, target_cpu);
    return v;
}

void pci_platform_deallocate_msi(pci_dev dev, u64 v)
{
    unregister_interrupt(v);
    deallocate_msi_interrupt(v);
}

boolean pci_platform_has_msi(void)
{
    return false;
}

