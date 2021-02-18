#include <kernel.h>
#include <pci.h>
#include <gic.h> // XXX tmp

//#define PCI_DEBUG
#ifdef PCI_DEBUG
# define pci_debug rprintf
#else
# define pci_debug(...) do { } while(0)
#endif // PCI_DEBUG

// use the global nodespace
static vector devices;
static vector drivers;
static heap virtual_page;

static u32 pci_bar_len(pci_dev dev, int bar)
{
    u32 orig = pci_cfgread(dev, 0x10 + 4 * bar, 4);
    pci_cfgwrite(dev, 0x10 + 4 * bar, 4, 0xffffffff);
    u32 len = pci_cfgread(dev, 0x10 + 4 * bar, 4);
    pci_cfgwrite(dev, 0x10 + 4 * bar, 4, orig);
    return len;
}

u64 pci_bar_size(pci_dev dev, struct pci_bar *b, int bar)
{
    u32 mask = b->type == PCI_BAR_MEMORY ? ~PCI_BAR_B_MEMORY_MASK : ~PCI_BAR_B_IOPORT_MASK;
    u32 len_lo = pci_bar_len(dev, bar) & mask;
    u32 len_hi = (b->flags & PCI_BAR_F_64BIT) ? pci_bar_len(dev, bar + 1) : 0xffffffff;
    return ~(((u64) len_hi << 32) | len_lo) + 1;
}

void pci_bar_init(pci_dev dev, struct pci_bar *b, int bar, bytes offset, bytes length)
{
    u32 base = pci_cfgread(dev, PCIR_BAR(bar), 4);
    pci_debug("%s: bus %d, slot %d, function %d, bar %d, base 0x%x\n", __func__,
              dev->bus, dev->slot, dev->function, bar, base);
    b->type = base & PCI_BAR_B_TYPE_MASK;

    if (b->type == PCI_BAR_MEMORY) {
        b->flags = base & PCI_BAR_B_MEMORY_MASK;
        u32 addr_hi = (b->flags & PCI_BAR_F_64BIT) ? pci_cfgread(dev, PCIR_BAR(bar + 1), 4) : 0;
        b->addr = ((u64) addr_hi << 32) | (base & ~PCI_BAR_B_MEMORY_MASK);
        pci_debug("   mem: b->addr 0x%lx, flags 0x%lx\n", b->addr, b->flags);
    } else {
        b->flags = 0;
        b->addr = (base & ~PCI_BAR_B_IOPORT_MASK) + offset;
        pci_debug("   i/o: addr 0x%x\n", b->addr);
    }
    b->size = pci_bar_size(dev, b, bar);
    pci_debug("%s: bar %d: type %d, addr 0x%lx, size 0x%lx, flags 0x%x\n",
              __func__, bar, b->type, b->addr, b->size, b->flags);

    if (b->type == PCI_BAR_MEMORY) {
        // map memory
        if (length == -1)
            length = b->size - offset;
        assert(offset + length <= b->size);
        b->vlen = pad(length, PAGESIZE);
        b->vaddr = allocate(virtual_page, b->vlen);
        pci_debug("%s: %p[0x%x] -> 0x%lx[0x%lx]+0x%x\n", __func__, b->vaddr,
                  b->vlen, b->addr, b->size, offset);
        u64 pa = b->addr + offset;
        map(u64_from_pointer(b->vaddr), pa & ~PAGEMASK, b->vlen, pageflags_writable(pageflags_device()));
        b->vaddr += pa & PAGEMASK;
    }
}

void pci_bar_deinit(struct pci_bar *b)
{
    if (b->type == PCI_BAR_MEMORY) {
        u64 vaddr_aligned = u64_from_pointer(b->vaddr) & ~PAGEMASK;
        unmap(vaddr_aligned, b->vlen);
        deallocate(virtual_page, vaddr_aligned, b->vlen);
    }
}

void pci_set_bus_master(pci_dev dev)
{
    pci_debug("%s\n", __func__);
    u16 command = pci_cfgread(dev, PCIR_COMMAND, 2);
    command |= PCIM_CMD_BUSMASTEREN;
    pci_cfgwrite(dev, PCIR_COMMAND, 2, command);
}

void pci_enable_io_and_memory(pci_dev dev)
{
    pci_debug("%s\n", __func__);
    u16 command = pci_cfgread(dev, PCIR_COMMAND, 2);
    command |= PCIM_CMD_IOEN | PCIM_CMD_MEMORYEN;
    pci_cfgwrite(dev, PCIR_COMMAND, 2, command);
}

static u32 _pci_find_cap(pci_dev dev, u8 cap, u32 cp)
{
    for (; cp != 0; cp = pci_cfgread(dev, cp + PCICAP_NEXTPTR, 1)) {
        u8 c = pci_cfgread(dev, cp + PCICAP_ID, 1);
        if (c == cap)
            break;
    }

    return cp;
}

u32 pci_find_cap(pci_dev dev, u8 cap)
{
    return _pci_find_cap(dev, cap, pci_cfgread(dev, PCIR_CAPABILITIES_POINTER, 1));
}

u32 pci_find_next_cap(pci_dev dev, u8 cap, u32 cp)
{
    return _pci_find_cap(dev, cap, pci_cfgread(dev, cp + PCICAP_NEXTPTR, 1));
}

int pci_get_msix_count(pci_dev dev)
{
    u32 cp = pci_find_cap(dev, PCIY_MSIX);
    if (cp == 0)
        return 0;
    u16 ctrl = pci_cfgread(dev, cp + 2, 2);
    return (ctrl & 0x7ff) + 1;
}

int pci_enable_msix(pci_dev dev)
{
    pci_debug("%s: dev %p\n", __func__, dev);
    u32 cp = pci_find_cap(dev, PCIY_MSIX);
    if (cp == 0)
        return 0;
    pci_debug("MSIX cap found at 0x%x\n", cp);

    // map MSI-X table
    u32 msix_table = pci_cfgread(dev, cp + 4, 4);
    int bar = msix_table & 0x7;
    bytes offset = msix_table & ~0x7;
    pci_cfgwrite(dev, PCIR_BAR(bar), 4, 0x10040000 + (dev->slot << 12));
    pci_bar_init(dev, &dev->msix_bar, bar, offset, -1);
    pci_debug("%s: msix_config.msix_table 0x%x, msix_table %p\n", __func__,
              msix_table, dev->msix_bar.vaddr);

    // enable MSI-X
    u16 ctrl = pci_cfgread(dev, cp + 2, 2);
    ctrl |= 0x8000;
    int num_entries = (ctrl & 0x7ff) + 1;
    pci_debug("%s: ctrl 0x%x, num entries %d\n", __func__, ctrl, num_entries);
    pci_cfgwrite(dev, cp + 2, 2, ctrl);
    return num_entries;
}

void msi_format(u32 *address, u32 *data, int vector)
{
#if 0 // XXX test, need another plat init
    u64 typer = *(u32*)(dev_base_pointer(GIC_V2M) + GIC_V2M_MSI_TYPER);
    u16 base = field_from_u64(typer, GIC_V2M_MSI_TYPER_BASE);
    rprintf("%s: typer 0x%lx, base %d\n", __func__, typer, base);
#endif
//    u32 dm = 0;             // destination mode: ignored if rh == 0
//    u32 rh = 0;             // redirection hint: 0 - disabled
//    u32 destination = 0;    // destination APIC
//    *address = (0xfee << 20) | (destination << 12) | (rh << 3) | (dm << 2);
    *address = 0x08020040; // v2m + V2M_MSI_SETSPI_NS

//    u32 mode = 0;           // delivery mode: 000 fixed, 001 lowest, 010 smi, 100 nmi, 101 init, 111 extint
//    u32 level = 0;          // trigger level: 0 - deassert, 1 - assert
//    u32 trigger = 0;        // trigger mode: 0 - edge, 1 - level
//    *data = (trigger << 15) | (level << 14) | (mode << 8) | vector;
    *data = vector; // XXX
}

void pci_setup_msix(pci_dev dev, int msi_slot, thunk h, const char *name)
{
    int v = allocate_interrupt();
    register_interrupt(v, h, name);
    u32 *msix_table = pci_msix_table(dev);
    pci_debug("%s: msix_table %p, msi %d: int %d, %s\n", __func__, msix_table, msi_slot, v, name);

    // XXX store num_entries

    u32 a, d;
    msi_format(&a, &d, v);

    msix_table[msi_slot*4] = a;
    msix_table[msi_slot*4 + 1] = 0;
    msix_table[msi_slot*4 + 2] = d;
    msix_table[msi_slot*4 + 3] = 0; /* vector control */
}

void pci_teardown_msix(pci_dev dev, int msi_slot)
{
    u32 *msix_table = pci_msix_table(dev);
    int v = msix_table[msi_slot*4 + 2] & 0xFF;
    pci_debug("%s: msix_table %p, msi %d: int %d\n", __func__, msix_table, msi_slot, v);
    msix_table[msi_slot*4 + 3] = 0x1;  /* set Masked bit to 1 */
    unregister_interrupt(v);
    deallocate_interrupt(v);
}

void pci_disable_msix(pci_dev dev)
{
    u32 cp = pci_find_cap(dev, PCIY_MSIX);
    u16 ctrl = pci_cfgread(dev, cp + 2, 2);
    ctrl &= ~0x8000;
    pci_cfgwrite(dev, cp + 2, 2, ctrl);
    pci_bar_deinit(&dev->msix_bar);
}

void register_pci_driver(pci_probe probe)
{
    struct pci_driver *d = allocate(drivers->h, sizeof(struct pci_driver));
    assert(d != INVALID_ADDRESS); 
    d->probe = probe;
    vector_push(drivers, d);
}

static int pci_dev_find(pci_dev dev)
{
    for (int i = 0; i < vector_length(devices); i++) {
        pci_dev d = vector_get(devices, i);
        if ((d->bus == dev->bus) && (d->slot == dev->slot) && (d->function == dev->function))
            return i;
    }
    return -1;
}

static void pci_probe_bus(int bus);

static void pci_probe_device(pci_dev dev)
{
    u16 vendor = pci_get_vendor(dev);
    if (vendor == 0xffff)
        return;
    pci_debug("%s: %02x:%02x:%x: %04x:%04x\n",
        __func__, dev->bus, dev->slot, dev->function, vendor, pci_get_device(dev));
    pci_dev pcid;
    int dev_index = pci_dev_find(dev);
    if (dev_index < 0) {
        pci_dev new_dev = allocate(devices->h, sizeof(*new_dev));
        if (new_dev == INVALID_ADDRESS) {
            msg_err("cannot allocate memory for PCI device\n");
            return;
        }
        *new_dev = *dev;
        new_dev->driver = 0;
        vector_push(devices, new_dev);
        pcid = new_dev;
    } else {
        pcid = vector_get(devices, dev_index);
        if (pcid->driver)
            return;
    }

    // PCI-PCI bridge
    u8 class = pci_get_class(dev);
    u8 subclass = pci_get_subclass(dev);
    if (class == PCIC_BRIDGE && subclass == PCIS_BRIDGE_PCI) {
        u8 secbus = pci_cfgread(dev, PCIR_SECBUS_1, 1);
        pci_debug("%s: %02x:%02x:%x: %04x:%04x: class %02x:%02x: secondary bus %02x\n",
            __func__, dev->bus, dev->slot, dev->function, vendor, pci_get_device(dev),
            class, subclass, secbus);
        pci_probe_bus(secbus);
        return;
    }

    // probe drivers
    struct pci_driver *d;
    vector_foreach(drivers, d) {
        pci_debug(" driver %p / %F\n", d, d->probe);
        if (apply(d->probe, pcid)) {
            pci_debug("  dev %02x:%02x:%x: attached to %F\n", dev->bus, dev->slot, dev->function,
                      d->probe);
            pcid->driver = d;
            break;
        }
    }
}

static void
pci_probe_bus(int bus)
{
    pci_debug("%s: probing bus %02x\n", __func__, bus);
    for (int i = 0; i <= PCI_SLOTMAX; i++) {
        struct pci_dev _dev = { .bus = bus, .slot = i, .function = 0 };
        pci_dev dev = &_dev;
        pci_probe_device(dev);

        // check multifunction devices
        if (pci_get_hdrtype(dev) & PCIM_MFDEV) {
            for (int f = 1; f <= PCI_FUNCMAX; f++) {
                dev->function = f;
                pci_probe_device(dev);
            }
        }
    }
}

/*
 * See https://wiki.osdev.org/PCI#Enumerating_PCI_Buses
 */
void pci_discover()
{
    struct pci_dev _dev = { .bus = 0, .slot = 0, .function = 0 };
    pci_dev dev = &_dev;

    if ((pci_get_hdrtype(dev) & PCIM_MFDEV) == 0) {
        pci_debug("%s: single\n", __func__);
        // single PCI host controller
        pci_probe_bus(0);
    } else {
        // multiple PCI host controllers
        for (int f = 1; f < 8; f++) {
            dev->function = f;
            u16 vendor = pci_get_vendor(dev);
            pci_debug("%s: %02x:%02x:%x: %04x:%04x\n",
                 __func__, dev->bus, dev->slot, dev->function, vendor, pci_get_device(dev));
            if (vendor != 0xffff)
                pci_probe_bus(f);
        }
    }
}

void init_pci(kernel_heaps kh)
{
    // should use the global node space
    virtual_page = (heap)heap_virtual_page(kh);
    devices = allocate_vector(heap_general(kh), 8);
    drivers = allocate_vector(heap_general(kh), 8);
}
