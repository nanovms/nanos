#include <kernel.h>
#include <pci.h>

//#define PCI_DEBUG
#ifdef PCI_DEBUG
# define pci_debug rprintf
#else
# define pci_debug(...) do { } while(0)
#endif // PCI_DEBUG

typedef struct pci_bridge {
    struct rmnode window;
    id_heap iomem;
} *pci_bridge;

// use the global nodespace
BSS_RO_AFTER_INIT static rangemap pci_bridges;
BSS_RO_AFTER_INIT static vector devices;
BSS_RO_AFTER_INIT static vector drivers;
static struct spinlock pci_lock;
BSS_RO_AFTER_INIT static heap virtual_page;

static u32 pci_bar_len(pci_dev dev, int bar)
{
    u32 orig = pci_cfgread(dev, 0x10 + 4 * bar, 4);
    pci_cfgwrite(dev, 0x10 + 4 * bar, 4, 0xffffffff);
    u32 len = pci_cfgread(dev, 0x10 + 4 * bar, 4);
    pci_cfgwrite(dev, 0x10 + 4 * bar, 4, orig);
    return len;
}

u64 pci_bar_size(pci_dev dev, u8 type, u8 flags, int bar)
{
    u32 mask = type == PCI_BAR_MEMORY ? ~PCI_BAR_B_MEMORY_MASK : ~PCI_BAR_B_IOPORT_MASK;
    u32 len_lo = pci_bar_len(dev, bar) & mask;
    u32 len_hi = (flags & PCI_BAR_F_64BIT) ? pci_bar_len(dev, bar + 1) : 0xffffffff;
    return ~(((u64) len_hi << 32) | len_lo) + 1;
}

void pci_bar_init(pci_dev dev, struct pci_bar *b, int bar, bytes offset, bytes length)
{
    pci_debug("%s: bus %d, slot %d, function %d, bar %d, offset 0x%lx, length 0x%lx\n",
              func_ss, dev->bus, dev->slot, dev->function, bar, offset, length);
    pci_platform_init_bar(dev, bar);
    u32 base = pci_cfgread(dev, PCIR_BAR(bar), 4);
    pci_debug("   base 0x%x\n", base);
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
    b->size = pci_bar_size(dev, b->type, b->flags, bar);
    pci_debug("   bar %d: type %d, addr 0x%lx, size 0x%lx, flags 0x%x\n",
              bar, b->type, b->addr, b->size, b->flags);

    if (b->type == PCI_BAR_MEMORY) {
        // map memory
        if (length == -1)
            length = b->size - offset;
        assert(offset + length <= b->size);
        b->vlen = pad(length, PAGESIZE);
        b->vaddr = allocate_u64(virtual_page, b->vlen);
        assert(b->vaddr != INVALID_PHYSICAL);
        pci_debug("   0x%lx[0x%x] -> 0x%lx[0x%lx]+0x%x\n", b->vaddr,
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
    pci_debug("%s\n", func_ss);
    u16 command = pci_cfgread(dev, PCIR_COMMAND, 2);
    command |= PCIM_CMD_BUSMASTEREN;
    pci_cfgwrite(dev, PCIR_COMMAND, 2, command);
}

void pci_enable_io_and_memory(pci_dev dev)
{
    pci_debug("%s\n", func_ss);
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
    pci_debug("%s: dev %p\n", func_ss, dev);
    if (!pci_platform_has_msi())
        return 0;
    u32 cp = pci_find_cap(dev, PCIY_MSIX);
    if (cp == 0)
        return 0;
    pci_debug("MSIX cap found at 0x%x\n", cp);

    // map MSI-X table
    u32 msix_table = pci_cfgread(dev, cp + 4, 4);
    int bar = msix_table & 0x7;
    bytes offset = msix_table & ~0x7;
    pci_bar_init(dev, &dev->msix_bar, bar, offset, -1);
    pci_debug("%s: msix_config.msix_table 0x%x, msix_table %p\n", func_ss,
              msix_table, dev->msix_bar.vaddr);

    // enable MSI-X
    u16 ctrl = pci_cfgread(dev, cp + 2, 2);
    ctrl |= 0x8000;
    int num_entries = (ctrl & 0x7ff) + 1;
    pci_debug("%s: ctrl 0x%x, num entries %d\n", func_ss, ctrl, num_entries);
    pci_cfgwrite(dev, cp + 2, 2, ctrl);
    return num_entries;
}

u64 pci_msix_table_slot_addr(pci_dev dev, int msi_slot)
{
    return pci_msix_table_addr(dev) + (msi_slot * sizeof(u32) * 4);
}

u64 pci_setup_msix(pci_dev dev, int msi_slot, thunk h, sstring name)
{
    pci_debug("%s: msi %d: %s\n", func_ss, msi_slot, name);

    u32 address, data;
    u64 vector = pci_platform_allocate_msi(dev, h, name, &address, &data);
    if (vector == INVALID_PHYSICAL)
        return vector;

    u64 slot_addr = pci_msix_table_slot_addr(dev, msi_slot);
    pci_debug("   vector %d, address 0x%x, data 0x%x, table slot addr 0x%lx\n",
              vector, address, data, slot_addr);
    mmio_write_32(slot_addr + (sizeof(u32) * 0), address);
    mmio_write_32(slot_addr + (sizeof(u32) * 1), 0);
    mmio_write_32(slot_addr + (sizeof(u32) * 2), data);
    mmio_write_32(slot_addr + (sizeof(u32) * 3), 0);
    return vector;
}

void pci_teardown_msix(pci_dev dev, int msi_slot)
{
    u64 slot_addr = pci_msix_table_slot_addr(dev, msi_slot);
    int v = msi_get_vector(mmio_read_32(slot_addr + sizeof(u32) * 2));
    pci_debug("%s: table slot addr 0x%lx, msi %d: int %d\n", func_ss, slot_addr, msi_slot, v);
    mmio_write_32(slot_addr + (sizeof(u32) * 3), 1); /* set Masked bit to 1 */
    pci_platform_deallocate_msi(dev, v);
}

void pci_disable_msix(pci_dev dev)
{
    u32 cp = pci_find_cap(dev, PCIY_MSIX);
    u16 ctrl = pci_cfgread(dev, cp + 2, 2);
    ctrl &= ~0x8000;
    pci_cfgwrite(dev, cp + 2, 2, ctrl);
    pci_bar_deinit(&dev->msix_bar);
}

void register_pci_driver(pci_probe probe, pci_remove remove)
{
    struct pci_driver *d = allocate(drivers->h, sizeof(struct pci_driver));
    assert(d != INVALID_ADDRESS); 
    d->probe = probe;
    d->remove = remove;
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

static void pci_parse_iomem(pci_dev dev, boolean allocate)
{
    pci_bridge bridge = (pci_bridge)rangemap_lookup(pci_bridges, dev->bus);
    if (bridge == INVALID_ADDRESS)
        return;
    id_heap iomem = bridge->iomem;
    int max_bar;
    switch (pci_get_hdrtype(dev) & PCIM_HDRTYPE) {
    case PCIM_HDRTYPE_NORMAL:
       max_bar = PCIR_MAX_BAR_0;
       break;
    case PCIM_HDRTYPE_BRIDGE:
       max_bar = 1;
       break;
    default:    /* no BARs */
        return;
    }
    for (int bar = 0; bar <= max_bar; bar++) {
        u32 base = pci_cfgread(dev, PCIR_BAR(bar), 4);
        if (((base & PCI_BAR_B_TYPE_MASK) == PCI_BAR_MEMORY) &&
            ((base & ~PCI_BAR_B_MEMORY_MASK) != 0)) {
            u64 size = pci_bar_size(dev, PCI_BAR_MEMORY, base & PCI_BAR_B_MEMORY_MASK, bar);
            u64 addr = base & ~PCI_BAR_B_MEMORY_MASK;
            if (base & PCI_BAR_F_64BIT) {
                addr |= ((u64)pci_cfgread(dev, PCIR_BAR(bar + 1), 4)) << 32;
                bar++;
            }
            pci_debug("%sllocating mem addr 0x%lx, size 0x%lx (bar %d)\n",
                      allocate ? ss("A") : ss("Dea"),
                      addr, size, bar);
            id_heap_set_area(iomem, addr, size, false, allocate);
        }
    }
}

void pci_probe_device(pci_dev dev)
{
    u16 vendor = pci_get_vendor(dev);
    if (vendor == 0xffff)
        return;
    pci_debug("%s: %02x:%02x:%x: %04x:%04x\n",
              func_ss, dev->bus, dev->slot, dev->function, vendor, pci_get_device(dev));
    pci_dev pcid;
    spin_lock(&pci_lock);
    int dev_index = pci_dev_find(dev);
    if (dev_index < 0) {
        pci_dev new_dev = allocate(devices->h, sizeof(*new_dev));
        if (new_dev == INVALID_ADDRESS) {
            msg_err("cannot allocate memory for PCI device\n");
            spin_unlock(&pci_lock);
            return;
        }
        *new_dev = *dev;
        new_dev->driver = 0;
        pci_parse_iomem(new_dev, true);
        vector_push(devices, new_dev);
        pcid = new_dev;
    } else {
        pcid = vector_get(devices, dev_index);
    }
    spin_unlock(&pci_lock);
    if (pcid->driver)
        return;

    // PCI-PCI bridge
    u8 class = pci_get_class(dev);
    u8 subclass = pci_get_subclass(dev);
    if (class == PCIC_BRIDGE && subclass == PCIS_BRIDGE_PCI) {
        u8 secbus = pci_cfgread(dev, PCIR_SECBUS_1, 1);
        pci_debug("%s: %02x:%02x:%x: %04x:%04x: class %02x:%02x: secondary bus %02x\n",
                  func_ss, dev->bus, dev->slot, dev->function, vendor, pci_get_device(dev),
            class, subclass, secbus);
        pci_probe_bus(secbus);
        return;
    }

    // probe drivers
    spin_lock(&pci_lock);
    if (pcid->driver) {
        spin_unlock(&pci_lock);
        return;
    }
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
    spin_unlock(&pci_lock);
}

closure_function(4, 0, void, pci_device_remove_complete,
                 int, bus, int, slot, int, function, thunk, completion)
{
    pci_debug("%s\n", func_ss);
    struct pci_dev dev = {
        .bus = bound(bus),
        .slot = bound(slot),
        .function = bound(function),
    };
    spin_lock(&pci_lock);
    int dev_index = pci_dev_find(&dev);
    if (dev_index >= 0) {
        deallocate(devices->h, vector_delete(devices, dev_index), sizeof(struct pci_dev));
        pci_parse_iomem(&dev, false);
    }
    spin_unlock(&pci_lock);
    apply(bound(completion));
    closure_finish();
}

void pci_remove_device(pci_dev dev, thunk completion)
{
    pci_debug("%s: %02x:%02x:%x\n", func_ss, dev->bus, dev->slot, dev->function);
    spin_lock(&pci_lock);
    int dev_index = pci_dev_find(dev);
    pci_driver driver;
    void *driver_data;
    if (dev_index >= 0) {
        pci_dev d = vector_get(devices, dev_index);
        thunk pci_completion = closure(devices->h, pci_device_remove_complete,
                                       d->bus, d->slot, d->function, completion);
        if (pci_completion != INVALID_ADDRESS)
            completion = pci_completion;
        else
            msg_err("cannot allocate completion closure\n");
        driver = d->driver;
        driver_data = d->driver_data;
        d->driver_data = 0;
    } else {
        driver = 0;
    }
    spin_unlock(&pci_lock);
    if (driver) {
        if (driver->remove && driver_data)
            apply(driver->remove, driver_data, completion);
    } else {
        apply(completion);
    }
}

static void
pci_probe_bus(int bus)
{
    pci_debug("%s: probing bus %02x\n", func_ss, bus);
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

void pci_bridge_set_iomem(range window, id_heap iomem)
{
    pci_debug("PCI bridge window %R\n", window);
    pci_bridge bridge = allocate(pci_bridges->h, sizeof(*bridge));
    assert(bridge != INVALID_ADDRESS);
    rmnode_init(&bridge->window, window);
    bridge->iomem = iomem;
    assert(rangemap_insert(pci_bridges, &bridge->window));
}

id_heap pci_bus_get_iomem(int bus)
{
    pci_bridge bridge = (pci_bridge)rangemap_lookup(pci_bridges, bus);
    if (bridge != INVALID_ADDRESS)
        return bridge->iomem;
    return 0;
}

/*
 * See https://wiki.osdev.org/PCI#Enumerating_PCI_Buses
 */
void pci_discover()
{
    struct pci_dev _dev = { .bus = 0, .slot = 0, .function = 0 };
    pci_dev dev = &_dev;

    if ((pci_get_hdrtype(dev) & PCIM_MFDEV) == 0) {
        /* Assume that 0.0.0 is always a host-to-pci bridge */
        if (pci_get_class(dev) == PCIC_BRIDGE) {
            pci_debug("%s: single\n", func_ss);
            // single PCI host controller
            pci_probe_bus(0);
        } else
            pci_debug("%s: no host-to-pci bridge found\n", func_ss);
    } else {
        // multiple PCI host controllers
        for (int f = 1; f < 8; f++) {
            dev->function = f;
            u16 vendor = pci_get_vendor(dev);
            pci_debug("%s: %02x:%02x:%x: %04x:%04x\n",
                      func_ss, dev->bus, dev->slot, dev->function, vendor, pci_get_device(dev));
            if (vendor != 0xffff)
                pci_probe_bus(f);
        }
    }
    struct rmnode k = {
        .r = irange(dev->function + 1, PCI_BUSMAX),
    };
    rangemap_foreach_of_range(pci_bridges, n, &k) {
        if (n->r.start >= k.r.start)
            pci_probe_bus(n->r.start);
    }
}

void init_pci(kernel_heaps kh)
{
    // should use the global node space
    virtual_page = (heap)heap_virtual_page(kh);
    pci_bridges = allocate_rangemap(heap_general(kh));
    assert(pci_bridges != INVALID_ADDRESS);
    devices = allocate_vector(heap_general(kh), 8);
    drivers = allocate_vector(heap_general(kh), 8);
    spin_lock_init(&pci_lock);
}
