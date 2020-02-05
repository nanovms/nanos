#include <kernel.h>
#include <pci.h>
#include <page.h>
#include <io.h>

#ifdef PCI_DEBUG
# define pci_debug rprintf
#else
# define pci_debug(...) do { } while(0)
#endif // PCI_DEBUG

#define CONF1_ADDR_PORT    0x0cf8
#define CONF1_DATA_PORT    0x0cfc

#define CONF1_ENABLE       0x80000000ul
#define CONF1_ENABLE_CHK   0x80000000ul
#define CONF1_ENABLE_MSK   0x7f000000ul
#define CONF1_ENABLE_CHK1  0xff000001ul
#define CONF1_ENABLE_MSK1  0x80000001ul
#define CONF1_ENABLE_RES1  0x80000000ul

#define CONF2_ENABLE_PORT  0x0cf8
#define CONF2_FORWARD_PORT 0x0cfa

#define CONF2_ENABLE_CHK   0x0e
#define CONF2_ENABLE_RES   0x0e

/* some PCI bus constants */
#define	PCI_DOMAINMAX	65535	/* highest supported domain number */
#define	PCI_BUSMAX	255	/* highest supported bus number */
#define	PCI_SLOTMAX	31	/* highest supported slot number */
#define	PCI_FUNCMAX	7	/* highest supported function number */
#define	PCI_REGMAX	255	/* highest supported config register addr. */
#define	PCIE_REGMAX	4095	/* highest supported config register addr. */
#define	PCI_MAXHDRTYPE	2

#define PCIR_CAPABILITIES_POINTER   0x34
#define PCI_CAPABILITY_MSIX 0x11

// use the global nodespace
static vector drivers;
static heap virtual_huge;
static heap pages;

// assume the single bus layout
static u32 *msi_map[PCI_SLOTMAX + 1];

struct pci_driver {
    pci_probe probe;
    boolean attached;
};

/* enable configuration space accesses and return data port address */
static int pci_cfgenable(pci_dev dev, int reg, int bytes)
{
    int dataport = 0;

    if (dev->bus <= PCI_BUSMAX && dev->slot <= PCI_SLOTMAX && dev->function <= PCI_FUNCMAX &&
        (unsigned)reg <= PCI_REGMAX && bytes != 3 &&
        (unsigned)bytes <= 4 && (reg & (bytes - 1)) == 0) {
        out32(CONF1_ADDR_PORT, (1U << 31) | (dev->bus << 16) | (dev->slot << 11)
              | (dev->function << 8) | (reg & ~0x03));
        dataport = CONF1_DATA_PORT + (reg & 0x03);
    }
    return (dataport);
}

u32 pci_cfgread(pci_dev dev, int reg, int bytes)
{
    u32 data = -1;
    int port;

    port = pci_cfgenable(dev, reg, bytes);
    if (port != 0) {
        switch (bytes) {
        case 1:
            data = in8(port);
            break;
        case 2:
            data = in16(port);
            break;
        case 4:
            data = in32(port);
            break;
        }
    }
    return (data);
}

u32 pci_readbar(pci_dev dev, int bid, u32 *length)
{
    u32 base = pci_cfgread(dev, 0x10 + 4 *bid, 4);
    pci_cfgwrite(dev, 0x10 + 4 *bid, 4, 0xffffffff);
    *length = ~pci_cfgread(dev, 0x10 + 4 *bid, 4) + 1;
    pci_cfgwrite(dev, 0x10 + 4 *bid, 4, base);
    return base;
}

void pci_cfgwrite(pci_dev dev, int reg, int bytes, u32 source)
{
    int port;

    port = pci_cfgenable(dev, reg, bytes);
    if (port != 0) {
        switch (bytes) {
        case 1:
            out8(port, source);
            break;
        case 2:
            out16(port, source);
            break;
        case 4:
            out32(port, source);
            break;
        }
    }
}

void pci_set_bus_master(pci_dev dev)
{
    u16 command = pci_cfgread(dev, PCI_COMMAND_REGISTER, 2);
    command |= 4; // bus master
    pci_cfgwrite(dev, PCI_COMMAND_REGISTER, 2, command);
}

void pci_enable_msix(pci_dev dev)
{
     u32 cp = pci_cfgread(dev, PCIR_CAPABILITIES_POINTER, 1);
     while (cp != 0) {
         if (pci_cfgread(dev, cp, 1) != PCI_CAPABILITY_MSIX) {
             // next cap
	     cp = pci_cfgread(dev, cp + 1, 1);
             continue;
         }

         u32 vector_table = pci_cfgread(dev, cp + 4, 4);
         pci_cfgread(dev, cp + 8, 4);
         u32 len;
         u32 vector_base = pci_readbar(dev, vector_table & 0x7, &len);
         len = pad(len, PAGESIZE);
         // ?? this is per device, so why is it global? - pass to probe?
         u8 *vector_table_ptr = allocate(virtual_huge, len);
         map(u64_from_pointer(vector_table_ptr), vector_base, len, PAGE_DEV_FLAGS, pages);
         msi_map[dev->slot] = (void *) (vector_table_ptr + (vector_table & ~0x7)); // table offset
         // qemu gets really* mad if you do this a 16 bit write
         pci_cfgwrite(dev, cp + 3, 1, 0x80);
         break;
     }
}

void msi_format(u32 *address, u32 *data, int vector)
{
    u32 dm = 0;             // destination mode: ignored if rh == 0
    u32 rh = 0;             // redirection hint: 0 - disabled
    u32 destination = 0;    // destination APIC
    *address = (0xfee << 20) | (destination << 12) | (rh << 3) | (dm << 2);

    u32 mode = 0;           // delivery mode: 000 fixed, 001 lowest, 010 smi, 100 nmi, 101 init, 111 extint
    u32 level = 0;          // trigger level: 0 - deassert, 1 - assert
    u32 trigger = 0;        // trigger mode: 0 - edge, 1 - level
    *data = (trigger << 15) | (level << 14) | (mode << 8) | vector;
}

void pci_setup_msix(pci_dev dev, int msi_slot, thunk h, const char *name)
{
    int v = allocate_interrupt();
    register_interrupt(v, h, name);

    u32 a, d;
    u32 vector_control = 0;
    msi_format(&a, &d, v);

    msi_map[dev->slot][msi_slot*4] = a;
    msi_map[dev->slot][msi_slot*4 + 1] = 0;
    msi_map[dev->slot][msi_slot*4 + 2] = d;
    msi_map[dev->slot][msi_slot*4 + 3] = vector_control;
}

void register_pci_driver(pci_probe probe)
{
    struct pci_driver *d = allocate(drivers->h, sizeof(struct pci_driver));
    d->probe = probe;
    d->attached = false;
    vector_push(drivers, d);
}

static void pci_probe_device(pci_dev dev)
{
    u16 vendor = pci_get_vendor(dev);
    if (vendor == 0xffff)
        return;
    pci_debug("%s: %02x:%02x:%x: %04x:%04x\n",
        __func__, dev->bus, dev->slot, dev->function, vendor, pci_get_device(dev));

    struct pci_driver *d;
    vector_foreach(drivers, d) {
        if (!d->attached && apply(d->probe, dev)) {
            d->attached = true;
        }
    }
}

/*
 * See https://wiki.osdev.org/PCI#Enumerating_PCI_Buses
 */
void pci_discover()
{
    // we dont actually need to do recursive discovery, qemu leaves it all on bus0 for us
    for (int i = 0; i <= PCI_SLOTMAX; i++) {
        struct pci_dev _dev = { .bus = 0, .slot = i, .function = 0 };
        pci_dev dev = &_dev;

        pci_probe_device(dev);

        // check multifunction devices
        if (pci_get_hdrtype(dev) & PCIM_MFDEV) {
            for (int f = 1; f < 8; f++) {
                dev->function = f;
                pci_probe_device(dev);
            }
        }
    }
}

void init_pci(kernel_heaps kh)
{
    // should use the global node space
    virtual_huge = (heap)heap_virtual_huge(kh);
    pages = heap_pages(kh);
    drivers = allocate_vector(heap_general(kh), 8);
}
