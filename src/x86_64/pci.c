#include <runtime.h>
#include <pci.h>
#include <kvm_platform.h>

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

#define PCIR_VENDOR     0x00
#define PCIR_DEVICE     0x02
#define PCIR_CAPABILITIES_POINTER   0x34


/* enable configuration space accesses and return data port address */
static int pci_cfgenable(unsigned bus, unsigned slot, unsigned func, int reg, int bytes)
{
    int dataport = 0;
    
    if (bus <= PCI_BUSMAX && slot <= PCI_SLOTMAX && func <= PCI_FUNCMAX &&
        (unsigned)reg <= PCI_REGMAX && bytes != 3 &&
        (unsigned)bytes <= 4 && (reg & (bytes - 1)) == 0) {
        out32(CONF1_ADDR_PORT, (1U << 31) | (bus << 16) | (slot << 11) 
              | (func << 8) | (reg & ~0x03));
        dataport = CONF1_DATA_PORT + (reg & 0x03);
    }
    return (dataport);
}

u32 pci_cfgread(int bus, int slot, int func, int reg, int bytes)
{
    u32 data = -1;
    int port;
    
    port = pci_cfgenable(bus, slot, func, reg, bytes);
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

u32 pci_readbar(unsigned bus, unsigned slot, unsigned func, int bid, u32 *length)
{
    u32 base = pci_cfgread(bus, slot, func, 0x10 + 4 *bid, 4);
    pci_cfgwrite(bus, slot, func, 0x10 + 4 *bid, 4, 0xffffffff);
    *length = ~pci_cfgread(bus, slot, func, 0x10 + 4 *bid, 4) + 1;
    pci_cfgwrite(bus, slot, func, 0x10 + 4 *bid, 4, base);    
    return base;
}

void pci_cfgwrite(int bus, int slot, int func, int reg, int bytes, u32 source)
{
    int port;
    
    port = pci_cfgenable(bus, slot, func, reg, bytes);
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

void pci_set_bus_master(int bus, int slot, int func)
{
    u16 command = pci_cfgread(bus, slot, func, PCI_COMMAND_REGISTER, 2);
    command |= 4; // bus master
    pci_cfgwrite(bus, slot, func, PCI_COMMAND_REGISTER, 2, command);
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

// assume the singel bus layout
static u32 *msi_map[PCI_SLOTMAX];

void msi_map_vector(int slot, int msislot, int vector)
{
    u32 a, d;
    u32 vector_control = 0;
    msi_format(&a, &d, vector);
    msi_map[slot][msislot*4] = a;
    msi_map[slot][msislot*4 + 1] = 0;
    msi_map[slot][msislot*4 + 2] = d;
    msi_map[slot][msislot*4 + 3] = vector_control;
}

    
#define MSI_MESSAGE_ENABLE 1
#define PCI_CAPABILITY_MSIX 0x11
extern void *pagebase;

// use the global nodespace
static table drivers;
static heap virtual_huge;
static heap pages;

void register_pci_driver(u16 vendor, u16 device, pci_probe p)
{
    table_set(drivers, pointer_from_u64((u64)(vendor<<16|device)), p);
}


void pci_discover()
{
    // we dont actually need to do recursive discovery, qemu leaves it all on bus0 for us
    for (int i = 0; i < 16; i++) {
        u32 vid = pci_cfgread(0, i, 0, PCIR_VENDOR, 2);
        u32 did = pci_cfgread(0, i, 0, PCIR_DEVICE, 2);
        if (!((vid == 0xffff)  && (did == 0xffff))) {
            u32 cp = pci_cfgread(0, i, 0, PCIR_CAPABILITIES_POINTER, 1);
            while (cp) {
                u32 cp0 = pci_cfgread(0, i, 0, cp, 1);
                if (cp0 == PCI_CAPABILITY_MSIX) {
                    u32 vector_table = pci_cfgread(0, i, 0, cp+4, 4);
                    pci_cfgread(0, i, 0, cp+8, 4);
                    u32 len;
                    u32 vector_base = pci_readbar(0, i, 0, vector_table & 0x7, &len);
                    len = pad(len, PAGESIZE);
                    // ?? this is per device, so why is it global? - pass to probe?
                    u8 *vector_table_ptr = allocate(virtual_huge, len);
                    map((u64)vector_table_ptr, vector_base, len, PAGE_DEV_FLAGS, pages);
                    msi_map[i] = (void *) (vector_table_ptr + (vector_table & ~0x7)); // table offset
                    // qemu gets really* mad if you do this a 16 bit write
                    pci_cfgwrite(0, i, 0, cp+3, 1, 0x80);
                    break;
                }
                cp = pci_cfgread(0, i, 0, cp + 1, 1);
            }
            pci_probe p;
            if ((p =  table_find(drivers, pointer_from_u64((u64)(vid<<16|did)))))
                apply(p, 0, i, 0);
        }
    }
}

void init_pci(kernel_heaps kh)
{
    // should use the global node space
    virtual_huge = heap_virtual_huge(kh);
    pages = heap_pages(kh);
    drivers = allocate_table(heap_general(kh), identity_key, pointer_equal);
}
