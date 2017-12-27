#include <runtime.h>
#include <virtio.h>
#include <pci.h>

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

void pci_cfgwrite(int bus, int slot, int func, int reg, int bytes, u32 source)
{
    u32 data = -1;
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

void pci_checko()
{
    // we dont actually need to do recursive discovery, qemu leaves it all on bus0 for us
    for (int i = 0; i < 16; i++) {
        u32 vid = pci_cfgread(0, i, 0, PCIR_VENDOR, 2);
        u32 did = pci_cfgread(0, i, 0, PCIR_DEVICE, 2);
        if ((vid ==  VIRTIO_PCI_VENDORID) &&  (did == VIRTIO_PCI_DEVICEID_MIN)) {
            attach_vtpci(0, i, 0);
        }
    }
}
