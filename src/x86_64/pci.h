/* PCI config register */
#define PCIR_VENDOR     0x00
#define PCIR_DEVICE     0x02
#define PCIR_SUBCLASS   0x0a
#define PCIR_CLASS      0x0b
#define PCIR_HDRTYPE    0x0e
#define PCIM_HDRTYPE            0x7f
#define PCIM_HDRTYPE_NORMAL     0x00
#define PCIM_HDRTYPE_BRIDGE     0x01
#define PCIM_HDRTYPE_CARDBUS    0x02
#define PCIM_MFDEV              0x80
#define PCIR_MEMBASE0_2 0x1c
#define PCIR_MEMLIMIT0_2 0x20
#define PCIR_MEMBASE1_2 0x24
#define PCIR_MEMLIMIT1_2 0x28
#define PCIR_IOBASEL_1  0x1c
#define PCIR_IOLIMITL_1 0x1d
#define PCIR_IOBASEH_1  0x30
#define PCIR_IOLIMITH_1 0x32

/* PCI device class */
#define PCIC_STORAGE 0x01
#define PCIC_DISPLAY 0x03

/* PCI device subclass */
#define PCIS_STORAGE_IDE 0x01

typedef struct pci_dev *pci_dev;

struct pci_dev {
    int bus;
    int slot;
    int function;
};

void pci_cfgwrite(pci_dev dev, int reg, int bytes, u32 source);
u32 pci_cfgread(pci_dev dev, int reg, int bytes);

static inline u16 pci_get_vendor(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_VENDOR, 2);
}

static inline u16 pci_get_device(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_DEVICE, 2);
}

static inline u8 pci_get_class(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_CLASS, 1);
}

static inline u8 pci_get_subclass(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_SUBCLASS, 1);
}

static inline u8 pci_get_hdrtype(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_HDRTYPE, 1);
}

u32 pci_readbar(pci_dev dev, int bid, u32 *length);
    
void pci_discover();
void pci_set_bus_master(pci_dev dev);
void pci_enable_msix(pci_dev dev);
void pci_setup_msix(pci_dev dev, int msi_slot, thunk h, const char *name);

#define PCI_COMMAND_REGISTER 6

void init_pci(kernel_heaps kh);

typedef closure_type(pci_probe, boolean, pci_dev); // bus slot func

void register_pci_driver(pci_probe p);
