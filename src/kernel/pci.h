/* some PCI bus constants */
#define	PCI_DOMAINMAX	65535	/* highest supported domain number */
#define	PCI_BUSMAX	255	/* highest supported bus number */
#define	PCI_SLOTMAX	31	/* highest supported slot number */
#define	PCI_FUNCMAX	7	/* highest supported function number */
#define	PCI_REGMAX	255	/* highest supported config register addr. */
#define	PCIE_REGMAX	4095	/* highest supported config register addr. */
#define	PCI_MAXHDRTYPE	2

#define PCIR_CAPABILITIES_POINTER   0x34

/* Capability Register Offsets */
#define PCICAP_ID       0x0
#define PCICAP_NEXTPTR  0x1

#define PCIR_INTERRUPT_LINE 0x3C

/* PCI config register */
#define PCIR_VENDOR     0x00
#define PCIR_DEVICE     0x02
#define PCIR_STATUS     0x06
#define PCIR_REVID      0x08
#define PCIR_PROG_IF    0x09
#define PCIR_SUBCLASS   0x0a
#define PCIR_CLASS      0x0b
#define PCIR_HDRTYPE    0x0e

#define PCIM_HDRTYPE            0x7f
#define PCIM_HDRTYPE_NORMAL     0x00
#define PCIM_HDRTYPE_BRIDGE     0x01
#define PCIM_HDRTYPE_CARDBUS    0x02
#define PCIM_MFDEV              0x80

#define PCIR_SECBUS_1   0x19
#define PCIR_MEMBASE0_2 0x1c
#define PCIR_MEMLIMIT0_2 0x20
#define PCIR_MEMBASE1_2 0x24
#define PCIR_MEMLIMIT1_2 0x28
#define PCIR_IOBASEL_1  0x1c
#define PCIR_IOLIMITL_1 0x1d
#define PCIR_SUBS_VND   0x2c
#define PCIR_SUBDEV_0   0x2e
#define PCIR_IOBASEH_1  0x30
#define PCIR_IOLIMITH_1 0x32
#define PCIR_INT_LINE   0x3c
#define PCIR_INT_PIN    0x3d

/* PCI device class */
#define PCIC_STORAGE 0x01
#define PCIS_STORAGE_IDE 0x01
#define PCIS_STORAGE_NVM 0x08
#define PCIPI_STORAGE_NVME  0x02

#define PCIC_DISPLAY 0x03
#define PCIS_VGA        0x00
#define PCIS_XGA        0x01
#define PCIS_3D         0x02

#define PCIC_BRIDGE 0x06
#define PCIS_BRIDGE_PCI 0x04

typedef struct pci_dev *pci_dev;

closure_type(pci_probe, boolean, pci_dev dev); // bus slot func
closure_type(pci_remove, void, void *driver_data, thunk complete);

typedef struct pci_driver {
    pci_probe probe;
    pci_remove remove;
} *pci_driver;

struct pci_bar {
    u64 addr;
    u64 size;
    u64 vaddr;         // mapped address (for PCI_BAR_MEMORY)
    u64 vlen;          // size of mapped memory (for PCI_BAR_MEMORY)
    u8 type;           // PCI_BAR_IOPORT, PCI_BAR_MEMORY
    u8 flags;          // PCI_BAR_F_*
};

struct pci_dev {
    int bus;
    int slot;
    int function;
    pci_driver driver;
    void *driver_data;
    struct pci_bar msix_bar;
};

#define pci_dev_id(dev) ((dev->bus << 8) | (dev->slot << 3) | dev->function)

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

static inline u16 pci_get_subdevice(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_SUBDEV_0, 2);
}

static inline u16 pci_get_subsystem_vendor(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_SUBS_VND, 2);
}

static inline u8 pci_get_revid(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_REVID, 1);
}

static inline u8 pci_get_class(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_CLASS, 1);
}

static inline u8 pci_get_subclass(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_SUBCLASS, 1);
}

static inline u8 pci_get_prog_if(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_PROG_IF, 1);
}

static inline u8 pci_get_hdrtype(pci_dev dev)
{
    return pci_cfgread(dev, PCIR_HDRTYPE, 1);
}

#define PCI_BAR_MEMORY 0
#define PCI_BAR_IOPORT 1

#define PCI_BAR_F_64BIT        U64_FROM_BIT(2)
#define PCI_BAR_F_PREFETCHABLE U64_FROM_BIT(3)

#define	PCIR_BARS       0x10
#define	PCIR_BAR(x)     (PCIR_BARS + (x) * 4)
#define	PCIR_MAX_BAR_0  5

#define PCI_BAR_B_TYPE_MASK      0x1
#define PCI_BAR_B_IOPORT_MASK    0x3
#define PCI_BAR_B_MEMORY_MASK    0xf

/*
 * PCI BAR (TODO name? really segment thereof)
 */

u64 pci_bar_size(pci_dev dev, u8 type, u8 flags, int bar);
void pci_bar_init(pci_dev dev, struct pci_bar *b, int bar, bytes offset, bytes length);
void pci_bar_deinit(struct pci_bar *b);
void pci_platform_init(void);
void pci_platform_init_bar(pci_dev dev, int bar);
u64 pci_platform_allocate_msi(pci_dev dev, thunk h, sstring name, u32 target_cpu,
                              u32 *address, u32 *data);
void pci_platform_deallocate_msi(pci_dev dev, u64 v);
boolean pci_platform_has_msi(void);

u8 pci_bar_read_1(struct pci_bar *b, u64 offset);
void pci_bar_write_1(struct pci_bar *b, u64 offset, u8 val);

u16 pci_bar_read_2(struct pci_bar *b, u64 offset);
void pci_bar_write_2(struct pci_bar *b, u64 offset, u16 val);

u32 pci_bar_read_4(struct pci_bar *b, u64 offset);
void pci_bar_write_4(struct pci_bar *b, u64 offset, u32 val);

u64 pci_bar_read_8(struct pci_bar *b, u64 offset);
void pci_bar_write_8(struct pci_bar *b, u64 offset, u64 val);

/* Capability Identification Numbers */
#define PCIY_MSI    0x05
#define PCIY_VENDOR 0x09
#define PCIY_MSIX 0x11

u32 pci_find_cap(pci_dev dev, u8 cap);
u32 pci_find_next_cap(pci_dev dev, u8 cap, u32 cp);

void pci_bridge_set_iomem(range window, id_heap iomem);
id_heap pci_bus_get_iomem(int bus);
void pci_discover();
void pci_probe_device(pci_dev dev);
void pci_remove_device(pci_dev dev, thunk completion);
void pci_set_bus_master(pci_dev dev);
int pci_get_msix_count(pci_dev dev);
int pci_enable_msix(pci_dev dev);
void pci_enable_io_and_memory(pci_dev dev);
u64 pci_setup_msix_aff(pci_dev dev, int msi_slot, thunk h, sstring name, range cpu_affinity);
#define pci_setup_msix(dev, slot, handler, name)    \
    pci_setup_msix_aff(dev, slot, handler, name, irange(0, 0))
void pci_teardown_msix(pci_dev dev, int msi_slot);
void pci_disable_msix(pci_dev dev);
void pci_setup_irq_aff(pci_dev dev, thunk h, sstring name, range cpu_affinity);
#define pci_setup_non_msi_irq(dev, handler, name)   \
    pci_setup_irq_aff(dev, handler, name, irange(0, 0))

static inline u64 pci_msix_table_addr(pci_dev dev)
{
    return dev->msix_bar.vaddr;
}

void pci_setup_fixed_irq(pci_dev dev, int v, thunk h, const char *name);

/* PCI config header registers for all devices */
#define PCIR_COMMAND 0x04

#define PCIM_CMD_IOEN           0x0001
#define PCIM_CMD_MEMORYEN       0x0002
#define PCIM_CMD_BUSMASTEREN    0x0004

void init_pci(kernel_heaps kh);

void register_pci_driver(pci_probe p, pci_remove remove);
