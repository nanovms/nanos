#pragma once
#define PCIR_MEMBASE0_2 0x1c
#define PCIR_MEMLIMIT0_2 0x20
#define PCIR_MEMBASE1_2 0x24
#define PCIR_MEMLIMIT1_2 0x28
#define PCIR_IOBASEL_1  0x1c
#define PCIR_IOLIMITL_1 0x1d
#define PCIR_IOBASEH_1  0x30
#define PCIR_IOLIMITH_1 0x32

void pci_cfgwrite(int bus, int slot, int func, int reg, int bytes, u32 source);
u32 pci_cfgread(int bus, int slot, int func, int reg, int bytes);
u32 pci_readbar(unsigned bus, unsigned slot, unsigned func, int bid, u32 *length);
    
void pci_discover();
void pci_set_bus_master(int bus, int slot, int func);
#define PCI_COMMAND_REGISTER 6

void init_pci(kernel_heaps kh);
typedef closure_type(pci_probe, void , int, int, int ); // bus slot func
void register_pci_driver(u16 vendor, u16 device, pci_probe p);
void msi_format(u32 *address, u32 *data, int vector);

