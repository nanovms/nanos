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

void pci_checko();
    
