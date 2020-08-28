#define DEV_MAP_SIZE          0x40000000
#define DEV_BASE_CPUPERIPHS   0x08000000
#define DEV_BASE_GIC_DIST     0x08000000
#define DEV_BASE_GIC_CPU      0x08010000
#define DEV_BASE_GIC_V2M      0x08020000
#define DEV_BASE_GIC_HYP      0x08030000
#define DEV_BASE_GIC_VCPU     0x08040000
#define DEV_BASE_GIC_ITS      0x08080000
#define DEV_BASE_GIC_REDIST   0x080A0000
#define DEV_BASE_UART         0x09000000
#define DEV_BASE_RTC          0x09010000
#define DEV_BASE_FW_CFG       0x09020000
#define DEV_BASE_GPIO         0x09030000
#define DEV_BASE_SECURE_UART  0x09040000
#define DEV_BASE_SMMU         0x09050000
#define DEV_BASE_PCDIMM_ACPI  0x09070000
#define DEV_BASE_ACPI_GED     0x09080000
#define DEV_BASE_NVDIMM_ACPI  0x09090000
#define DEV_BASE_MMIO         0x0a000000
#define DEV_BASE_PLATFORM_BUS 0x0c000000
#define DEV_BASE_SECURE_MEM   0x0e000000
#define DEV_BASE_PCIE_MMIO    0x10000000
#define DEV_BASE_PCIE_PIO     0x3eff0000
#define DEV_BASE_PCIE_ECAM    0x3f000000

#define GIC_SGI_INTS_START 0
#define GIC_SGI_INTS_END   16
#define GIC_PPI_INTS_START 16
#define GIC_PPI_INTS_END   32
#define GIC_SPI_INTS_START 32
#define GIC_SPI_INTS_END   64
#define GIC_MAX_INT        GIC_SPI_INTS_END
#define GIC_MAX_PRIO       16
#define GIC_TIMER_IRQ      27

#define dev_base_pointer(x) (pointer_from_u64(DEVICE_BASE + DEV_BASE_ ##x))

void early_debug(const char *s);
void early_debug_u64(u64 n);
void early_dump(void *p, unsigned long length);
