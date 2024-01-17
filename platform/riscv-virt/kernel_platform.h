#define PHYSMEM_BASE          0x80000000
#define BIOS_SIZE             (256*KB)
#define DTB_SIZE              (16*KB)
#define INIT_PAGEMEM          (PHYSMEM_BASE+BIOS_SIZE+DTB_SIZE)
#define INIT_IDENTITY_SIZE    0x00800000

#define DEVICETREE_BLOB_BASE  (KERNEL_BASE-DTB_SIZE)

#define DEV_MAP_SIZE          0x80000000
#define DEV_BASE_UART         0x10000000 
#define DEV_BASE_CLINT        0x02000000
#define DEV_BASE_PLIC         0x0c000000
#define DEV_BASE_RTC          0x00101000
#define DEV_BASE_SYSCON       0x00100000
#define DEV_BASE_PCIE_ECAM    0x30000000
#define DEV_BASE_PCIE_MMIO    0x40000000
#define DEV_BASE_PCIE_PIO     0x03000000

#define SYSCON_POWEROFF       0x5555
#define SYSCON_POWEROFF_FAIL  0x3333
#define SYSCON_REBOOT         0x7777

#ifndef __ASSEMBLY__
#define DEVICETREE pointer_from_u64(DEVICETREE_BLOB_BASE)

#define mmio_base_addr(x) ((u64)(DEVICE_BASE + DEV_BASE_ ##x))

#include "sbi_ecall_interface.h"
#endif
