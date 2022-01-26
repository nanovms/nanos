#include <acpi.h>
#include <kernel.h>
#include <boot/uefi.h>
#include <drivers/acpi.h>

/* OS services layer */

ACPI_PHYSICAL_ADDRESS AcpiOsGetRootPointer(void)
{
    return boot_params.acpi_rsdp;
}

ACPI_STATUS AcpiOsReadPort(ACPI_IO_ADDRESS address, UINT32 *value, UINT32 width)
{
    switch (width) {
    case 8:
        *value = mmio_read_8(address);
        break;
    case 16:
        *value = mmio_read_16(address);
        break;
    case 32:
        *value = mmio_read_32(address);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

ACPI_STATUS AcpiOsWritePort(ACPI_IO_ADDRESS address, UINT32 value, UINT32 width)
{
    switch (width) {
    case 8:
        mmio_write_8(address, value);
        break;
    case 16:
        mmio_write_16(address, value);
        break;
    case 32:
        mmio_write_32(address, value);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

UINT32 AcpiOsInstallInterruptHandler(UINT32 interrupt_number, ACPI_OSD_HANDLER service_routine,
                                     void *context)
{
    return AE_NOT_IMPLEMENTED;
}

ACPI_STATUS AcpiOsRemoveInterruptHandler(UINT32 interrupt_number, ACPI_OSD_HANDLER service_routine)
{
    return AE_NOT_IMPLEMENTED;
}
