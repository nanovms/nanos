#include <acpi.h>
#include <kernel.h>
#include <apic.h>
#include <drivers/acpi.h>
#include <io.h>

//#define ACPI_DEBUG
#ifdef ACPI_DEBUG
#define acpi_debug(x, ...) rprintf("ACPI: " x "\n", ##__VA_ARGS__)
#else
#define acpi_debug(x, ...)
#endif

#define acpi_heap   heap_locked(get_kernel_heaps())

closure_function(2, 0, void, acpi_irq,
                 ACPI_OSD_HANDLER, service_routine, void *, context)
{
    acpi_debug("irq");
    bound(service_routine)(bound(context));
}

static u64 find_rsdp_internal(u64 va, u64 len)
{
    assert((va & MASK(4)) == 0);
    for (u64 i = va; i < va + len; i += 16) {
        acpi_rsdp rsdp = pointer_from_u64(i);
        if (runtime_memcmp(&rsdp->sig, "RSD PTR ", sizeof(rsdp->sig)) != 0)
            continue;
        if (!acpi_checksum(rsdp, 20)) {
            acpi_debug("%s: RSDP failed checksum", __func__);
            continue;
        }
        return i;
    }
    return INVALID_PHYSICAL;
}

/* ACPI spec says the RSDP is found in the first KB of EBDA or
 * in the BIOS ROM space between 0xe0000 and 0xfffff */
#define BIOS_SEARCH_LENGTH (128*KB)
#define BIOS_SEARCH_ADDR 0xe0000
#define EDBA_SEARCH_LENGTH (1*KB)
static u64 find_rsdp(kernel_heaps kh)
{
    u64 va, edba_pa, rsdp;
    heap vh = (heap)heap_virtual_page(kh);

    va = allocate_u64(vh, BIOS_SEARCH_LENGTH);
    assert(va != INVALID_PHYSICAL);

    /* Search BIOS ROM */
    map(va, BIOS_SEARCH_ADDR, BIOS_SEARCH_LENGTH, pageflags_memory());
    rsdp = find_rsdp_internal(va, BIOS_SEARCH_LENGTH);
    unmap(va, BIOS_SEARCH_LENGTH);
    if (rsdp != INVALID_PHYSICAL) {
        rsdp = BIOS_SEARCH_ADDR + rsdp - va;
        goto out;
    }

    /* Search EDBA as a backup. The EDBA segment location is found at
     * 40:0Eh per ACPI spec */
    map(va, 0, PAGESIZE, pageflags_memory());
    edba_pa = (*(u16 *)(va + 0x40e))<<4;
    unmap(va, PAGESIZE);
    u64 edba_pa_map = edba_pa & ~PAGEMASK;
    u64 edba_off = edba_pa & PAGEMASK;
    u64 edba_map_len = pad(edba_off + EDBA_SEARCH_LENGTH, PAGESIZE);
    map(va, edba_pa_map, edba_map_len, pageflags_memory());
    rsdp = find_rsdp_internal(va + edba_off, EDBA_SEARCH_LENGTH);
    if (rsdp != INVALID_PHYSICAL)
        rsdp = edba_pa_map + rsdp - va;
    unmap(va, edba_map_len);
out:
    deallocate_u64(vh, va, BIOS_SEARCH_LENGTH);
    if (rsdp != INVALID_PHYSICAL) {
        acpi_debug("%s: found RSDP at %p", __func__, rsdp);
    } else {
        acpi_debug("%s: could not find valid RSDP", __func__);
    }
    return rsdp;
}

/* OS services layer */

ACPI_PHYSICAL_ADDRESS AcpiOsGetRootPointer(void)
{
    u64 rsdp = find_rsdp(get_kernel_heaps());
    return (rsdp != INVALID_PHYSICAL) ? rsdp : 0;
}

ACPI_STATUS AcpiOsReadPort(ACPI_IO_ADDRESS address, UINT32 *value, UINT32 width)
{
    switch (width) {
    case 8:
        *value = in8(address);
        break;
    case 16:
        *value = in16(address);
        break;
    case 32:
        *value = in32(address);
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
        out8(address, value);
        break;
    case 16:
        out16(address, value);
        break;
    case 32:
        out32(address, value);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

UINT32 AcpiOsInstallInterruptHandler(UINT32 interrupt_number, ACPI_OSD_HANDLER service_routine,
                                     void *context)
{
    thunk irq_handler = closure(acpi_heap, acpi_irq, service_routine, context);
    if (irq_handler == INVALID_ADDRESS)
        return AE_NO_MEMORY;
    ioapic_register_int(interrupt_number, irq_handler, "ACPI");
    return AE_OK;
}

ACPI_STATUS AcpiOsRemoveInterruptHandler(UINT32 interrupt_number, ACPI_OSD_HANDLER service_routine)
{
    return AE_NOT_IMPLEMENTED;
}
