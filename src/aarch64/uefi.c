#include <runtime.h>
#include <page.h>
#include <uefi.h>

void uefi_arch_setup(heap general, heap aligned, uefi_arch_options options)
{
    options->load_to_physical = true;
}

void uefi_start_kernel(void *image_handle, efi_system_table system_table, buffer kern_elf,
                       void *kern_entry)
{
    struct uefi_boot_params boot_params = {0};
    for (int i = 0; i < system_table->number_of_table_entries; i++) {
        efi_configuration_table table = &system_table->configuration_table[i];
        if (!runtime_memcmp(&table->guid, &uefi_acpi20_table, sizeof(table->guid))) {
            boot_params.acpi_rsdp = u64_from_pointer(table->table);
            break;
        }
    }
    boot_params.efi_rt_svc = system_table->runtime_services;
    uefi_exit_bs(&boot_params.mem_map);

    /* disable MMU */
    u64 sctlr = 0;
    asm volatile ("msr SCTLR_EL1, %0;"
                  "isb":: "r" (sctlr));

    void (*start)(u64 x0, u64 x1) = kern_entry;
    start(0, u64_from_pointer(&boot_params));
}

physical map_with_complete(u64 v, physical p, u64 length, pageflags flags, status_handler complete)
{
    /* Mapping is not needed, since the MMU is disabled before starting the kernel. */
    if (complete)
        apply(complete, STATUS_OK);
    return p;
}
