#include <runtime.h>
#include <drivers/dmi.h>
#include <kernel_machine.h>
#include <page.h>
#include <region.h>
#include <uefi.h>

#define PGDIR_ADDR      pointer_from_u64(0x8000)
#define KERN_ENTRY_ADDR pointer_from_u64(0x8008)
#define START_FUNC_ADDR pointer_from_u64(0x8010)

#define START_FUNC_SIZE 0x20

static heap uefi_heap;
static void *pgdir; /* page directory (PML4) */
static rangemap rsvd_mem;

static void rsvd_mem_add(range r)
{
    rmnode n = allocate(uefi_heap, sizeof(*n));
    assert(n != INVALID_ADDRESS);
    rmnode_init(n, r);
    assert(rangemap_insert(rsvd_mem, n));
}

/* This function runs at a fixed address (START_FUNC_ADDR). It must not access static variables or
 * use any RIP-relative addressing, and its code size must not exceed START_FUNC_SIZE. */
static void __attribute__((noinline)) start_kernel_new_stack(void)
{
    void **pgdir_addr = PGDIR_ADDR;
    mov_to_cr("cr3", *pgdir_addr);
    void (**kern_entry_addr)(u64 rdi, u64 rsi) = KERN_ENTRY_ADDR;
    (*kern_entry_addr)(0, 0);
}

static void start_kernel(void *kern_entry)
{
    /* Before switching to the new set of page tables, instructions, stack pointer and data must be
     * moved to addresses below INITIAL_MAP_SIZE. */
    void **pgdir_addr = PGDIR_ADDR;
    *pgdir_addr = pgdir;
    void **kern_entry_addr = KERN_ENTRY_ADDR;
    *kern_entry_addr = kern_entry;
    runtime_memcpy(START_FUNC_ADDR, start_kernel_new_stack, START_FUNC_SIZE);
    switch_stack((u64)INITIAL_MAP_SIZE - STACK_ALIGNMENT, START_FUNC_ADDR);
}

void uefi_arch_setup(heap general, heap aligned, uefi_arch_options options)
{
    uefi_heap = general;
    regions->type = 0;  /* initialize region area */
    rsvd_mem = allocate_rangemap(general);
    assert(rsvd_mem != INVALID_ADDRESS);
    u64 initial_pages_size = INITIAL_PAGES_SIZE;
    u64 initial_pages = allocate_u64(aligned, initial_pages_size);
    assert(initial_pages != INVALID_PHYSICAL);
    if (initial_pages < INITIAL_MAP_SIZE) {
        /* we don't want the initial pages to overlap with the initial map area */
        initial_pages_size -= INITIAL_MAP_SIZE - initial_pages;
        initial_pages = INITIAL_MAP_SIZE;
    }
    create_region(initial_pages, initial_pages_size, REGION_INITIAL_PAGES);
    rsvd_mem_add(irangel(initial_pages, initial_pages_size));
    init_mmu();
    pgdir = bootstrap_page_tables(region_allocator(general, PAGESIZE, REGION_INITIAL_PAGES));
    map(0, 0, INITIAL_MAP_SIZE, pageflags_writable(pageflags_exec(pageflags_memory())));
    map(initial_pages, initial_pages, initial_pages_size, pageflags_writable(pageflags_memory()));
    options->load_to_physical = false;
}

closure_function(1, 1, boolean, uefi_add_mem,
                 region, last_region,
                 range, r)
{
    region last_region = bound(last_region);
    if (last_region && (last_region->base + last_region->length == r.start))
        /* Merge adjacent regions. */
        last_region->length += range_span(r);
    else
        bound(last_region) = create_region(r.start, range_span(r), REGION_PHYSICAL);
    return true;
}

void uefi_start_kernel(void *image_handle, efi_system_table system_table, buffer kern_elf,
                       void *kern_entry)
{
    u64 kern_base = u64_from_pointer(buffer_ref(kern_elf, 0));
    u64 kern_len = pad(buffer_length(kern_elf), PAGESIZE);
    create_region(kern_base, kern_len, REGION_KERNIMAGE);
    rsvd_mem_add(irangel(kern_base, kern_len));
    for (int i = 0; i < system_table->number_of_table_entries; i++) {
        efi_configuration_table table = &system_table->configuration_table[i];
        if (!runtime_memcmp(&table->guid, &uefi_smbios_table, sizeof(table->guid)))
            create_region(u64_from_pointer(table->table), SMBIOS_EP_SIZE, REGION_SMBIOS);
        else if (!runtime_memcmp(&table->guid, &uefi_acpi20_table, sizeof(table->guid)))
            create_region(u64_from_pointer(table->table), sizeof(u64), REGION_RSDP);
    }
    struct uefi_mem_map map;
    uefi_exit_bs(&map);
    int num_desc = map.map_size / map.desc_size;
    range_handler gap_handler = stack_closure(uefi_add_mem, 0);
    for (int i = 0; i < num_desc; i++) {
        efi_memory_desc d = map.map + i * map.desc_size;
        switch (d->type) {
        case efi_loader_code:
        case efi_loader_data:
        case efi_boot_services_code:
        case efi_boot_services_data:
        case efi_conventional_memory:
            rangemap_range_find_gaps(rsvd_mem,
                irangel(d->physical_start, d->number_of_pages * PAGESIZE), gap_handler);
            break;
        default:
            break;
        }
    }
    start_kernel(kern_entry);
}
