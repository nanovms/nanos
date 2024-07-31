/* UEFI standard definitions */

typedef u16 wchar_t;
typedef u64 efi_status;

#define EFIERR(a)   (0x8000000000000000ull | a)

#define EFI_ERROR(s)    (((s64)s) < 0)

#define EFI_SUCCESS             0
#define EFI_LOAD_ERROR          EFIERR(1)
#define EFI_INVALID_PARAMETER   EFIERR(2)
#define EFI_UNSUPPORTED         EFIERR(3)
#define EFI_BAD_BUFFER_SIZE     EFIERR(4)
#define EFI_BUFFER_TOO_SMALL    EFIERR(5)

#ifndef EFIAPI
#define EFIAPI
#endif

typedef struct efi_guid {
    u32 data1;
    u16 data2;
    u16 data3;
    u8 data4[8];
} *efi_guid;

typedef struct efi_table_header {
    u64 signature;
    u32 revision;
    u32 header_size;
    u32 crc32;
    u32 reserved;
} *efi_table_header;

typedef struct efi_input_key {
    u16 scan_code;
    wchar_t unicode_char;
} *efi_input_key;

typedef struct simple_input_interface *simple_input_interface;
typedef struct simple_text_output_interface *simple_text_output_interface;

typedef efi_status (EFIAPI *efi_input_reset)(simple_input_interface this,
        boolean extended_verification);
typedef efi_status (EFIAPI *efi_input_read_key)(simple_input_interface this, efi_input_key key);

struct simple_input_interface {
    efi_input_reset reset;
    efi_input_read_key read_key_stroke;
    void *wait_for_key;
};

typedef efi_status (EFIAPI *efi_text_reset)(simple_text_output_interface this,
        boolean extended_verification);
typedef efi_status (EFIAPI *efi_text_output_string)(simple_text_output_interface this,
        wchar_t *str);
typedef efi_status (EFIAPI *efi_text_test_string)(simple_text_output_interface this, wchar_t *str);
typedef efi_status (EFIAPI *efi_text_query_mode)(simple_text_output_interface this, int mode_number,
        int *columns, int *rows);
typedef efi_status (EFIAPI *efi_text_set_mode)(simple_text_output_interface this, int mode_number);
typedef efi_status (EFIAPI *efi_text_set_attribute)(simple_text_output_interface this,
        int attribute);
typedef efi_status (EFIAPI *efi_text_clear_screen)(simple_text_output_interface this);
typedef efi_status (EFIAPI *efi_text_set_cursor_position)(simple_text_output_interface this,
        int column, int row);
typedef efi_status (EFIAPI *efi_text_enable_cursor)(simple_text_output_interface this,
        boolean enable);

typedef struct simple_text_output_mode {
    u32 max_mode;
    u32 mode;
    u32 attribute;
    u32 cursor_column;
    u32 cursor_row;
    boolean cursor_visible;
} *simple_text_output_mode;

struct simple_text_output_interface {
    efi_text_reset reset;
    efi_text_output_string output_string;
    efi_text_test_string test_string;
    efi_text_query_mode query_mode;
    efi_text_set_mode set_mode;
    efi_text_set_attribute set_attribute;
    efi_text_clear_screen clear_screen;
    efi_text_set_cursor_position set_cursor_position;
    efi_text_enable_cursor enable_cursor;
    simple_text_output_mode mode;
};

#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL  0x00000001
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL        0x00000002
#define EFI_OPEN_PROTOCOL_TEST_PROTOCOL       0x00000004
#define EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER 0x00000008
#define EFI_OPEN_PROTOCOL_BY_DRIVER           0x00000010
#define EFI_OPEN_PROTOCOL_EXCLUSIVE           0x00000020

typedef struct efi_block_io_protocol *efi_block_io_protocol;
typedef struct efi_block_io_media {
    u32 media_id;
    boolean removable_media;
    boolean media_present;
    boolean logical_partition;
    boolean read_only;
    boolean write_caching;
    u32 block_size;
    u32 io_align;
    u64 last_block;
    /* revision 2 */
    u64 lowest_aligned_lba;
    u32 logical_blocks_per_physical_block;
    /* revision 3 */
    u32 optimal_transfer_length_granularity;
} *efi_block_io_media;

typedef efi_status (EFIAPI *efi_block_reset)(efi_block_io_protocol this,
        boolean extended_verification);
typedef efi_status (EFIAPI *efi_block_read)(efi_block_io_protocol this, u32 media_id, u64 lba,
        u64 buffer_size, void *buffer);
typedef efi_status (EFIAPI *efi_block_write)(efi_block_io_protocol this, u32 media_id, u64 lba,
        u64 buffer_size, void *buffer);
typedef efi_status (EFIAPI *efi_block_flush)(efi_block_io_protocol this);

struct efi_block_io_protocol {
    u64 revision;
    efi_block_io_media media;
    efi_block_reset reset;
    efi_block_read read_blocks;
    efi_block_write write_blocks;
    efi_block_flush flush_blocks;
};

typedef efi_status (EFIAPI *efi_block_reset)(efi_block_io_protocol this,
        boolean extended_verification);
typedef efi_status (EFIAPI *efi_block_read)(efi_block_io_protocol this, u32 media_id, u64 lba,
        u64 buffer_size, void *buffer);
typedef efi_status (EFIAPI *efi_block_write)(efi_block_io_protocol this, u32 media_id, u64 lba,
        u64 buffer_size, void *buffer);
typedef efi_status (EFIAPI *efi_block_flush)(efi_block_io_protocol this);

typedef struct efi_rng_protocol *efi_rng_protocol;

typedef efi_status (EFIAPI *efi_rng_get_info)(efi_rng_protocol this, u64 *rng_algo_list_size,
        struct efi_guid *algo_list);
typedef efi_status (EFIAPI *efi_rng_get_rng)(efi_rng_protocol this, efi_guid rng_algo,
        u64 rng_value_length, void *rng_value);

struct efi_rng_protocol {
    efi_rng_get_info get_info;
    efi_rng_get_rng get_rng;
};

typedef enum {
    allocate_any_pages,
    allocate_maax_address,
    allocate_address,
    max_allocate_type
} efi_allocate_type;

typedef enum {
    efi_reserved_memory_type,
    efi_loader_code,
    efi_loader_data,
    efi_boot_services_code,
    efi_boot_services_data,
    efi_runtime_services_code,
    efi_runtime_services_data,
    efi_conventional_memory,
    efi_unusable_memory,
    efi_acpi_reclaim_memory,
    efi_acpi_memory_nvs,
    efi_memory_mapped_io,
    efi_memory_mapped_io_port_space,
    efi_pal_code,
    efi_max_memory_type
} efi_memory_type;

typedef struct efi_memory_desc {
    u32 type;
    u32 pad;
    u64 physical_start;
    void *virtual_start;
    u64 number_of_pages;
    u64 attribute;
} *efi_memory_desc;

/* memory descriptor attribute flags */
#define EFI_MEMORY_RUNTIME  U64_FROM_BIT(63)

typedef enum {
    timer_cancel,
    timer_periodic,
    timer_relative,
    timer_type_max
} efi_timer_delay;

typedef enum {
    efi_native_interface,
    efi_pcode_interface
} efi_interface_type;

typedef enum {
    all_handles,
    by_register_notify,
    by_protocol
} efi_locate_search_type;

typedef struct  {
    u8 type;
    u8 sub_type;
    u8 length[2];
} *efi_device_path;

typedef struct {
    void *agent_handle;
    void *controller_handle;
    u32 attributes;
    u32 open_count;
} *efi_open_protocol_information_entry;

typedef u64 (EFIAPI *efi_raise_tpl)(u64 new_tpl);
typedef void (EFIAPI *efi_restore_tpl)(u64 old_tpl);
typedef efi_status (EFIAPI *efi_allocate_pages)(efi_allocate_type type, efi_memory_type memory_type,
        u64 num_pages, void **memory);
typedef efi_status (EFIAPI *efi_free_pages)(void **memory, u64 num_pages);
typedef efi_status (EFIAPI *efi_get_memory_map)(u64 *memory_map_size,
        struct efi_memory_desc *memory_map, u64 *map_key, u64 *desc_size, u32 *desc_version);
typedef efi_status (EFIAPI *efi_allocate_pool)(efi_memory_type pool_type, u64 size, void **buffer);
typedef efi_status (EFIAPI *efi_free_pool)(void *buffer);
typedef efi_status (EFIAPI *efi_create_event)(u32 type, u64 notify_tpl,
        void (*notify_function)(void *event, void *context), void *notify_context, void **event);
typedef efi_status (EFIAPI *efi_set_timer)(void *event, efi_timer_delay type, u64 trigger_time);
typedef efi_status (EFIAPI *efi_wait_for_event)(u64 number_of_events, void **event, u64 *index);
typedef efi_status (EFIAPI *efi_signal_event)(void *event);
typedef efi_status (EFIAPI *efi_close_event)(void *event);
typedef efi_status (EFIAPI *efi_check_event)(void *event);
typedef efi_status (EFIAPI *efi_install_protocol_interface)(void *handle, efi_guid protocol,
        efi_interface_type interface_type, void *interface);
typedef efi_status (EFIAPI *efi_reinstall_protocol_interface)(void *handle, efi_guid protocol,
        void *old_interface, void *new_interface);
typedef efi_status (EFIAPI *efi_uninstall_protocol_interface)(void *handle, efi_guid protocol,
        void *interface);
typedef efi_status (EFIAPI *efi_handle_protocol)(void *handle, efi_guid protocol, void **interface);
typedef efi_status (EFIAPI *efi_register_protocol_notify)(efi_guid protocol, void *event,
        void **registration);
typedef efi_status (EFIAPI *efi_locate_handle)(efi_locate_search_type search_type,
        efi_guid protocol, void *search_key, u64 *buffer_size, void **buffer);
typedef efi_status (EFIAPI *efi_locate_device_path)(efi_guid protocol, efi_device_path *device_path,
        void **device);
typedef efi_status (EFIAPI *efi_install_configuration_table)(efi_guid guid, void *table);
typedef efi_status (EFIAPI *efi_image_load)(boolean boot_policy, void *parent_image_handle,
        efi_device_path file_path, void *source_buffer, u64 source_size, void **image_handle);
typedef efi_status (EFIAPI *efi_image_start)(void *image_handle, u64 *exit_data_size,
        wchar_t **exit_data);
typedef efi_status (EFIAPI *efi_exit)(void *image_handle, efi_status exit_status,
        u64 *exit_data_size, wchar_t **exit_data);
typedef efi_status (EFIAPI *efi_image_unload)(void *image_handle);
typedef efi_status (EFIAPI *efi_exit_boot_services)(void *image_handle, u64 map_key);
typedef efi_status (EFIAPI *efi_get_next_monotonic_count)(u64 *count);
typedef efi_status (EFIAPI *efi_stall)(u64 microseconds);
typedef efi_status (EFIAPI *efi_set_watchdog_timer)(u64 timeout, u64 watchdog_code, u64 data_size,
        wchar_t *watchdog_data);
typedef efi_status (EFIAPI *efi_connect_controller)(void *controller_handle,
        void **driver_image_handle, efi_device_path remaining_device_path, boolean recursive);
typedef efi_status (EFIAPI *efi_disconnect_controller)(void *controller_handle,
        void *driver_image_handle, void *child_handle);
typedef efi_status (EFIAPI *efi_open_protocol)(void *handle, efi_guid protocol, void **interface,
        void *agent_handle, void *controller_handle, u32 attributes);
typedef efi_status (EFIAPI *efi_close_protocol)(void *handle, efi_guid protocol, void *agent_handle,
        void *controller_handle);
typedef efi_status (EFIAPI *efi_open_protocol_information)(void *handle, efi_guid protocol,
        efi_open_protocol_information_entry *entry_buffer, u64 *entry_count);
typedef efi_status (EFIAPI *efi_protocols_per_handle)(void *handle, efi_guid **protocol_buffer,
        u64 *protocol_buffer_count);
typedef efi_status (EFIAPI *efi_locate_handle_buffer)(efi_locate_search_type search_type,
        efi_guid protocol, void *search_key, u64 *num_handles, void ***buffer);
typedef efi_status (EFIAPI *efi_locate_protocol)(efi_guid protocol, void *registration,
        void **interface);
typedef efi_status (EFIAPI *efi_install_multiple_protocol_interfaces)(void **handle, ...);
typedef efi_status (EFIAPI *efi_uninstall_multiple_protocol_interfaces)(void *handle, ...);
typedef efi_status (EFIAPI *efi_calculate_crc32)(void *data, u64 data_size, u32 *crc32);
typedef efi_status (EFIAPI *efi_copy_mem)(void *destination, void *source, u64 length);
typedef efi_status (EFIAPI *efi_set_mem)(void *buffer, u64 size, u8 value);
typedef efi_status (EFIAPI *efi_create_event_ex)(u32 type, u64 notify_tpl,
        void (*notify_function)(void *event, void *context), const void *notify_context,
        const efi_guid event_group, void **event);

typedef struct efi_boot_services {
    struct efi_table_header hdr;
    efi_raise_tpl raise_tpl;
    efi_restore_tpl restoretpl;
    efi_allocate_pages allocate_pages;
    efi_free_pages free_pages;
    efi_get_memory_map get_memory_map;
    efi_allocate_pool allocate_pool;
    efi_free_pool free_pool;
    efi_create_event create_event;
    efi_set_timer set_timer;
    efi_wait_for_event wait_for_event;
    efi_signal_event signal_event;
    efi_close_event close_event;
    efi_check_event check_event;
    efi_install_protocol_interface install_protocol_interface;
    efi_reinstall_protocol_interface reinstall_protocol_interface;
    efi_uninstall_protocol_interface uninstall_protocol_interface;
    efi_handle_protocol handle_protocol;
    efi_handle_protocol pc_handle_protocol;
    efi_register_protocol_notify register_protocol_notify;
    efi_locate_handle locate_handle;
    efi_locate_device_path locate_device_path;
    efi_install_configuration_table install_configuration_table;
    efi_image_load load_image;
    efi_image_start start_image;
    efi_exit exit;
    efi_image_unload unload_image;
    efi_exit_boot_services exit_boot_services;
    efi_get_next_monotonic_count get_next_monotonic_count;
    efi_stall stall;
    efi_set_watchdog_timer set_watchdog_timer;
    efi_connect_controller connect_controller;
    efi_disconnect_controller disconnect_controller;
    efi_open_protocol open_protocol;
    efi_close_protocol close_protocol;
    efi_open_protocol_information open_protocol_information;
    efi_protocols_per_handle protocols_per_handle;
    efi_locate_handle_buffer locate_handle_buffer;
    efi_locate_protocol locate_protocol;
    efi_install_multiple_protocol_interfaces install_multiple_protocol_interfaces;
    efi_uninstall_multiple_protocol_interfaces uninstall_multiple_protocol_interfaces;
    efi_calculate_crc32 calculate_crc32;
    efi_copy_mem copy_mem;
    efi_set_mem set_mem;
    efi_create_event_ex create_event_ex;
} *efi_boot_services;

typedef struct efi_time {
    u16 year;
    u8 month;
    u8 day;
    u8 hour;
    u8 minute;
    u8 second;
    u8 pad1;
    u32 nanosecond;
    s16 timezone;
    u8 daylight;
    u8 pad2;
} *efi_time;

#define EFI_UNSPECIFIED_TIMEZONE    0x07FF

typedef struct efi_time_capabilities {
    u32 resolution;
    u32 accuracy;
    boolean sets_to_zero;
} *efi_time_capabilities;

typedef enum {
    efi_reset_cold,
    efi_reset_warm,
    efi_reset_shutdown,
    efi_reset_platform_specific
} efi_reset_type;

typedef struct efi_capsule_header {
    struct efi_guid capsule_guid;
    u32 header_size;
    u32 flags;
    u32 capsule_image_size;
} *efi_capsule_header;

typedef efi_status (EFIAPI *efi_get_time)(efi_time time, efi_time_capabilities capabilities);
typedef efi_status (EFIAPI *efi_set_time)(efi_time time);
typedef efi_status (EFIAPI *efi_get_wakeup_time)(boolean *enabled, boolean *pending, efi_time time);
typedef efi_status (EFIAPI *efi_set_wakeup_time)(boolean *enable, efi_time time);
typedef efi_status (EFIAPI *efi_set_virtual_address_map)(u32 memory_map_size, u32 descriptor_size,
                                                         u32 descriptor_version,
                                                         efi_memory_desc virtual_map);
typedef efi_status (EFIAPI *efi_convert_pointer)(u32 debug_disposition, void **address);
typedef efi_status (EFIAPI *efi_get_variable)(wchar_t *variable_name, efi_guid vendor_guid,
                                              u32 *attributes, u32 *data_size, void *data);
typedef efi_status (EFIAPI *efi_get_next_variable_name)(u32 *variable_name_size,
                                                        wchar_t *variable_name,
                                                        efi_guid vendor_guid);
typedef efi_status (EFIAPI *efi_set_variable)(wchar_t *variable_name, efi_guid vendor_guid,
                                              u32 attributes, u32 data_size, void *data);
typedef efi_status (EFIAPI *efi_get_next_high_mono_count)(u32 *high_count);
typedef void (EFIAPI *efi_reset_system)(efi_reset_type reset_type, efi_status reset_status,
                                        u32 data_size, void *reset_data);
typedef efi_status (EFIAPI *efi_update_capsule)(efi_capsule_header *capsule_header_array,
                                                u32 capsule_count, u64 scatter_gather_list);
typedef efi_status (EFIAPI *efi_query_capsule_caps)(efi_capsule_header *capsule_header_array,
                                                    u32 capsule_count, u64 *maximum_capsule_size,
                                                    efi_reset_type *reset_type);
typedef efi_status (EFIAPI *efi_query_variable_info)(u32 attributes,
                                                     u64 *maximum_variable_storage_size,
                                                     u64 *remaining_variable_storage_size,
                                                     u64 *maximum_variable_size);

typedef struct efi_runtime_services {
    struct efi_table_header hdr;
    efi_get_time get_time;
    efi_set_time set_time;
    efi_get_wakeup_time get_wakeup_time;
    efi_set_wakeup_time set_wakeup_time;
    efi_set_virtual_address_map set_virtual_address_map;
    efi_convert_pointer convert_pointer;
    efi_get_variable get_variable;
    efi_get_next_variable_name get_next_variable_name;
    efi_set_variable set_variable;
    efi_get_next_high_mono_count get_next_high_mono_count;
    efi_reset_system reset_system;
    efi_update_capsule update_capsule;
    efi_query_capsule_caps query_capsule_capabilities;
    efi_query_variable_info query_variable_info;
} *efi_runtime_services;

typedef struct efi_configuration_table {
    struct efi_guid guid;
    void *table;
} *efi_configuration_table;

typedef struct efi_system_table {
    struct efi_table_header hdr;
    wchar_t *firmware_vendor;
    u32 firmware_revision;
    void *console_in_handle;
    simple_input_interface con_in;
    void *console_out_handle;
    simple_text_output_interface con_out;
    void *standard_error_handle;
    simple_text_output_interface std_err;
    efi_runtime_services runtime_services;
    efi_boot_services boot_services;
    int number_of_table_entries;
    efi_configuration_table configuration_table;
} *efi_system_table;

/* End of UEFI standard definitions */

typedef struct uefi_arch_options {
    boolean load_to_physical;
} *uefi_arch_options;

typedef struct uefi_mem_map {
    void *map;
    u64 map_size;
    u64 desc_size;
    u32 desc_version;
} *uefi_mem_map;

typedef struct uefi_boot_params {
    u64 acpi_rsdp;
    efi_runtime_services efi_rt_svc;
    struct uefi_mem_map mem_map;
} *uefi_boot_params;

void uefi_exit_bs(uefi_mem_map map);

extern struct efi_guid uefi_smbios_table;
extern struct efi_guid uefi_acpi20_table;

/* Arch-specific functions */

/* Aligned heap allocates at page-aligned addresses. */
void uefi_arch_setup(heap general, heap aligned, uefi_arch_options options);

void uefi_start_kernel(void *image_handle, efi_system_table system_table, buffer kern_elf,
                       void *kern_entry);
