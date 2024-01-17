/* SMBIOS entry point structure size */
#define SMBIOS_EP_SIZE  32

enum dmi_field {
    DMI_CHASSIS_ASSET_TAG,
};

extern u64 smbios_entry_point;

sstring dmi_get_string(enum dmi_field field);
