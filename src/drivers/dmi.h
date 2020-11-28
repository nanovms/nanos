enum dmi_field {
    DMI_CHASSIS_ASSET_TAG,
};

const char *dmi_get_string(enum dmi_field field);
