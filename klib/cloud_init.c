#include <kernel.h>
#include <cloud_init.h>
#include <drivers/dmi.h>

#define AZURE_CHASSIS   "7783-7084-3265-9085-8269-3286-77"

enum cloud {
    CLOUD_ERROR,
    CLOUD_AZURE,
    CLOUD_UNKNOWN
};

static enum cloud cloud_detect(klib_get_sym get_sym)
{
    const char *(*dmi_get_string)(enum dmi_field) = get_sym("dmi_get_string");
    int (*runtime_strcmp)(const char *, const char *) = get_sym("runtime_strcmp");
    if (!dmi_get_string || !runtime_strcmp)
        return CLOUD_ERROR;
    const char *chassis_asset_tag = dmi_get_string(DMI_CHASSIS_ASSET_TAG);
    if (!chassis_asset_tag)
        return CLOUD_UNKNOWN;
    if (!runtime_strcmp(chassis_asset_tag, AZURE_CHASSIS))
        return CLOUD_AZURE;
    return CLOUD_UNKNOWN;
}

int init(void *md, klib_get_sym get_sym, klib_add_sym add_sym)
{
    void *(*get_kernel_heaps)(void) = get_sym("get_kernel_heaps");
    boolean (*first_boot)(void) = get_sym("first_boot");
    if (!get_kernel_heaps || !first_boot)
        return KLIB_INIT_FAILED;
    heap h = heap_general(get_kernel_heaps());
    if (first_boot()) {
        enum cloud c = cloud_detect(get_sym);
        switch (c) {
        case CLOUD_ERROR:
            return KLIB_INIT_FAILED;
        case CLOUD_AZURE:
            if (!azure_cloud_init(h, get_sym))
                return KLIB_INIT_FAILED;
            break;
        default:
            break;
        }
    }
    return KLIB_INIT_OK;
}
