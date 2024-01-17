#include <kernel.h>
#include "dmi.h"

#define SMBIOS_SCAN_START   0xF0000
#define SMBIOS_SCAN_SIZE    0x10000

#define DMI_TYPE_BIOS_INFO      0
#define DMI_TYPE_SYSTEM_INFO    1
#define DMI_TYPE_BASEBOARD_INFO 2
#define DMI_TYPE_CHASSIS_INFO   3

//#define DMI_DEBUG
#ifdef DMI_DEBUG
#define dmi_debug(x, ...) do {rprintf("DMI: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define dmi_debug(x, ...)
#endif

struct dmi_header {
    u8 type;
    u8 length;
    u16 handle;
} __attribute__((packed));

BSS_RO_AFTER_INIT u64 smbios_entry_point;

static u32 dmi_len;
static u16 dmi_num;
static void *dmi_base;

static void dmi_parse(heap h, u8 *p)
{
    if (!runtime_memcmp(p, "_DMI_", 5)) {
        u8 buf[16];
        runtime_memcpy(buf, p, sizeof(buf));    /* so that unaligned access is possible */
        dmi_len = le16toh(*(u16 *)(buf + 6));
        u64 phys_base = le32toh(*(u32 *)(buf + 8));
        dmi_num = le16toh(*(u16 *)(buf + 12));
        dmi_debug("mapping base %p, len %d, num %d", phys_base, dmi_len, dmi_num);
        dmi_base = allocate(h, dmi_len);
        if (dmi_base == INVALID_ADDRESS) {
            dmi_base = 0;
            return;
        }
        u64 map_end = pad(phys_base + dmi_len, PAGESIZE);
        map(u64_from_pointer(dmi_base), phys_base & ~PAGEMASK, map_end - (phys_base & ~PAGEMASK),
            pageflags_writable(pageflags_device()));
        dmi_base += phys_base & PAGEMASK;
    }
}

static void dmi_map(void)
{
    heap h = (heap)heap_virtual_page(get_kernel_heaps());
    if (smbios_entry_point) {
        u64 ep_end = smbios_entry_point + SMBIOS_EP_SIZE;
        u64 ep_map_size = ((ep_end & ~PAGEMASK) == (smbios_entry_point & ~PAGEMASK)) ?
                PAGESIZE : (2 * PAGESIZE);
        u8 *smbios = allocate(h, ep_map_size);
        if (smbios == INVALID_ADDRESS)
            return;
        map(u64_from_pointer(smbios), smbios_entry_point & ~PAGEMASK, ep_map_size,
            pageflags_writable(pageflags_device()));
        /* DMI header is 16 bytes after SMBIOS header. */
        dmi_parse(h, smbios + (smbios_entry_point & PAGEMASK) + 16);
        unmap(u64_from_pointer(smbios), ep_map_size);
        deallocate(h, smbios, ep_map_size);
        if (dmi_base)
            return;
    }
    u8 *smbios = allocate(h, SMBIOS_SCAN_SIZE);
    if (smbios == INVALID_ADDRESS)
        return;
    map(u64_from_pointer(smbios), SMBIOS_SCAN_START, SMBIOS_SCAN_SIZE,
        pageflags_writable(pageflags_device()));
    for (u8 *p = smbios; p < smbios + SMBIOS_SCAN_SIZE; p += 16) {
        dmi_parse(h, p);
        if (dmi_base) {
            unmap(u64_from_pointer(smbios), SMBIOS_SCAN_SIZE);
            deallocate(h, smbios, SMBIOS_SCAN_SIZE);
            return;
        }
    }
}

static sstring dmi_string(const struct dmi_header *dm, u8 s)
{
    const char *str = ((char *)dm) + dm->length;
    if (!s)
        return sstring_empty();
    while (--s && *str) {
        do {
            str++;
        } while (*str);
        str++;
    }
    sstring sstr = sstring_from_cstring(str, (char *)dmi_base + dmi_len - str);
    dmi_debug("returning string '%s'", sstr);
    return sstr;
}

sstring dmi_get_string(enum dmi_field field)
{
    dmi_debug("get string %d", field);
    int type, offset;
    switch (field) {
    case DMI_CHASSIS_ASSET_TAG:
        type = DMI_TYPE_CHASSIS_INFO;
        offset = 8;
        break;
    default:
        return sstring_null();
    }
    if (!dmi_base)
        dmi_map();
    if (!dmi_base)
        return sstring_null();
    int i = 0;
    for (u8 *data = dmi_base;
            (i < dmi_num) && (data + sizeof(struct dmi_header) <= (u8 *)dmi_base + dmi_len); i++) {
        const struct dmi_header *dm = (const struct dmi_header *)data;
        dmi_debug("table type %d, length %d, handle %d", dm->type, dm->length, dm->handle);
        data += dm->length;

        /* Find the end of the strings section. */
        while ((data < (u8 *)dmi_base + dmi_len - 1) && (data[0] || data[1]))
            data++;
        data += 2;

        if ((dm->type == type) && (dm->length > offset) && (data <= (u8 *)dmi_base + dmi_len)) {
            return dmi_string(dm, *(((u8 *)dm) + offset));
        }
    }
    return sstring_null();
}
