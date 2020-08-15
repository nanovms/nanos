struct partition_entry {
    u8 active;
    u8 chs_start[3];
    u8 type;
    u8 chs_end[3];
    u32 lba_start;
    u32 nsectors;
} __attribute__((packed));

enum partition {
    PARTITION_BOOTFS,
    PARTITION_ROOTFS,
};

#define SECTOR_OFFSET 9ULL
#define SECTOR_SIZE (1ULL << SECTOR_OFFSET)
#define BOOTFS_SIZE (8 * MB)
#define SEC_PER_TRACK 63
#define HEADS 255
#define MAX_CYL 1023

#define partition_get(mbr, index)    ({ \
    u16 *mbr_sig = (u16 *)((u64)(mbr) + SECTOR_SIZE - sizeof(*mbr_sig));  \
    struct partition_entry *e;  \
    if (*mbr_sig == 0xaa55) \
        e = (struct partition_entry *)((u64_from_pointer(mbr_sig)) -    \
                (4 - (index)) * sizeof(struct partition_entry));    \
    else    \
        e = 0;  \
    e;  \
})

static inline void mbr_chs(u8 *chs, u64 offset)
{
    u64 cyl = ((offset / SECTOR_SIZE) / SEC_PER_TRACK) / HEADS;
    u64 head = ((offset / SECTOR_SIZE) / SEC_PER_TRACK) % HEADS;
    u64 sec = ((offset / SECTOR_SIZE) % SEC_PER_TRACK) + 1;
    if (cyl > MAX_CYL) {
        cyl = MAX_CYL;
    head = 254;
    sec = 63;
    }

    chs[0] = head;
    chs[1] = (cyl >> 8) | sec;
    chs[2] = cyl & 0xff;
}

static inline void partition_write(struct partition_entry *e, boolean active,
                                   u8 type, u64 offset, u64 size)
{
    e->active = active ? 0x80 : 0x00;
    e->type = type;
    mbr_chs(e->chs_start, offset);
    mbr_chs(e->chs_end, offset + size - SECTOR_SIZE);
    e->lba_start = offset / SECTOR_SIZE;
    e->nsectors = size / SECTOR_SIZE;
}
