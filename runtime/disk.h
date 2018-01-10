#define CMD_READ 0x20 // was 0x20 read ext?
#define BSY_FLAG 0x80

#define sector_log 9

extern void *disktarget;
extern void diskcopy();

static inline void read_sectors(void *dest, u32 sector, u32 count)
{
    u16 max, base = 0x1f0;
    u8  drive = 0x40;
    u32 total = pad(count, (1<<sector_log));

    disktarget = dest;

    while (total) {
        u32 secs = total>>sector_log;
        u16 xfer = (secs > 256)?256:secs;

        out8(base + 2, xfer);
        out8(base + 3, sector);
        out8(base + 4, sector >> 8);
        out8(base + 5, sector >> 16);
        out8(base + 6, (sector >> 24) | drive);
        out8(base + 7, CMD_READ);

        for(int index = 0; index < xfer; index++) {
            // its necessary..but slow.. to do this each time to get repeatable results
            // shouldn't be
            while(in8(base + 7) & BSY_FLAG);
            diskcopy();
        }

        while(in8(base + 7) & BSY_FLAG); // umm?
        total -= xfer<<sector_log;
    }
}
