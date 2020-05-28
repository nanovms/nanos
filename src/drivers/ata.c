#include <kernel.h>
#include <x86_64/io.h>
#include "ata.h"

/*
 * See
 * - https://wiki.osdev.org/ATA_PIO_Mode
 * - https://wiki.osdev.org/PCI_IDE_Controller
 *
 * Also partially borrowed from FreeBSD sys/dev/ata/
 */

#ifdef ATA_DEBUG
# define ata_debug rprintf
#else
# define ata_debug(...) do { } while(0)
#endif // ATA_DEBUG

#define ATA_SECTOR_SIZE 512

/* register defines (from sys/dev/ahci/ahci.h) */
#define ATA_DATA                        0       /* (RW) data */
#define ATA_FEATURE                     1       /* (W) feature */
#define ATA_COUNT                       2       /* (W) sector count */
#define ATA_SECTOR                      3       /* (RW) sector # */
#define ATA_CYL_LSB                     4       /* (RW) cylinder# LSB */
#define ATA_CYL_MSB                     5       /* (RW) cylinder# MSB */
#define ATA_DRIVE                       6       /* (W) Sector/Drive/Head */
#define         ATA_D_LBA               0x40    /* use LBA addressing */
#define         ATA_D_IBM               0xa0    /* 512 byte sectors, ECC */
#define ATA_COMMAND                     7       /* (W) command */
#define ATA_ERROR                       8       /* (R) error */
#define ATA_IREASON                     9       /* (R) interrupt reason */
#define ATA_STATUS                      10      /* (R) status */
#define ATA_ALTSTAT                     11      /* (R) alternate status */
#define         ATA_S_ERROR             0x01    /* error */
#define         ATA_S_INDEX             0x02    /* index */
#define         ATA_S_CORR              0x04    /* data corrected */
#define         ATA_S_DRQ               0x08    /* data request */
#define         ATA_S_DSC               0x10    /* drive seek completed */
#define         ATA_S_SERVICE           0x10    /* drive needs service */
#define         ATA_S_DWF               0x20    /* drive write fault */
#define         ATA_S_DMA               0x20    /* DMA ready */
#define         ATA_S_READY             0x40    /* drive ready */
#define         ATA_S_BUSY              0x80    /* busy */
#define ATA_CONTROL                     12      /* (W) control */
#define         ATA_A_IDS               0x02    /* disable interrupts */
#define         ATA_A_RESET             0x04    /* RESET controller */
#define         ATA_A_4BIT              0x08    /* 4 head bits */
#define         ATA_A_HOB               0x80    /* High Order Byte enable */
#define ATA_MAX_RES                     13

#define ATA_PRIMARY                     0x1f0
#define ATA_SECONDARY                   0x170
#define ATA_CTLOFFSET                   0x206   /* control register offset */
#define ATA_DEV(unit)                   ((unit > 0) ? 0x10 : 0)

/* IDENTIFY data offsets */
#define ATA_IDENT_DEVICETYPE   0
#define ATA_IDENT_CYLINDERS    2
#define ATA_IDENT_HEADS        6
#define ATA_IDENT_SECTORS      12
#define ATA_IDENT_SERIAL       20
#define ATA_IDENT_MODEL        54
#define ATA_IDENT_CAPABILITIES 98
#define ATA_IDENT_FIELDVALID   106
#define ATA_IDENT_MAX_LBA      120
#define ATA_IDENT_COMMAND_SETS 164
#define ATA_IDENT_MAX_LBA_EXT  200

#define ATA_CS_LBA48 0x4000000

struct ata {
    u32 reg_port[ATA_MAX_RES];  // ATA register port
    int unit;                   // 0 - master

    heap general;

    char model[41];
    u16 signature;
    u16 capabilities;
    u32 command_sets;
    u64 capacity;
};

static inline u8 ata_in8(struct ata *dev, int reg)
{
    u8 val = in8(dev->reg_port[reg]);
    //ata_debug("%s: reg %d: port 0x%x -> 0x%x\n", __func__, reg, dev->reg_port[reg], val);
    return val;
}

static inline void ata_ins32(struct ata *dev, int reg, void *addr, u32 count)
{
    //ata_debug("%s: reg %d: port 0x%x -> %p/%d\n", __func__, reg, dev->reg_port[reg], addr, count);
    ins32(dev->reg_port[reg], addr, count);
}

static void ata_out8(struct ata *dev, int reg, u8 val)
{
    //ata_debug("%s: reg %d: port 0x%x <- 0x%x\n", __func__, reg, dev->reg_port[reg], val);
    out8(dev->reg_port[reg], val);
}

static void ata_outs32(struct ata *dev, int reg, const void *addr, u32 count)
{
    //ata_debug("%s: reg %d: port 0x%x <- %p/%d\n", __func__, reg, dev->reg_port[reg], addr, count);
    outs32(dev->reg_port[reg], addr, count);
}

// from FreeBSD sys/dev/ata/ata-lowlevel.c
static int ata_wait(struct ata *dev, u8 mask)
{
    u8 status;
    int timeout = 0;

    kernel_delay(microseconds(1));

    /* wait at max 1 second for device to get !BUSY */
    while (timeout < 1000000) {
        status = ata_in8(dev, ATA_ALTSTAT);

        /* if drive fails status, reselect the drive and try again */
        if (status == 0xff) {
            u8 sel = ATA_D_IBM | ATA_D_LBA | ATA_DEV(dev->unit);
            ata_out8(dev, ATA_DRIVE, sel);
            if (ata_in8(dev, ATA_DRIVE) != sel) {
                /* drive missing */
                return -1;
            }

            timeout += 1000;
            kernel_delay(microseconds(1000));
            continue;
        }

        /* are we done ? */
        if (!(status & ATA_S_BUSY))
            break;

        if (timeout > 1000) {
            timeout += 1000;
            kernel_delay(microseconds(1000));
        } else {
            timeout += 10;
            kernel_delay(microseconds(10));
        }
    }
    if (timeout >= 1000000)
        return -2;
    if (!mask)
        return (status & ATA_S_ERROR);

    /* wait 50 msec for bits wanted */
    timeout = 5000;
    do {
        if ((status & mask) == mask)
            return (status & ATA_S_ERROR);
        kernel_delay(microseconds(10));
        status = ata_in8(dev, ATA_ALTSTAT);
    } while (timeout--);
    return -3;
}

static int ata_io_loop(struct ata *dev, int cmd, void *buf, u64 nsectors)
{
    assert(nsectors > 0);
    int mask = ATA_S_DRQ;
    if (cmd == ATA_WRITE48)
        mask |= ATA_S_READY;

    for (;;) {
        if (ata_wait(dev, mask) < 0) {
            ata_debug("%s: timeout (nsectors %ld)\n", __func__, nsectors);
            return -1;
        }

        switch (cmd) {
        case ATA_READ:
        case ATA_READ48:
            ata_ins32(dev, ATA_DATA, buf, ATA_SECTOR_SIZE / sizeof(u32));
            break;
        case ATA_WRITE:
        case ATA_WRITE48:
            ata_outs32(dev, ATA_DATA, buf, ATA_SECTOR_SIZE / sizeof(u32));
            break;
        }

        buf += ATA_SECTOR_SIZE;
        if (--nsectors == 0)
            return 0;
    }
}

void ata_io_cmd(void * _dev, int cmd, void * buf, range blocks, status_handler s)
{
    struct ata *dev = (struct ata *)_dev;
    const char *err;

    u64 lba = blocks.start;
    u64 nsectors = range_span(blocks);
    if (nsectors == 0) {
        const char *err = "ata_io_cmd: zero blocks I/O";
        apply(s, timm("result", "%s", err));
        return;
    }
    if (dev->command_sets & ATA_CS_LBA48) {
        assert(nsectors <= 65536);
        if (nsectors == 65536)
            nsectors = 0;
    } else {
        assert(nsectors <= 255);
        if (cmd == ATA_READ48)
            cmd = ATA_READ;
        else if (cmd == ATA_WRITE48)
            cmd = ATA_WRITE;
    }
    ata_debug("%s: cmd 0x%x, blocks %R, sectors %d\n",
        __func__, cmd, blocks, nsectors);

    // wait for device to become ready
    if (ata_wait(dev, 0) < 0)
        goto timeout;

    // set LBA
    if (dev->command_sets & ATA_CS_LBA48) {
        ata_out8(dev, ATA_COUNT, nsectors >> 8);
        ata_out8(dev, ATA_COUNT, nsectors);
        ata_out8(dev, ATA_CYL_MSB, lba >> 40);
        ata_out8(dev, ATA_CYL_LSB, lba >> 32);
        ata_out8(dev, ATA_SECTOR, lba >> 24);
        ata_out8(dev, ATA_CYL_MSB, lba >> 16);
        ata_out8(dev, ATA_CYL_LSB, lba >> 8);
        ata_out8(dev, ATA_SECTOR, lba);
        ata_out8(dev, ATA_DRIVE, ATA_D_LBA | ATA_DEV(dev->unit));
    } else {
        ata_out8(dev, ATA_COUNT, nsectors);
        ata_out8(dev, ATA_CYL_MSB, lba >> 16);
        ata_out8(dev, ATA_CYL_LSB, lba >> 8);
        ata_out8(dev, ATA_SECTOR, lba);
        ata_out8(dev, ATA_DRIVE, ATA_D_IBM | ATA_D_LBA | ATA_DEV(dev->unit) | ((lba >> 24) & 0x0f));
    }

    // send I/O command
    ata_out8(dev, ATA_COMMAND, cmd);

    // read/write data
    if (ata_io_loop(dev, cmd, buf, range_span(blocks)) < 0)
        goto timeout;

    // ok
    apply(s, 0);
    return;

timeout:
    err = "ata_io_cmd: device timeout";
    msg_err("%s\n", err);
    apply(s, timm("result", "%s", err));
}

closure_function(2, 3, void, ata_io_cmd_cfn,
                 void *, _dev, int, cmd,
                 void *, buf, range, blocks, status_handler, s)
{
    ata_io_cmd(bound(_dev), bound(cmd), buf, blocks, s);
}

block_io create_ata_io(heap h, void * dev, int cmd)
{
    return closure(h, ata_io_cmd_cfn, dev, cmd);
}

struct ata *ata_alloc(heap general)
{
    struct ata *dev = allocate(general, sizeof(*dev));
    dev->general = general;
    dev->unit = 0; // always master for now
    return dev;
}

void ata_dealloc(struct ata *dev)
{
    deallocate(dev->general, dev, sizeof(*dev));
}

boolean ata_probe(struct ata *dev)
{
    /* configure ATA registers */
    for (int i = ATA_DATA; i <= ATA_COMMAND; i++)
        dev->reg_port[i] = ATA_PRIMARY + i;
    dev->reg_port[ATA_CONTROL] = ATA_PRIMARY + ATA_CTLOFFSET;
    dev->reg_port[ATA_ERROR] = dev->reg_port[ATA_FEATURE];
    dev->reg_port[ATA_IREASON] = dev->reg_port[ATA_COUNT];
    dev->reg_port[ATA_STATUS] = dev->reg_port[ATA_COMMAND];
    dev->reg_port[ATA_ALTSTAT] = dev->reg_port[ATA_CONTROL];

    // reset controller
    ata_out8(dev, ATA_CONTROL, ATA_A_RESET);
    kernel_delay(milliseconds(2));
    ata_out8(dev, ATA_CONTROL, 0);
    kernel_delay(nanoseconds(400));

    // select primary master
    u8 sel = ATA_D_IBM | ATA_D_LBA | ATA_DEV(dev->unit);
    ata_out8(dev, ATA_DRIVE, sel);
    if (ata_in8(dev, ATA_DRIVE) != sel) {
        // drive does not exist
        ata_debug("%s: drive does not exist\n", __func__);
        return false;
    }

    // disable interrupts
    ata_out8(dev, ATA_CONTROL, ATA_A_IDS);

    // identify
    ata_out8(dev, ATA_COMMAND, ATA_ATA_IDENTIFY);
    if (ata_wait(dev, ATA_S_READY | ATA_S_DRQ) < 0) {
        ata_debug("%s: IDENTIFY timeout\n", __func__);
        return false;
    }
    char buf[512];
    ata_ins32(dev, ATA_DATA, buf, sizeof(buf) / sizeof(u32));

    runtime_memcpy(&dev->signature, buf + ATA_IDENT_DEVICETYPE, sizeof(dev->signature));
    runtime_memcpy(&dev->capabilities, buf + ATA_IDENT_CAPABILITIES, sizeof(dev->capabilities));
    runtime_memcpy(&dev->command_sets, buf + ATA_IDENT_COMMAND_SETS, sizeof(dev->command_sets));
    u64 sectors;
    if (dev->command_sets & ATA_CS_LBA48) {
        runtime_memcpy(&sectors, buf + ATA_IDENT_MAX_LBA_EXT, sizeof(sectors));
    } else {
        u32 lba28_sectors;
        runtime_memcpy(&lba28_sectors, buf + ATA_IDENT_MAX_LBA, sizeof(lba28_sectors));
        sectors = lba28_sectors;
    }
    dev->capacity = sectors * ATA_SECTOR_SIZE;
    for (int i = 0; i < sizeof(dev->model) - 1; i += 2) {
        dev->model[i] = buf[ATA_IDENT_MODEL + i + 1];
        dev->model[i + 1] = buf[ATA_IDENT_MODEL + i];
    }
    dev->model[sizeof(dev->model) - 1] = ' ';
    for (int i = sizeof(dev->model) - 1; i >= 0; i--) {
        if (dev->model[i] != ' ')
            break;
        dev->model[i] = '\0';
    }
    ata_debug("%s: model %s, signature 0x%x, capabilities 0x%x, command sets 0x%x, %ld sectors\n",
        __func__, dev->model, dev->signature, dev->capabilities, dev->command_sets, sectors);

    return true;
}

u64 ata_get_capacity(struct ata *dev)
{
    return dev->capacity;
}
