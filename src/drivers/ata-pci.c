#include <runtime/runtime.h>
#include <x86_64/pci.h>
#include <x86_64/io.h>
#include <x86_64/x86_64.h>
#include "ata-pci.h"

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

/* device identifiers (from sys/dev/ata/ata-pci.h) */
#define ATA_ACARD_ID            0x1191
#define ATA_ACER_LABS_ID        0x10b9
#define ATA_AMD_ID              0x1022
#define ATA_ADAPTEC_ID          0x9005
#define ATA_ATI_ID              0x1002
#define ATA_CENATEK_ID          0x16ca
#define ATA_CYRIX_ID            0x1078
#define ATA_CYPRESS_ID          0x1080
#define ATA_HIGHPOINT_ID        0x1103
#define ATA_INTEL_ID            0x8086
#define ATA_ITE_ID              0x1283
#define ATA_JMICRON_ID          0x197b
#define ATA_MARVELL_ID          0x11ab
#define ATA_MARVELL2_ID         0x1b4b
#define ATA_MICRON_ID           0x1042
#define ATA_NATIONAL_ID         0x100b
#define ATA_NETCELL_ID          0x169c
#define ATA_NVIDIA_ID           0x10de
#define ATA_PROMISE_ID          0x105a
#define ATA_SERVERWORKS_ID      0x1166
#define ATA_SILICON_IMAGE_ID    0x1095
#define ATA_SIS_ID              0x1039
#define ATA_VIA_ID              0x1106

#ifdef ATA_DEBUG
static const char *ata_pcivendor2str(pci_dev d)
{
    switch (pci_get_vendor(d)) {
    case ATA_ACARD_ID:          return "Acard";
    case ATA_ACER_LABS_ID:      return "AcerLabs";
    case ATA_AMD_ID:            return "AMD";
    case ATA_ADAPTEC_ID:        return "Adaptec";
    case ATA_ATI_ID:            return "ATI";
    case ATA_CYRIX_ID:          return "Cyrix";
    case ATA_CYPRESS_ID:        return "Cypress";
    case ATA_HIGHPOINT_ID:      return "HighPoint";
    case ATA_INTEL_ID:          return "Intel";
    case ATA_ITE_ID:            return "ITE";
    case ATA_JMICRON_ID:        return "JMicron";
    case ATA_MARVELL_ID:        return "Marvell";
    case ATA_MARVELL2_ID:       return "Marvell";
    case ATA_NATIONAL_ID:       return "National";
    case ATA_NETCELL_ID:        return "Netcell";
    case ATA_NVIDIA_ID:         return "nVidia";
    case ATA_PROMISE_ID:        return "Promise";
    case ATA_SERVERWORKS_ID:    return "ServerWorks";
    case ATA_SILICON_IMAGE_ID:  return "SiI";
    case ATA_SIS_ID:            return "SiS";
    case ATA_VIA_ID:            return "VIA";
    case ATA_CENATEK_ID:        return "Cenatek";
    case ATA_MICRON_ID:         return "Micron";
    default:                    return "Generic";
    }
}
#endif // ATA_DEBUG

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

/* ATA commands (from sys/sys/ata.h) */
#define ATA_NOP                         0x00    /* NOP */
#define ATA_DATA_SET_MANAGEMENT         0x06
#define ATA_DEVICE_RESET                0x08    /* reset device */
#define ATA_READ                        0x20    /* read */
#define ATA_READ48                      0x24    /* read 48bit LBA */
#define ATA_READ_DMA48                  0x25    /* read DMA 48bit LBA */
#define ATA_READ_DMA_QUEUED48           0x26    /* read DMA QUEUED 48bit LBA */
#define ATA_READ_NATIVE_MAX_ADDRESS48   0x27    /* read native max addr 48bit */
#define ATA_READ_MUL48                  0x29    /* read multi 48bit LBA */
#define ATA_READ_STREAM_DMA48           0x2a    /* read DMA stream 48bit LBA */
#define ATA_READ_LOG_EXT                0x2f    /* read log ext - PIO Data-In */
#define ATA_READ_STREAM48               0x2b    /* read stream 48bit LBA */
#define ATA_WRITE                       0x30    /* write */
#define ATA_WRITE48                     0x34    /* write 48bit LBA */
#define ATA_WRITE_DMA48                 0x35    /* write DMA 48bit LBA */
#define ATA_WRITE_DMA_QUEUED48          0x36    /* write DMA QUEUED 48bit LBA*/
#define ATA_SET_MAX_ADDRESS48           0x37    /* set max address 48bit */
#define ATA_WRITE_MUL48                 0x39    /* write multi 48bit LBA */
#define ATA_WRITE_STREAM_DMA48          0x3a
#define ATA_WRITE_STREAM48              0x3b
#define ATA_WRITE_DMA_FUA48             0x3d
#define ATA_WRITE_DMA_QUEUED_FUA48      0x3e
#define ATA_WRITE_LOG_EXT               0x3f
#define ATA_READ_VERIFY                 0x40
#define ATA_READ_VERIFY48               0x42
#define ATA_WRITE_UNCORRECTABLE48       0x45    /* write uncorrectable 48bit LBA */
#define ATA_READ_LOG_DMA_EXT            0x47    /* read log DMA ext - PIO Data-In */
#define ATA_ZAC_MANAGEMENT_IN           0x4a    /* ZAC management in */
#define ATA_WRITE_LOG_DMA_EXT           0x57    /* WRITE LOG DMA EXT */
#define ATA_TRUSTED_NON_DATA            0x5b    /* TRUSTED NON-DATA */
#define ATA_TRUSTED_RECEIVE             0x5c    /* TRUSTED RECEIVE */
#define ATA_TRUSTED_RECEIVE_DMA         0x5d    /* TRUSTED RECEIVE DMA */
#define ATA_TRUSTED_SEND                0x5e    /* TRUSTED SEND */
#define ATA_TRUSTED_SEND_DMA            0x5f    /* TRUSTED SEND DMA */
#define ATA_READ_FPDMA_QUEUED           0x60    /* read DMA NCQ */
#define ATA_WRITE_FPDMA_QUEUED          0x61    /* write DMA NCQ */
#define ATA_NCQ_NON_DATA                0x63    /* NCQ non-data command */
#define ATA_SEND_FPDMA_QUEUED           0x64    /* send DMA NCQ */
#define ATA_RECV_FPDMA_QUEUED           0x65    /* receive DMA NCQ */
#define ATA_SEP_ATTN                    0x67    /* SEP request */
#define ATA_SEEK                        0x70    /* seek */
#define ATA_ZAC_MANAGEMENT_OUT          0x9f    /* ZAC management out */
#define ATA_DOWNLOAD_MICROCODE          0x92    /* DOWNLOAD MICROCODE */
#define ATA_DOWNLOAD_MICROCODE_DMA      0x93    /* DOWNLOAD MICROCODE DMA */
#define ATA_PACKET_CMD                  0xa0    /* packet command */
#define ATA_ATAPI_IDENTIFY              0xa1    /* get ATAPI params*/
#define ATA_SERVICE                     0xa2    /* service command */
#define ATA_SMART_CMD                   0xb0    /* SMART command */
#define ATA_CFA_ERASE                   0xc0    /* CFA erase */
#define ATA_READ_MUL                    0xc4    /* read multi */
#define ATA_WRITE_MUL                   0xc5    /* write multi */
#define ATA_SET_MULTI                   0xc6    /* set multi size */
#define ATA_READ_DMA_QUEUED             0xc7    /* read DMA QUEUED */
#define ATA_READ_DMA                    0xc8    /* read DMA */
#define ATA_WRITE_DMA                   0xca    /* write DMA */
#define ATA_WRITE_DMA_QUEUED            0xcc    /* write DMA QUEUED */
#define ATA_WRITE_MUL_FUA48             0xce
#define ATA_STANDBY_IMMEDIATE           0xe0    /* standby immediate */
#define ATA_IDLE_IMMEDIATE              0xe1    /* idle immediate */
#define ATA_STANDBY_CMD                 0xe2    /* standby */
#define ATA_IDLE_CMD                    0xe3    /* idle */
#define ATA_READ_BUFFER                 0xe4    /* read buffer */
#define ATA_READ_PM                     0xe4    /* read portmultiplier */
#define ATA_CHECK_POWER_MODE            0xe5    /* device power mode */
#define ATA_SLEEP                       0xe6    /* sleep */
#define ATA_FLUSHCACHE                  0xe7    /* flush cache to disk */
#define ATA_WRITE_BUFFER                0xe8    /* write buffer */
#define ATA_WRITE_PM                    0xe8    /* write portmultiplier */
#define ATA_READ_BUFFER_DMA             0xe9    /* read buffer DMA */
#define ATA_FLUSHCACHE48                0xea    /* flush cache to disk */
#define ATA_WRITE_BUFFER_DMA            0xeb    /* write buffer DMA */
#define ATA_ATA_IDENTIFY                0xec    /* get ATA params */
#define ATA_SETFEATURES                 0xef    /* features command */
#define ATA_CHECK_POWER_MODE            0xe5    /* Check Power Mode */
#define ATA_SECURITY_SET_PASSWORD       0xf1    /* set drive password */
#define ATA_SECURITY_UNLOCK             0xf2    /* unlock drive using passwd */
#define ATA_SECURITY_ERASE_PREPARE      0xf3    /* prepare to erase drive */
#define ATA_SECURITY_ERASE_UNIT         0xf4    /* erase all blocks on drive */
#define ATA_SECURITY_FREEZE_LOCK        0xf5    /* freeze security config */
#define ATA_SECURITY_DISABLE_PASSWORD   0xf6    /* disable drive password */
#define ATA_READ_NATIVE_MAX_ADDRESS     0xf8    /* read native max address */
#define ATA_SET_MAX_ADDRESS             0xf9    /* set max address */

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

struct ata {
    struct pci_dev _dev;
    pci_dev dev;

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

    kern_sleep(microseconds(1));

    /* wait at max 1 second for device to get !BUSY */
    while (timeout < 1000000) {
        status = ata_in8(dev, ATA_ALTSTAT);

        /* if drive fails status, reselect the drive and try again */
        if (status == 0xff) {
            ata_out8(dev, ATA_DRIVE, ATA_D_IBM | ATA_DEV(dev->unit));
            timeout += 1000;
            kern_sleep(microseconds(1000));
            continue;
        }

        /* are we done ? */
        if (!(status & ATA_S_BUSY))
            break;

        if (timeout > 1000) {
            timeout += 1000;
            kern_sleep(microseconds(1000));
        } else {
            timeout += 10;
            kern_sleep(microseconds(10));
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
        kern_sleep(microseconds(10));
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
        case ATA_READ48:
            ata_ins32(dev, ATA_DATA, buf, ATA_SECTOR_SIZE / sizeof(u32));
            break;
        case ATA_WRITE48:
            ata_outs32(dev, ATA_DATA, buf, ATA_SECTOR_SIZE / sizeof(u32));
            break;
        }

        buf += ATA_SECTOR_SIZE;
        if (--nsectors == 0)
            return 0;
    }
}

static void ata_io(struct ata *dev, int cmd, void *buf, range blocks, status_handler s)
{
    const char *err;
    u64 lba = blocks.start;
    u64 nsectors = range_span(blocks);
    if (nsectors == 0) {
        const char *err = "ata_io: zero blocks I/O";
        apply(s, timm("result", "%s", err));
        return;
    }
    assert(nsectors <= 65536);
    if (nsectors == 65536)
        nsectors = 0;
    ata_debug("%s: cmd 0x%x, blocks %R, sectors %d\n",
        __func__, cmd, blocks, nsectors);

    // wait for device to become ready
    if (ata_wait(dev, 0) < 0)
        goto timeout;

    // set LBA
    ata_out8(dev, ATA_COUNT, nsectors >> 8);
    ata_out8(dev, ATA_COUNT, nsectors);
    ata_out8(dev, ATA_CYL_MSB, lba >> 40);
    ata_out8(dev, ATA_CYL_LSB, lba >> 32);
    ata_out8(dev, ATA_SECTOR, lba >> 24);
    ata_out8(dev, ATA_CYL_MSB, lba >> 16);
    ata_out8(dev, ATA_CYL_LSB, lba >> 8);
    ata_out8(dev, ATA_SECTOR, lba);
    ata_out8(dev, ATA_DRIVE, ATA_D_LBA | ATA_DEV(dev->unit));

    // send I/O command
    ata_out8(dev, ATA_COMMAND, cmd);

    // read/write data
    if (ata_io_loop(dev, cmd, buf, range_span(blocks)) < 0)
        goto timeout;

    // ok
    apply(s, 0);
    return;

timeout:
    err = "ata_io: device timeout";
    msg_err("%s\n", err);
    apply(s, timm("result", "%s", err));
}

static CLOSURE_1_3(ata_read, void, struct ata *, void *, range, status_handler);
static void ata_read(struct ata *dev, void *dest, range blocks, status_handler s)
{
    ata_debug("%s: %R\n", __func__, blocks);
    ata_io(dev, ATA_READ48, dest, blocks, s);
}

static CLOSURE_1_3(ata_write, void, struct ata *, void *, range, status_handler);
static void ata_write(struct ata *dev, void *source, range blocks, status_handler s)
{
    ata_debug("%s: %R\n", __func__, blocks);
    ata_io(dev, ATA_WRITE48, source, blocks, s);
}

static void ata_attach(struct ata *dev, storage_attach a)
{
    // reset controller (master is selected)
    ata_out8(dev, ATA_CONTROL, ATA_A_RESET);
    kern_sleep(milliseconds(2));
    ata_out8(dev, ATA_CONTROL, 0);
    kern_sleep(nanoseconds(400));

    // disable interrupts
    ata_out8(dev, ATA_CONTROL, ATA_A_IDS);

    // identify
    ata_out8(dev, ATA_COMMAND, ATA_ATA_IDENTIFY);
    if (ata_in8(dev, ATA_STATUS) == 0) {
        // drive does not exist
        return;
    }
    if (ata_wait(dev, ATA_S_READY | ATA_S_DRQ) < 0) {
        rprintf("%s: IDENTIFY timeout\n", __func__);
        return;
    }
    char buf[512];
    ata_ins32(dev, ATA_DATA, buf, sizeof(buf) / sizeof(u32));

    runtime_memcpy(&dev->signature, buf + ATA_IDENT_DEVICETYPE, sizeof(dev->signature));
    runtime_memcpy(&dev->capabilities, buf + ATA_IDENT_CAPABILITIES, sizeof(dev->capabilities));
    runtime_memcpy(&dev->command_sets, buf + ATA_IDENT_COMMAND_SETS, sizeof(dev->command_sets));
    u64 sectors;
    runtime_memcpy(&sectors, buf + ATA_IDENT_MAX_LBA_EXT, sizeof(sectors));
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
    ata_debug("%s: %s ATA controller, model %s, signature 0x%x, capabilities 0x%x, command sets 0x%x, %ld sectors\n",
        __func__, ata_pcivendor2str(dev->dev),
        dev->model, dev->signature, dev->capabilities, dev->command_sets,
        sectors);

    // attach
    block_io in = closure(dev->general, ata_read, dev);
    block_io out = closure(dev->general, ata_write, dev);
    apply(a, in, out, dev->capacity);
}

static CLOSURE_2_1(ata_pci_probe, boolean, heap, storage_attach, pci_dev);
static boolean ata_pci_probe(heap general, storage_attach a, pci_dev d)
{
    if (pci_get_class(d) != PCIC_STORAGE || pci_get_subclass(d) != PCIS_STORAGE_IDE)
        return false;

    struct ata *dev = allocate(general, sizeof(struct ata));
    dev->_dev = *d;
    dev->dev = &dev->_dev;
    dev->general = general;
    dev->unit = 0; // always master for now

    /* configure ATA registers */
    for (int i = ATA_DATA; i <= ATA_COMMAND; i++)
        dev->reg_port[i] = ATA_PRIMARY + i;
    dev->reg_port[ATA_CONTROL] = ATA_PRIMARY + ATA_CTLOFFSET;
    dev->reg_port[ATA_ERROR] = dev->reg_port[ATA_FEATURE];
    dev->reg_port[ATA_IREASON] = dev->reg_port[ATA_COUNT];
    dev->reg_port[ATA_STATUS] = dev->reg_port[ATA_COMMAND];
    dev->reg_port[ATA_ALTSTAT] = dev->reg_port[ATA_CONTROL];

    ata_attach(dev, a);
    return true;
}

void ata_pci_register(kernel_heaps kh, storage_attach a)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, ata_pci_probe, h, a));
}
