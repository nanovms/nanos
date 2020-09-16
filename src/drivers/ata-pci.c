#include <kernel.h>
#include <page.h>
#include <storage.h>
#include <x86_64/apic.h>
#include <x86_64/pci.h>
#include "ata-pci.h"
#include "ata.h"

#ifdef ATA_DEBUG
# define ata_debug rprintf
#else
# define ata_debug(...) do { } while(0)
#endif // ATA_DEBUG

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

#define PCI_PRODUCT_PIIX4       0x7111

#define ATA_PRIMARY     0
#define ATA_SECONDARY   1

#define PRDT_ENTRIES    256

/* Allocate twice the nominal PRDT size so that we can align the PRDT to ensure
 * it doesn't cross a 64K boundary. */
#define PRDT_SIZE   (2 * PRDT_ENTRIES * sizeof(struct prd))

#define PRD_LAST_ENTRY  (1 << 15)

#define BMR_CHAN_OFFSET 0x08

#define ATA_BMR_CMD(chan)       ((chan) * BMR_CHAN_OFFSET + 0x0)
#define ATA_BMR_STATUS(chan)    ((chan) * BMR_CHAN_OFFSET + 0x2)
#define ATA_BMR_PRDT(chan)      ((chan) * BMR_CHAN_OFFSET + 0x4)

#define ATA_BMR_CMD_START   (1 << 0)
#define ATA_BMR_CMD_READ    (1 << 3)

#define ATA_BMR_STATUS_ERR  (1 << 1)
#define ATA_BMR_STATUS_IRQ  (1 << 2)

#define ATA_IRQ(chan)  (14 + (chan))

struct prd {
    u32 buf_addr;   /* physical address */
    u16 byte_count;
    u16 ctrl;
} __attribute__((packed));

declare_closure_struct(2, 3, void, ata_pci_io,
                       struct ata_pci *, apci, boolean, write,
                       void *, buf, range, blocks, status_handler, s);

declare_closure_struct(1, 0, void, ata_pci_irq,
                       struct ata_pci *, apci);

declare_closure_struct(1, 0, void, ata_pci_service,
                       struct ata_pci *, apci);

typedef struct ata_pci {
    heap h;
    struct ata *ata;
    struct prd *prdt;   /* physical region descriptor table */
    u64 prdt_phys;
    struct pci_bar bmr; /* bus master register */
    closure_struct(ata_pci_io, read);
    closure_struct(ata_pci_io, write);
    block_io pio_read, pio_write;
    closure_struct(ata_pci_irq, irq_handler);
    closure_struct(ata_pci_service, service);
    struct list reqs;
    struct spinlock lock;
} *ata_pci;

typedef struct ata_pci_req {
    struct list l;
    boolean write;
    void *buf;
    range remain;
    status_handler sh;
    status s;
} *ata_pci_req;

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

static ata_pci ata_pci_alloc(heap general, heap contiguous, pci_dev d)
{
    ata_pci apci = allocate(general, sizeof(*apci));
    assert(apci != INVALID_ADDRESS);
    apci->ata = ata_alloc(general);
    apci->prdt = allocate(contiguous, PRDT_SIZE);
    assert(apci->prdt != INVALID_ADDRESS);
    ata_debug("%s: %s ATA controller\n", __func__, ata_pcivendor2str(d));
    return apci;
}

void ata_pci_dealloc(heap general, heap contiguous, ata_pci apci)
{
    ata_debug("%s\n", __func__);
    deallocate(contiguous, apci->prdt, PRDT_SIZE);
    ata_dealloc(apci->ata);
    deallocate(general, apci, sizeof(*apci));
}

static boolean ata_pci_service_req(ata_pci apci, ata_pci_req req)
{
    ata_debug("%s: %R %v\n", __func__, req->remain, req->s);
    if (!is_ok(req->s))
        goto done;
    u64 byte_count = range_span(req->remain) * SECTOR_SIZE;
    if (byte_count == 0)
        goto done;
    u64 buf_phys;
    int prd_count = 0;
    while (byte_count > 0 && prd_count < PRDT_ENTRIES) {
        buf_phys = physical_from_virtual(req->buf);
        if (buf_phys >= U64_FROM_BIT(32))
            break;

        /* Ensure the buffer doesn't cross a 64K boundary. */
        u64 boundary = pad(buf_phys + 1, 64 * KB);
        u64 len = MIN(byte_count, boundary - buf_phys);

        ata_debug("%s: PRD address 0x%08x, len %ld\n", __func__, buf_phys, len);
        req->buf += len;
        byte_count -= len;
        if (len == U64_FROM_BIT(16))
            len = 0;
        apci->prdt[prd_count].buf_addr = buf_phys;
        apci->prdt[prd_count].byte_count = len;
        apci->prdt[prd_count].ctrl = 0;
        prd_count++;
    }
    if (prd_count > 0) {
        apci->prdt[prd_count - 1].ctrl = PRD_LAST_ENTRY;
        range blocks = irange(req->remain.start,
            req->remain.end - byte_count / SECTOR_SIZE);
        ata_debug("%s: starting DMA for %R\n", __func__, blocks);
        pci_bar_write_4(&apci->bmr, ATA_BMR_PRDT(ATA_PRIMARY), apci->prdt_phys);
        if (!ata_io_cmd_dma(apci->ata, req->write, blocks)) {
            req->s = timm("result", "ATA command failed");
            goto done;
        }
        req->remain = irange(blocks.end, req->remain.end);
        write_barrier();
        u8 cmd = ATA_BMR_CMD_START | (!req->write ? ATA_BMR_CMD_READ : 0);
        pci_bar_write_1(&apci->bmr, ATA_BMR_CMD(ATA_PRIMARY), cmd);
        return false;
    }

    /* Couldn't use DMA, fall back to PIO. */
    apply(req->write ? apci->pio_write : apci->pio_read, req->buf, req->remain,
            req->sh);
    return true;

done:
    apply(req->sh, req->s);
    return true;
}

static void ata_pci_service_reqs(ata_pci apci)
{
    u64 irqflags = spin_lock_irq(&apci->lock);
    while (!list_empty(&apci->reqs)) {
        ata_pci_req req = struct_from_list(list_begin(&apci->reqs), ata_pci_req,
            l);
        spin_unlock_irq(&apci->lock, irqflags);
        if (ata_pci_service_req(apci, req)) {
            irqflags = spin_lock_irq(&apci->lock);
            list_delete(&req->l);
            deallocate(apci->h, req, sizeof(*req));
        } else {    /* request is in progress */
            return;
        }
    }
    spin_unlock_irq(&apci->lock, irqflags);
}

define_closure_function(2, 3, void, ata_pci_io,
                        ata_pci, apci, boolean, write,
                        void *, buf, range, blocks, status_handler, sh)
{
    ata_pci apci = bound(apci);
    ata_pci_req req = allocate(apci->h, sizeof(*req));
    if (req == INVALID_ADDRESS) {
        apply(sh, timm("result", "request allocation failed"));
        return;
    }
    req->write = bound(write);
    req->buf = buf;
    req->remain = blocks;
    req->sh = sh;
    req->s = STATUS_OK;
    u64 irqflags = spin_lock_irq(&apci->lock);
    boolean idle = list_empty(&apci->reqs);
    list_push_back(&apci->reqs, &req->l);
    spin_unlock_irq(&apci->lock, irqflags);
    if (idle)
        ata_pci_service_reqs(apci);
}

define_closure_function(1, 0, void, ata_pci_irq,
                        ata_pci, apci)
{
    ata_pci apci = bound(apci);
    pci_bar_write_1(&apci->bmr, ATA_BMR_CMD(ATA_PRIMARY), 0);
    u8 status = pci_bar_read_1(&apci->bmr, ATA_BMR_STATUS(ATA_PRIMARY));
    boolean error = ata_clear_irq(apci->ata);
    ata_debug("%s: BMR status 0x%02x, ATA %s\n", __func__, status,
              error ? "error" : "OK");
    if (status & ATA_BMR_STATUS_ERR) {
        /* Clear error status */
        pci_bar_write_1(&apci->bmr, ATA_BMR_STATUS(ATA_PRIMARY),
            ATA_BMR_STATUS_ERR);

        error = true;
    }
    u64 irqflags = spin_lock_irq(&apci->lock);
    if (!list_empty(&apci->reqs)) {
        if (error) {
            ata_pci_req req = struct_from_list(list_begin(&apci->reqs),
                ata_pci_req, l);
            req->s = timm("result", "I/O error");
        }
        enqueue(bhqueue, &apci->service);
    }
    spin_unlock_irq(&apci->lock, irqflags);
}

define_closure_function(1, 0, void, ata_pci_service,
                        ata_pci, apci)
{
    ata_pci_service_reqs(bound(apci));
}

closure_function(3, 1, boolean, ata_pci_probe,
                 heap, general, heap, contiguous, storage_attach, a,
                 pci_dev, d)
{
    heap general = bound(general);
    heap contiguous = bound(contiguous);
    if (pci_get_class(d) != PCIC_STORAGE || pci_get_subclass(d) != PCIS_STORAGE_IDE)
        return false;

    ata_pci dev = ata_pci_alloc(general, contiguous, d);
    if (!ata_probe(dev->ata)) {
        ata_pci_dealloc(general, contiguous, dev);
        return false;
    }

    /* Align the PRDT to ensure it doesn't cross a 64K boundary. */
    dev->prdt_phys = physical_from_virtual(dev->prdt);
    u64 boundary = pad(dev->prdt_phys, 64 * KB);
    int align_offset =
            (dev->prdt_phys + PRDT_ENTRIES * sizeof(struct prd) > boundary) ?
                    boundary - dev->prdt_phys : 0;
    dev->prdt_phys += align_offset;
    assert(dev->prdt_phys < U64_FROM_BIT(32));
    dev->prdt = pointer_from_u64(u64_from_pointer(dev->prdt) + align_offset);

    dev->h = general;
    pci_bar_init(d, &dev->bmr, 4, 0, -1);
    pci_set_bus_master(d);
    list_init(&dev->reqs);
    spin_lock_init(&dev->lock);

    // attach
    init_closure(&dev->read, ata_pci_io, dev, false);
    init_closure(&dev->write, ata_pci_io, dev, true);
    dev->pio_read = create_ata_io(general, dev->ata, ATA_READ48);
    dev->pio_write = create_ata_io(general, dev->ata, ATA_WRITE48);
    init_closure(&dev->irq_handler, ata_pci_irq, dev);
    init_closure(&dev->service, ata_pci_service, dev);
    ata_clear_irq(dev->ata);
    u64 irq = allocate_interrupt();
    assert(irq != INVALID_PHYSICAL);
    ioapic_set_int(ATA_IRQ(ATA_PRIMARY), irq);
    register_interrupt(irq, (thunk)&dev->irq_handler, "ata pci");
    apply(bound(a), (block_io)&dev->read, (block_io)&dev->write,
          ata_get_capacity(dev->ata));
    return true;
}

void ata_pci_register(kernel_heaps kh, storage_attach a)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, ata_pci_probe, h, heap_backed(kh), a));
}
