#include <kernel.h>
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

static struct ata *ata_pci_alloc(heap general, pci_dev d)
{
    struct ata *dev = ata_alloc(general);
    ata_debug("%s: %s ATA controller\n", __func__, ata_pcivendor2str(d));
    return dev;
}

closure_function(2, 1, boolean, ata_pci_probe,
                 heap, general, storage_attach, a,
                 pci_dev, d)
{
    heap general = bound(general);
    if (pci_get_class(d) != PCIC_STORAGE || pci_get_subclass(d) != PCIS_STORAGE_IDE)
        return false;

    struct ata *dev = ata_pci_alloc(general, d);
    if (!ata_probe(dev)) {
        ata_dealloc(dev);
        return false;
    }

    // attach
    block_io in = create_ata_io(general, dev, ATA_READ48);
    block_io out = create_ata_io(general, dev, ATA_WRITE48);
    apply(bound(a), in, out, ata_get_capacity(dev));
    return true;
}

void ata_pci_register(kernel_heaps kh, storage_attach a)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, ata_pci_probe, h, a));
}
