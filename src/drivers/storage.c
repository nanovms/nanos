#include <kernel.h>
#include <virtio/virtio.h>
#include <vmware/storage.h>
#include <drivers/ata-pci.h>
#include <drivers/nvme.h>

void init_storage(kernel_heaps kh, storage_attach a, boolean enable_ata)
{
    virtio_register_blk(kh, a);
    virtio_register_scsi(kh, a);

    /* TODO register these dynamically */
#ifdef __x86_64__
    pvscsi_register(kh, a);
    nvme_register(kh, a);
    if (enable_ata)
        ata_pci_register(kh, a);
#endif
}
