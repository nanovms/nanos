#include <virtio/virtio.h>

void init_storage(kernel_heaps kh, storage_attach a)
{
    virtio_register_blk(kh, a);
    virtio_register_scsi(kh, a);
}
