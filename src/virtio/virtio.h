#include <drivers/storage.h>

void init_network_iface(tuple root);
void init_virtio_network(kernel_heaps kh);

void virtio_register_scsi(kernel_heaps kh, storage_attach a);
void virtio_register_blk(kernel_heaps kh, storage_attach a);
