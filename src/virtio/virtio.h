#include <drivers/storage.h>

void init_virtio_network(kernel_heaps kh);

void virtio_register_scsi(kernel_heaps kh, storage_attach a);
void virtio_register_blk(kernel_heaps kh, storage_attach a);

void virtio_mmio_parse(kernel_heaps kh, const char *str, int len);
