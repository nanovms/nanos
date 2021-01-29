void init_virtio_network(kernel_heaps kh);
void init_virtio_scsi(kernel_heaps kh, storage_attach a);
void init_virtio_blk(kernel_heaps kh, storage_attach a);

void virtio_mmio_parse(kernel_heaps kh, const char *str, int len);
