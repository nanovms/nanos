void init_virtio_9p(kernel_heaps kh);
void init_virtio_balloon(kernel_heaps kh);
void init_virtio_blk(kernel_heaps kh, storage_attach a);
void init_virtio_network(kernel_heaps kh);
void init_virtio_rng(kernel_heaps kh);
void init_virtio_scsi(kernel_heaps kh, storage_attach a);
void init_virtio_socket(kernel_heaps kh);

void virtio_mmio_enum_devs(kernel_heaps kh);
