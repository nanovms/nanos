
/* Status byte for guest to report progress. */
#define VIRTIO_CONFIG_STATUS_RESET	0x00
#define VIRTIO_CONFIG_STATUS_ACK	0x01
#define VIRTIO_CONFIG_STATUS_DRIVER	0x03
#define VIRTIO_CONFIG_STATUS_DRIVER_OK	0x04
#define VIRTIO_CONFIG_STATUS_FEATURE	0x08
#define VIRTIO_CONFIG_STATUS_FAILED	0x80

/*
 * Generate interrupt when the virtqueue ring is
 * completely used, even if we've suppressed them.
 */
#define VIRTIO_F_NOTIFY_ON_EMPTY U64_FROM_BIT(24)

/* Support for indirect buffer descriptors. */
#define VIRTIO_RING_F_INDIRECT_DESC	U64_FROM_BIT(28)

/* Support to suppress interrupt until specific index is reached. */
#define VIRTIO_RING_F_EVENT_IDX		U64_FROM_BIT(29)

/*
 * The guest should never negotiate this feature; it
 * is used to detect faulty drivers.
 */
#define VIRTIO_F_BAD_FEATURE U64_FROM_BIT(30)

/*
 * Some VirtIO feature bits (currently bits 28 through 31) are
 * reserved for the transport being used (eg. virtio_ring), the
 * rest are per-device feature bits.
 */
#define VIRTIO_TRANSPORT_F_START	28
#define VIRTIO_TRANSPORT_F_END		32

typedef closure_type(storage_attach, void, block_read, block_write, u64);
void init_virtio_storage(kernel_heaps kh, storage_attach);
void init_virtio_network(kernel_heaps kh);
void init_network_iface(tuple root);
