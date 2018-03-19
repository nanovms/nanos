
/* VirtIO PCI vendor/device ID. */
#define VIRTIO_PCI_VENDORID	0x1AF4
#define VIRTIO_PCI_DEVICEID_MIN	0x1000
#define VIRTIO_PCI_DEVICEID_MAX	0x103F
#define VIRTIO_PCI_DEVICEID_NETWORK 0x1000
#define VIRTIO_PCI_DEVICEID_STORAGE 0x1001
#define VIRTIO_PCI_DEVICEID_BALLOON 0x1002
#define VIRTIO_PCI_DEVICEID_CONSOLE 0x1003
#define VIRTIO_PCI_DEVICEID_ENTROPY 0x1005
#define VIRTIO_PCI_DEVICEID_FILESYSTEM_9P 0x1009

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
#define VIRTIO_F_NOTIFY_ON_EMPTY (1 << 24)

/* Support for indirect buffer descriptors. */
#define VIRTIO_RING_F_INDIRECT_DESC	(1 << 28)

/* Support to suppress interrupt until specific index is reached. */
#define VIRTIO_RING_F_EVENT_IDX		(1 << 29)

/*
 * The guest should never negotiate this feature; it
 * is used to detect faulty drivers.
 */
#define VIRTIO_F_BAD_FEATURE (1 << 30)

/*
 * Some VirtIO feature bits (currently bits 28 through 31) are
 * reserved for the transport being used (eg. virtio_ring), the
 * rest are per-device feature bits.
 */
#define VIRTIO_TRANSPORT_F_START	28
#define VIRTIO_TRANSPORT_F_END		32

void init_virtio_storage(heap h, heap physical, heap pages);
void init_virtio_network(heap h, heap physical, heap pages);
