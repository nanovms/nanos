typedef struct vtpci *vtpci;
vtpci attach_vtpci(int bus, int slot, int func);

/* VirtIO PCI vendor/device ID. */
#define VIRTIO_PCI_VENDORID	0x1AF4
#define VIRTIO_PCI_DEVICEID_MIN	0x1000
#define VIRTIO_PCI_DEVICEID_MAX	0x103F

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
