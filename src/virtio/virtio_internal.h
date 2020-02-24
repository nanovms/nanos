#include "virtio_pci.h"

typedef struct virtqueue *virtqueue;

typedef closure_type(vqfinish, void, u64);

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

void vtpci_notify_virtqueue(vtpci sc, u16 queue);

status virtqueue_alloc(vtpci dev,
                       const char *name,
                       u16 queue,
                       u16 size,
                       int align,
                       struct virtqueue **vqp,
                       thunk *t);

void virtqueue_set_max_queued(virtqueue, int);

/* The Host uses this in used->flags to advise the Guest: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization.  Guest will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY  1
/* The Guest uses this in avail->flags to advise the Host: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT      1

physical virtqueue_paddr(struct virtqueue *vq);
u16 virtqueue_entries(virtqueue vq);

typedef struct vqmsg *vqmsg;

vqmsg allocate_vqmsg(virtqueue vq);
void deallocate_vqmsg(virtqueue vq, vqmsg m);
void vqmsg_push(virtqueue vq, vqmsg m, void * addr, u32 len, boolean write);
void vqmsg_commit(virtqueue vq, vqmsg m, vqfinish completion);
