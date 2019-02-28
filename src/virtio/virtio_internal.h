#include <runtime.h>
#include <kvm_platform.h>

typedef struct virtqueue *virtqueue;

typedef struct vtpci *vtpci;

typedef closure_type(vqfinish, void, u64);

struct vtpci {
    int slot;
    u64 base; //io region base
    u64 vtpci_features;

    heap contiguous;
    heap general;    
    struct virtio_feature_desc	*vtpci_child_feat_desc;

    int vtpci_nvqs;
    struct virtqueue *vtpci_vqs;
};

#include <pci.h>
#include <virtio.h>
#include <virtio_pci.h>
#include <virtio_net.h>

void vtpci_notify_virtqueue(vtpci sc, u16 queue);

status virtqueue_alloc(vtpci dev,
                       u16 queue,
                       u16 size,
                       int align,
                       struct virtqueue **vqp,
                       thunk *t);


/* The Host uses this in used->flags to advise the Guest: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization.  Guest will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY  1
/* The Guest uses this in avail->flags to advise the Host: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT      1

physical virtqueue_paddr(struct virtqueue *vq);

typedef struct vqmsg *vqmsg;

vqmsg allocate_vqmsg(virtqueue vq);
void deallocate_vqmsg(virtqueue vq, vqmsg m);
void vqmsg_push(virtqueue vq, vqmsg m, void * addr, u32 len, boolean write);
void vqmsg_commit(virtqueue vq, vqmsg m, vqfinish completion);
