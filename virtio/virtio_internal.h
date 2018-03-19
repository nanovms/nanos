#include <sruntime.h>
typedef u64 uint64_t;
typedef u32 uint32_t;
typedef u16 uint16_t;
typedef u8 uint8_t;

typedef u64 physical;
typedef u64 virtual;


struct virtqueue;

typedef struct vtpci *vtpci;

struct vtpci {
    u64 base; //io region base
    uint64_t			 vtpci_features;

    heap contiguous;
    heap general;    
    struct virtio_feature_desc	*vtpci_child_feat_desc;

    int				 vtpci_nvqs;
    struct virtqueue	 *vtpci_vqs;
    //struct vtpci_interrupt	 vtpci_device_interrupt;
    //truct vtpci_interrupt	 *vtpci_msix_vq_interrupts;
    int				 vtpci_nmsix_resources;
    void *vtpci_msix_res; // not a res
};



/* VirtIO ring descriptors: 16 bytes.
 * These can chain together via "next". */
struct vring_desc {
        /* Address (guest-physical). */
        uint64_t addr;
        /* Length. */
        uint32_t len;
        /* The flags as indicated above. */
        uint16_t flags;
        /* We chain unused descriptors via this, too. */
        uint16_t next;
};

struct vring_avail {
        uint16_t flags;
        uint16_t idx;
        uint16_t ring[0];
};

/* uint32_t is used here for ids for padding reasons. */
struct vring_used_elem {
        /* Index of start of used descriptor chain. */
        uint32_t id;
        /* Total length of the descriptor chain which was written to. */
        uint32_t len;
};

struct vring_used {
        uint16_t flags;
        uint16_t idx;
        struct vring_used_elem ring[0];
};

struct vring {
	unsigned int num;

	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
};

struct virtqueue {
    void *		 vq_dev;
    string name;
    uint16_t		 vq_queue_index;
    uint16_t		 vq_nentries;
    uint32_t		 vq_flags;
#define	VIRTQUEUE_FLAG_INDIRECT	 0x0001
#define	VIRTQUEUE_FLAG_EVENT_IDX 0x0002

    int			 vq_alignment;
    int			 vq_ring_size;
    void		*vq_ring_mem;
    int			 vq_max_indirect_size;
    int			 vq_indirect_mem_size;
    thunk interrupt;
    struct vring         vq_ring;
    uint16_t		 vq_free_cnt;
    uint16_t		 vq_queued_cnt;
    /*
     * Head of the free chain in the descriptor table. If
     * there are no free descriptors, this will be set to
     * VQ_RING_DESC_CHAIN_END.
     */
    uint16_t		 vq_desc_head_idx;
    /*
     * Last consumed descriptor in the used table,
     * trails vq_ring.used->idx.
     */
    uint16_t		 vq_used_cons_idx;

    struct vq_desc_extra {
        void		  *cookie;
        struct vring_desc *indirect;
        physical	   indirect_paddr;
        uint16_t	   ndescs;
    } vq_descx[0];
};


#include <pci.h>
#include <virtio.h>
#include <virtio_pci.h>
#include <virtqueue.h>
#include <virtio_net.h>

void vtpci_notify_virtqueue(vtpci sc, uint16_t queue);
