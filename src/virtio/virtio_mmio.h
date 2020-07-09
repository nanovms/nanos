#define VTMMIO_OFFSET_MAGIC             0x000
#define VTMMIO_OFFSET_VERSION           0x004
#define VTMMIO_OFFSET_DEVID             0x008
#define VTMMIO_OFFSET_DEVFEATURES       0x010
#define VTMMIO_OFFSET_DEVFEATSEL        0x014
#define VTMMIO_OFFSET_DRVFEATURES       0x020
#define VTMMIO_OFFSET_DRVFEATSEL        0x024
#define VTMMIO_OFFSET_QUEUESEL          0x030
#define VTMMIO_OFFSET_QUEUENUMMAX       0x034
#define VTMMIO_OFFSET_QUEUENUM          0x038
#define VTMMIO_OFFSET_QUEUEREADY        0x044
#define VTMMIO_OFFSET_QUEUENOTIFY       0x050
#define VTMMIO_OFFSET_INTSTATUS         0x060
#define VTMMIO_OFFSET_INTACK            0x064
#define VTMMIO_OFFSET_STATUS            0x070
#define VTMMIO_OFFSET_QUEUEDESCLOW      0x080
#define VTMMIO_OFFSET_QUEUEDESCHIGH     0x084
#define VTMMIO_OFFSET_QUEUEAVAILLOW     0x090
#define VTMMIO_OFFSET_QUEUEAVAILHIGH    0x094
#define VTMMIO_OFFSET_QUEUEUSEDLOW      0x0A0
#define VTMMIO_OFFSET_QUEUEUSEDHIGH     0x0A4
#define VTMMIO_OFFSET_CONFIG            0x100

declare_closure_struct(1, 2, void, vtmmio_notify,
                       struct vtmmio_dev *, dev,
                       u16, queue_index, bytes, notify_offset);

declare_closure_struct(1, 0, void, vtmmio_irq,
    struct vtmmio_dev *, dev);

typedef struct vtmmio_dev {
    struct vtdev virtio_dev; /* must be first */
    struct list l;
    u64 membase;
    u64 memsize;
    int irq;
    void *vbase;
    u64 irq_vector;
    closure_struct(vtmmio_notify, notify);
    closure_struct(vtmmio_irq, irq_handler);
    vector vq_handlers;
} *vtmmio;

#define vtmmio_get_u32(dev, offset) (*((volatile u32 *)((dev)->vbase + offset)))

#define vtmmio_set_u32(dev, offset, value)  do {    \
    *(volatile u32 *)((dev)->vbase + offset) = value; \
} while (0)

static inline void vtmmio_set_u64(vtmmio dev, u64 offset, u64 value)
{
    vtmmio_set_u32(dev, offset, value);
    vtmmio_set_u32(dev, offset + 4, value >> 32);
}

#define vtmmio_get_status(dev)  (u8)vtmmio_get_u32(dev, VTMMIO_OFFSET_STATUS)

typedef closure_type(vtmmio_probe, void, vtmmio);

void vtmmio_probe_devs(vtmmio_probe probe);
void vtmmio_set_status(vtmmio dev, u8 status);
boolean attach_vtmmio(heap h, heap page_allocator, vtmmio d, u64 feature_mask);
status vtmmio_alloc_virtqueue(vtmmio dev, const char *name, int idx,
                              struct virtqueue **result);
