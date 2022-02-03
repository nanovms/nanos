#define PLIC_MAX_INT 0x35
#define PLIC_VIRTIO_INTS_START 1
#define PLIC_VIRTIO_INTS_END 9
#define PLIC_PCIE_INTS_START 0x20
#define PLIC_PCIE_INTS_END 0x23

#define PLIC_PRIORITY   0
#define PLIC_PENDING    0x1000
#define PLIC_ENABLE_C1  0x2080
#define PLIC_THRESH_C1  0x201000
#define PLIC_CLAIM_C1   0x201004

void plic_disable_int(int irq);
void plic_enable_int(int irq);
void plic_clear_pending_int(int irq);
void plic_set_int_priority(int irq, u32 pri);
void plic_set_c1_threshold(u32 thresh);
void plic_set_int_config(int irq, u32 cfg);
boolean plic_int_is_pending(int irq);
u64 plic_dispatch_int(void);
void plic_eoi(int irq);
void init_plic();

