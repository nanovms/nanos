boolean hyperv_detect(kernel_heaps kh);
boolean hyperv_detected(void);

static inline void HV_SHUTDOWN(void) __attribute__((noreturn));

#define PM1a_CNT 0x00000404
#define SLP_TYPa 0x0
#define SLP_EN  1<<13
static inline void HV_SHUTDOWN(void)
{
    out16((unsigned int)PM1a_CNT, SLP_TYPa | SLP_EN);
    while(1);
}

void init_vmbus(kernel_heaps kh);
status hyperv_probe_devices(storage_attach a, boolean* storage_inited);
