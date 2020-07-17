boolean hyperv_detect(kernel_heaps kh);
boolean hyperv_detected(void);

void init_vmbus(kernel_heaps kh);
status hyperv_probe_devices(storage_attach a, boolean* storage_inited);
