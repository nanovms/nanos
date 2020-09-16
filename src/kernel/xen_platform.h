boolean xen_detect(kernel_heaps kh);
boolean xen_detected(void);
status xen_probe_devices(void);
void init_xennet(kernel_heaps kh);
void init_xenblk(kernel_heaps kh, storage_attach sa);
