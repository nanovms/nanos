void lapic_eoi(void);
void init_apic(kernel_heaps kh);
void lapic_runloop_timer(timestamp interval);
void configure_lapic_timer(heap h);
