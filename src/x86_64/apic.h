clock_timer lapic_runloop_timer;

void lapic_eoi(void);
void init_apic(kernel_heaps kh);
void configure_lapic_timer(heap h);
