void lapic_eoi(void);
void init_apic(kernel_heaps kh);
void lapic_set_tsc_deadline_mode(u32 v);
clock_timer init_lapic_timer(void);
