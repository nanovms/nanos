void serial_putchar(char c);
void serial_set_devbase(u64 devbase);
void serial_enable_buffered_output(heap h);
void serial_flush_and_disable_buffered_output(void);
