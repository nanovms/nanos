void serial_putchar(char c);
void serial_set_devbase(u64 devbase);

struct console_driver *pl011_console_init(kernel_heaps kh, void *base);
