struct console_driver {
    void (*write)(void *d, char *s, bytes count);
};

typedef closure_type(console_attach, void, struct console_driver *);

void init_console(kernel_heaps kh);
