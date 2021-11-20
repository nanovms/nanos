struct console_driver {
    struct list l;
    void (*write)(void *d, const char *s, bytes count);
    void (*config)(void *d, tuple r);
    char *name;
    boolean disabled;
};

typedef closure_type(console_attach, void, struct console_driver *);

void init_console(kernel_heaps kh);
void config_console(tuple root);
void attach_console_driver(struct console_driver *driver);
void console_force_unlock(void);
