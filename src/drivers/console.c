#include <kernel.h>
#include "serial.h"
#include "console.h"
#include "vga.h"

static void serial_console_write(void *d, const char *s, bytes count)
{
    for (; count--; s++) {
        serial_putchar(*s);
    }
}

struct console_driver serial_console_driver = {
    .write = serial_console_write
};

struct console_driver *console_drivers[4] = {
    &serial_console_driver,
};

static struct spinlock write_lock;

void console_write(const char *s, bytes count)
{
    spin_lock(&write_lock);
    for (struct console_driver **pd = console_drivers; *pd; pd++) {
        (*pd)->write(*pd, s, count);
    }
    spin_unlock(&write_lock);
}

closure_function(0, 1, void, attach_console,
                 struct console_driver *, d)
{
    struct console_driver **pd;

    for (pd = console_drivers; *pd; pd++)
        ;
    // last console driver elem is reserved for EOL marker
    assert(pd < console_drivers + _countof(console_drivers) - 1);

    *pd = d;
}

void init_console(kernel_heaps kh)
{
    heap h = heap_general(kh);
    vga_pci_register(kh, closure(h, attach_console));
}
