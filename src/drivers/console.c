#include <kernel.h>
#include "serial.h"
#include "console.h"
#include "vga.h"
#include "netconsole.h"

static void serial_console_write(void *d, const char *s, bytes count)
{
    for (; count--; s++) {
        serial_putchar(*s);
    }
}

struct console_driver serial_console_driver = {
    .write = serial_console_write,
    .name = "serial"
};

struct console_driver *console_drivers[4] = {
    &serial_console_driver,
};

static struct spinlock write_lock;

void console_write(const char *s, bytes count)
{
    spin_lock(&write_lock);
    for (struct console_driver **pd = console_drivers; *pd; pd++) {
        if ((*pd)->disabled)
            continue;
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
    console_attach a = closure(h, attach_console);
    vga_pci_register(kh, a);
    netconsole_register(kh, a);
}

void config_console(tuple root)
{
    buffer b;
    vector v = vector_from_tuple(transient, get(root, sym(consoles)));

    if (v == 0)
        return;
    vector_foreach(v, b) {
        if (buffer_length(b) < 2)
            goto error;
        u8 op = pop_u8(b);
        switch(op) {
        case '+':
        case '-':
            for (struct console_driver **pd = console_drivers; *pd; pd++) {
                if (!buffer_compare_with_cstring(b, (*pd)->name))
                    continue;
                (*pd)->disabled = op == '-';
                if ((*pd)->config)
                    (*pd)->config(*pd, root);
                break;
            }
            break;
        default:
            goto error;
        }
    }
    return;
error:
    msg_err("error parsing consoles from manifest\n");
    return;
}
