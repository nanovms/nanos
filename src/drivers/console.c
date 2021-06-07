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

static struct list console_drivers;

static struct spinlock write_lock;

void console_write(const char *s, bytes count)
{
    spin_lock(&write_lock);
    list_foreach(&console_drivers, e) {
        struct console_driver *d = struct_from_list(e, struct console_driver *, l);
        if (d->disabled)
            break;
        d->write(d, s, count);
    }
    spin_unlock(&write_lock);
}

closure_function(0, 1, void, attach_console,
                 struct console_driver *, d)
{
    list_insert_before(d->disabled ? list_end(&console_drivers) : list_begin(&console_drivers),
            &d->l);
}

void init_console(kernel_heaps kh)
{
    list_init(&console_drivers);
    list_push_back(&console_drivers, &serial_console_driver.l);
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
            list_foreach(&console_drivers, e) {
                struct console_driver *d = struct_from_list(e, struct console_driver *, l);
                if (!buffer_compare_with_cstring(b, d->name))
                    continue;
                list_delete(e);
                if (op == '-') {
                    d->disabled = true;
                    list_push_back(&console_drivers, e);
                } else {
                    d->disabled = false;
                    list_insert_before(list_begin(&console_drivers), e);
                }
                if (d->config)
                    d->config(d, root);
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
