#include <kernel.h>
#include "serial.h"
#include "console.h"
#include "netconsole.h"

static boolean inited;

void serial_console_write(void *d, const char *s, bytes count)
{
    for (; count--; s++) {
        serial_putchar(*s);
    }
}

static struct list console_drivers;

static struct spinlock write_lock;

void attach_console_driver(struct console_driver *driver)
{
    spin_lock(&write_lock);
    list_insert_before(driver->disabled ? list_end(&console_drivers) : list_begin(&console_drivers),
            &driver->l);
    spin_unlock(&write_lock);
}

void console_write(const char *s, bytes count)
{
    if (!inited) {
        while (count-- > 0)
            serial_putchar(*s++);
        return;
    }
    spin_lock(&write_lock);
    list_foreach(&console_drivers, e) {
        struct console_driver *d = struct_from_list(e, struct console_driver *, l);
        if (d->disabled)
            break;
        d->write(d, s, count);
    }
    spin_unlock(&write_lock);
}

void console_force_unlock(void)
{
    spin_unlock(&write_lock);
}

closure_function(0, 1, void, attach_console,
                 struct console_driver *, d)
{
    attach_console_driver(d);
}

void init_console(kernel_heaps kh)
{
    list_init(&console_drivers);
    heap h = heap_general(kh);
    console_attach a = closure(h, attach_console);
    netconsole_register(kh, a);
    inited = true;
}

closure_function(1, 2, boolean, config_console_each,
                 tuple, root,
                 value, a, value, v)
{
    if (!is_string(v)) {
        msg_err("value (attr %v) not a string\n", a);
        return false;
    }
    if (buffer_length(v) < 2)
        return false;
    buffer b = alloca_wrap(v);
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
                d->config(d, bound(root));
            break;
        }
        break;
    default:
        return false;
    }
    return true;
}

void config_console(tuple root)
{
    value v = get(root, sym(consoles));
    if (v == 0)
        return;
    if (!is_composite(v)) {
        msg_err("consoles config is neither vector nor tuple\n");
        return;
    }
    if (!iterate(v, stack_closure(config_console_each, root)))
        msg_err("error parsing consoles from manifest\n");
}
