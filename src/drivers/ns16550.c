#include <kernel.h>
#include "console.h"

typedef struct ns16550_console {
    struct console_driver driver;
    u8 *addr;
} *ns16550_console;

static boolean tx_empty(volatile u8 *addr) {
    return *(addr + 5) & 0x20;
}

static void ns16550_write(void *d, const char *s, bytes count)
{
    ns16550_console console = d;
    for (; count--; s++) {
        while (!tx_empty(console->addr))
            ;
        *console->addr = *s;
    }
}

struct console_driver *ns16550_console_init(kernel_heaps kh, void *base)
{
    ns16550_console console = allocate(heap_general(kh), sizeof(*console));
    console->addr = base;
    zero(&console->driver, sizeof(console->driver));
    console->driver.name = "16550";
    console->driver.write = ns16550_write;
    return &console->driver;
}
