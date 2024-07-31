#include <kernel.h>
#include <drivers/console.h>
#include "serial.h"

typedef struct pl011_console {
    struct console_driver driver;
    u32 *addr;
} *pl011_console;

RO_AFTER_INIT volatile u32 *UART0_DR = (volatile u32 *)DEV_BASE_UART;
RO_AFTER_INIT volatile u32 *UART0_FR = (volatile u32 *)(DEV_BASE_UART + 0x18);

#define UART_FR_TXFF (1 << 5)   /* TX FIFO full */

static inline boolean tx_full(void) {
    return ((*UART0_FR) & UART_FR_TXFF) != 0;
}

/* This floods the ftrace buffers when user is outputting lots of data */
NOTRACE
void serial_putchar(char c)
{
    while (tx_full());
    *UART0_DR = c;
}

void serial_set_devbase(u64 devbase)
{
    UART0_DR = ((void*)UART0_DR) + devbase;
    UART0_FR = ((void*)UART0_FR) + devbase;
}

static void pl011_write(void *d, const char *s, bytes count)
{
    pl011_console console = d;
    for (; count--; s++) {
        while (console->addr[6] & UART_FR_TXFF)
            ;
        console->addr[0] = *s;
    }
}

struct console_driver *pl011_console_init(kernel_heaps kh, void *base)
{
    pl011_console console = allocate(heap_general(kh), sizeof(*console));
    console->addr = base;
    zero(&console->driver, sizeof(console->driver));
    console->driver.name = ss("pl011");
    console->driver.write = pl011_write;
    return &console->driver;
}
