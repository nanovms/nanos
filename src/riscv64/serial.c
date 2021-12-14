#include <kernel.h>
#include "serial.h"

/* This is a NS16550A UART, i.e. PC style */
volatile u8 *UART0_BASE = (volatile u8 *)DEV_BASE_UART;

static inline boolean tx_empty(void) {
    return *(UART0_BASE+5) & 0x20;
}

/* This floods the ftrace buffers when user is outputting lots of data */
NOTRACE
void serial_putchar(char c)
{
    while (!tx_empty());
    *UART0_BASE = c;
}

void serial_set_devbase(u64 devbase)
{
    UART0_BASE = ((void*)UART0_BASE) + devbase;
}

