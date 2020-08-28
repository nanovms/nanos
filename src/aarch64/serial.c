#include <kernel.h>
#include <io.h>
#include "serial.h"

volatile u32 *UART0_DR = (volatile u32 *)DEV_BASE_UART;
volatile u32 *UART0_FR = (volatile u32 *)(DEV_BASE_UART + 0x18);

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
