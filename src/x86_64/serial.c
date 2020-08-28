#include <kernel.h>
#include <io.h>
#include "serial.h"

#define BASE 0x3f8

// XXX never gets called!
void serial_init()
{
    out8(BASE+3, 0x80); // dlab
    out8(BASE+0, 0x0c); // 9600
    out8(BASE+1, 0x0); // divisor latch
    out8(BASE+3, 0x3); // 8n1
    out8(BASE+2, 0xc7); // fifo control
    out8(BASE+5, 0xc7); // dtr, rts, out2
}

static boolean is_transmit_empty() {
    return in8(BASE + 5) & 0x20;
}

/* This floods the ftrace buffers when user is outputting lots of data */
NOTRACE
void serial_putchar(char c)
{
    while (!is_transmit_empty())
        ;
    out8(BASE, c);
}
