#include <runtime.h>
#define BASE 0x3f8

void serial_init()
{
    outb(BASE+3, 0x80); // dlab
    outb(BASE+0, 0x0c); // 9600
    outb(BASE+1, 0x0); // divisor latch
    outb(BASE+3, 0x3); // 8n1
    outb(BASE+2, 0xc7); // fifo control
    outb(BASE+5, 0xc7); // dtr, rts, out2
}

static boolean is_transmit_empty() {
    return inb(BASE + 5) & 0x20;
}

void serial_out(char a)
{
    while (!is_transmit_empty());
    outb(BASE, a);
}
