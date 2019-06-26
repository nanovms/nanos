#include <runtime.h>
#include "serial.h"

void console_write(char *s, bytes count)
{
    for (; count--; s++) {
        serial_putchar(*s);
    }
}
