/* just a test */

volatile unsigned int *UART0DR = (unsigned int *)0x09000000; /* data register */
volatile unsigned int *UART0FR = (unsigned int *)0x09000018; /* flag register */

#define UART_FR_TXFF (1 << 5)   /* TX FIFO full */

void putc(char c)
{
    while ((*UART0FR) & UART_FR_TXFF);
    *UART0DR = c;
}

void puts(char *s)
{
    while (*s != '\0')
        putc(*s++);
}

int main(void)
{
  puts("unibooty\n");
  return 0;
}
