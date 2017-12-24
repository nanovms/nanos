#include <unistd.h>

unsigned int x;
unsigned int y=5;

#define outl(__data, __port)	__asm __volatile("outl %0, %w1" : : "a" (__data), "Nd" (__port));

extern void pci_checko();
extern void serial_out(char);
static char hex[]="0123456789abcdef";

static void runny(unsigned char x)
{
    if (x > 10) {
        serial_out((x-10) + 'a');
        }
    else
        {
                        serial_out(x + '0');
        }
}

static void p(unsigned char x)
{
    runny ((x>>4)&0xf);
    runny (x&0xf);
}

int main()
{
    char hello_world[] = "Hello World!\n";
    write (1, hello_world, sizeof(hello_world)-1);
    pci_checko();
    return 0;
}
