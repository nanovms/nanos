#include <kernel.h>
#include <gpio.h>

#define PL061_GPIOIEV   0x40c
#define PL061_GPIOIE    0x410
#define PL061_GPIOIC    0x41c

void gpio_irq_enable(u64 mask)
{
    mmio_write_32(mmio_base_addr(GPIO) + PL061_GPIOIEV, mask);
    mmio_write_32(mmio_base_addr(GPIO) + PL061_GPIOIE, mask);
}

void gpio_irq_clear(u64 mask)
{
    mmio_write_32(mmio_base_addr(GPIO) + PL061_GPIOIC, mask);
}
