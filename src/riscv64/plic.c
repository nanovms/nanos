#include <kernel.h>
#include <plic.h>

#define PLIC_OFF(r) (mmio_base_addr(PLIC)+(r))
#define read_plic(o) mmio_read_32(PLIC_OFF(o))
#define read_plic_irq(o, i) mmio_read_32(PLIC_OFF(o)+(i)*sizeof(u32))
#define read_plic_bit(o, i) (((mmio_read_32(PLIC_OFF(o)+(i/32)*sizeof(u32)))&(1<<((i)%32)))!=0)
#define write_plic(o, x) (mmio_write_32(PLIC_OFF(o),(x)))
#define write_plic_irq(o, i, x) (mmio_write_32(PLIC_OFF(o)+(i)*sizeof(u32),(x)))
#define set_plic_bit(r, i) do { u32 off = ((i)/32)*sizeof(u32); write_plic(r+off, read_plic(r+off)|(1<<((i)%32))); } while(0)
#define clear_plic_bit(r, i) do { u32 off = ((i)/32)*sizeof(u32); write_plic(r+off, read_plic(r+off)&~(1<<((i)%32))); } while(0)

static inline u64 context_from_hartid(u64 hartid)
{
    return (hartid << 1) + 1;
}

void plic_disable_int(int irq)
{
    for (int cpuid = 0; cpuid < present_processors; cpuid++) {
        cpuinfo ci = cpuinfo_from_id(cpuid);
        clear_plic_bit(PLIC_ENABLE(context_from_hartid(ci->m.hartid)), irq);
    }
}

void plic_enable_int(int irq, u32 target_cpu)
{
    cpuinfo ci = cpuinfo_from_id(target_cpu);
    set_plic_bit(PLIC_ENABLE(context_from_hartid(ci->m.hartid)), irq);
}

void plic_set_int_priority(int irq, u32 pri)
{
    write_plic_irq(PLIC_PRIORITY, irq, pri);
}

void plic_set_threshold(u64 hartid, u32 thresh)
{
    write_plic(PLIC_THRESH(context_from_hartid(hartid)), thresh);
}

boolean plic_int_is_pending(int irq)
{
    return read_plic_bit(PLIC_PENDING, irq);
}

u64 plic_dispatch_int(void)
{
    return read_plic(PLIC_CLAIM(context_from_hartid(current_cpu()->m.hartid)));
}

void plic_eoi(int irq)
{
    write_plic(PLIC_CLAIM(context_from_hartid(current_cpu()->m.hartid)), irq);
}

void init_plic()
{
}

void msi_format(u32 *address, u32 *data, int vector, u32 target_cpu)
{
}

void msi_get_config(u32 address, u32 data, int *vector, u32 *target_cpu)
{
}
