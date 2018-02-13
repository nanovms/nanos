#include <runtime.h>
#include <booto.h>
#include <x86_64.h>
#include <elf64.h>
#include <closure.h>
#include <closure_templates.h>


void register_interrupt(int vector, thunk t);
void msi_map_vector(int slot, int vector);
u8 allocate_msi(thunk h);

extern void *pagebase;
extern u64 *ptalloc();

static inline void halt(char *x, ...)
{
}

static void set_syscall_handler(void *syscall_entry)
{
    u64 cs  = 0x08;
    u64 ss  = 0x10;

    write_msr(LSTAR_MSR, u64_from_pointer(syscall_entry));
    // 48 is sysret cs, and ds is cs + 16...so fix the gdt for return
    // 32 is syscall cs, and ds is cs + 8
    write_msr(STAR_MSR, (cs<<48) | (cs<<32));
    write_msr(SFMASK_MSR, 0);
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
}
