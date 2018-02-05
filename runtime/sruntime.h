#include <runtime.h>
#include <booto.h>
#include <x86_64.h>
#include <elf64.h>

void register_interrupt(int vector, thunk t);
void msi_map_vector(int slot, int vector);
u8 allocate_msi(thunk h);

extern void *pagebase;
extern u64 *ptalloc();

// belong here?
#define FRAME_RAX 0
#define FRAME_SYSCALL 0
#define FRAME_RBX 1
#define FRAME_RCX 2
#define FRAME_RDX 3
#define FRAME_RBP 4
#define FRAME_RSP 5
#define FRAME_RSI 6
#define FRAME_RDI 7
#define FRAME_R8 8
#define FRAME_R9 9 
#define FRAME_R10 10
#define FRAME_R11 11
#define FRAME_R12 12
#define FRAME_R13 13
#define FRAME_R14 14
#define FRAME_R15 15
#define FRAME_VECTOR 16
#define FRAME_RIP 17
#define FRAME_FLAGS 18
// ok, fs, gs, and xmm


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
