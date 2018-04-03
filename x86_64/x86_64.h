#include <x86.h>

#define VIRTUAL_ADDRESS_BITS 48

#define FS_MSR 0xc0000100
#define GS_MSR 0xc0000101
#define LSTAR 0xC0000082
#define EFER_MSR 0xc0000080
#define EFER_SCE 1
#define STAR_MSR 0xc0000081
#define LSTAR_MSR 0xc0000082
#define SFMASK_MSR 0xc0000084

extern u64 cpuid();
extern u64 read_msr(u64);
extern void write_msr(u64, u64);
extern u64 read_xmsr(u64);
extern void write_xmsr(u64, u64);
extern void syscall_enter();
extern u64 *frame;

#define HUGE_PAGESIZE 0x100000000ull


static inline void enable_interrupts()
{
    asm ("sti");
}

static inline void disable_interrupts()
{
    asm ("cli");
}

// belong here? share with nasm
// currently maps to the linux gdb frame layout for convenience
// could use a map
#define FRAME_RAX 0
#define FRAME_SYSCALL 0
#define FRAME_RBX 1
#define FRAME_RCX 2
#define FRAME_RDX 3
#define FRAME_RSI 4
#define FRAME_RDI 5
#define FRAME_RBP 6
#define FRAME_RSP 7
#define FRAME_R8  8
#define FRAME_R9  9 
#define FRAME_R10 10
#define FRAME_R11 11
#define FRAME_R12 12
#define FRAME_R13 13
#define FRAME_R14 14
#define FRAME_R15 15
#define FRAME_RIP 17
#define FRAME_FLAGS 18
#define FRAME_VECTOR 19 
#define FRAME_FS 20
#define FRAME_GS 21
//  xmm?
#define REG_MAX 27

typedef u64 context[REG_MAX];

boolean breakpoint_insert(u32 a);
boolean breakpoint_remove(u32 a);

#define ENTER(frame) __asm__("mov %0, %%rbx"::"g"(frame)); __asm__("jmp frame_enter")


static inline void write_barrier()
{
    asm ("sfence");
}
static inline void read_barrier()
{
        asm ("lfence");
}

static inline void memory_barrier()
{
    // waa
    asm ("lfence");
    asm ("sfence");
}


static inline void set_syscall_handler(void *syscall_entry)
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

static time rdtsc(void)
{
    u64 a, d;
    asm("cpuid");
    asm volatile("rdtsc" : "=a" (a), "=d" (d));

    return (((time)a) | (((time)d) << 32));
}

void init_clock(heap backed_virtual);
void serial_out(char a);

boolean valiate_virtual(void *base, u64 length);

#define halt(__m) console(__m); QEMU_HALT();


// tuples
char *interrupt_name(u64 code);
char *register_name(u64 code);

