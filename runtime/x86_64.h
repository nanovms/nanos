
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

#include <io.h>
#include <disk.h>

/*
 * WARNING: these inserts seem to be very fragile wrt actually
 *          referring to the correct value by the right register
 */
#define mov_to_cr(__x, __y) __asm__("mov %0,%%"__x: :"r"(__y):);
#define mov_from_cr(__x, __y) __asm__("mov %%"__x", %0":"=r"(__y):);

static inline void enable_interrupts()
{
    asm ("sti");
}

static inline void disable_interrupts()
{
    asm ("cli");
}



// belong here? share with nasm
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
#define FRAME_FS 19
// gs, and xmm

#define ENTER(frame) __asm__("mov %0, %%rbx"::"g"(frame)); __asm__("jmp frame_enter")
