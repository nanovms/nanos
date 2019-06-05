#pragma once
#define STACK_ALIGNMENT     16
#define KERNEL_STACK_PAGES  32
#define FAULT_STACK_PAGES   8
#define INT_STACK_PAGES     8
#define BH_STACK_PAGES      8
#define SYSCALL_STACK_PAGES 8

#define VIRTUAL_ADDRESS_BITS 48

#define CODE_SEGMENT_SELECTOR   8

#define FS_MSR 0xc0000100
#define GS_MSR 0xc0000101
#define LSTAR 0xC0000082
#define EFER_MSR 0xc0000080
#define EFER_SCE   0x0001
#define EFER_LME   0x0100
#define EFER_LMA   0x0400
#define EFER_NXE   0x0800
#define EFER_SVME  0x1000
#define EFER_LMSLE 0x2000
#define EFER_FFXSR 0x4000
#define EFER_TCE   0x8000
#define STAR_MSR 0xc0000081
#define LSTAR_MSR 0xc0000082
#define SFMASK_MSR 0xc0000084
#define TSC_DEADLINE_MSR 0x6e0

#define C0_WP   0x00010000

static inline void cpuid(u32 fn, u32 ecx, u32 * v)
{
    asm volatile("cpuid" : "=a" (v[0]), "=b" (v[1]), "=c" (v[2]), "=d" (v[3]) : "0" (fn), "2" (ecx));
}

extern u64 read_msr(u64);
extern void write_msr(u64, u64);
extern u64 read_xmsr(u64);
extern void write_xmsr(u64, u64);
extern void syscall_enter();

#define HUGE_PAGESIZE 0x100000000ull

#define mov_to_cr(__x, __y) asm volatile("mov %0,%%"__x : : "a"(__y) : "memory");
#define mov_from_cr(__x, __y) asm volatile("mov %%"__x", %0" : "=a"(__y) : : "memory");

static inline void enable_interrupts()
{
    asm volatile("sti");
}

static inline void disable_interrupts()
{
    asm volatile("cli");
}

// belong here? share with nasm
// currently maps to the linux gdb frame layout for convenience
#include "frame.h"

typedef u64 *context;

extern context running_frame;

extern void * syscall_stack_top;

#define BREAKPOINT_INSTRUCTION 00
#define BREAKPOINT_WRITE 01
#define BREAKPOINT_IO 10
#define BREAKPOINT_READ_WRITE 11

boolean breakpoint_insert(u64 a, u8 type, u8 length);
boolean breakpoint_remove(u32 a);

#define IRETURN(frame) asm volatile("mov %0, %%rbx"::"g"(frame)); asm("jmp frame_return")

void msi_map_vector(int slot, int msislot, int vector);

static inline void write_barrier()
{
    asm volatile("sfence");
}

static inline void read_barrier()
{
    asm volatile("lfence" ::: "memory");
}

static inline void memory_barrier()
{
    asm volatile("mfence" ::: "memory");
}

static inline void set_syscall_handler(void *syscall_entry)
{
    u64 cs = CODE_SEGMENT_SELECTOR;

    write_msr(LSTAR_MSR, u64_from_pointer(syscall_entry));
    // 48 is sysret cs, and ds is cs + 16...so fix the gdt for return
    // 32 is syscall cs, and ds is cs + 8
    write_msr(STAR_MSR, ((cs | 0x3)<<48) | (cs<<32));
    write_msr(SFMASK_MSR, 0);
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
}

static inline void set_page_write_protect(boolean enable)
{
    word cr0;
    mov_from_cr("cr0", cr0);
    cr0 = enable ? (cr0 | C0_WP) : (cr0 & ~C0_WP);
    mov_to_cr("cr0", cr0);
}

static inline u64 rdtsc(void)
{
    u32 a, d;
    asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx"); /* serialize execution */
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

void init_clock(kernel_heaps kh);
boolean using_lapic_timer(void);
void serial_out(u8 a);

// tuples
char *interrupt_name(u64 code);
char *register_name(u64 code);

// tuples
#define FLAG_INTERRUPT 9

static inline u64 read_flags()
{
    u64 out;
    asm("pushf");
    asm("pop %0":"=g"(out));
    return out;
}

typedef struct queue *queue;
extern queue runqueue;
extern queue bhqueue;

heap physically_backed(heap meta, heap virtual, heap physical, heap pages, u64 pagesize);
void physically_backed_dealloc_virtual(heap h, u64 x, bytes length);
void print_stack(context c);
void print_frame(context f);

typedef closure_type(fault_handler, context, context);

void configure_timer(timestamp rate, thunk t);

boolean enqueue(queue q, void *n);
void *dequeue(queue q);
void *queue_peek(queue q);
int queue_length(queue q);
queue allocate_queue(heap h, u64 size);
void deallocate_queue(queue q);

context allocate_frame(heap h);

static inline void frame_push(context new)
{
    console("frame_push: ");
    print_u64(u64_from_pointer(running_frame));
    console("\n");
    new[FRAME_SAVED_FRAME] = u64_from_pointer(running_frame);
    running_frame = new;
}

static inline void frame_pop(void)
{
    console("frame_pop: from ");
    print_u64(u64_from_pointer(running_frame));
    console(" to ");
    print_u64(running_frame[FRAME_SAVED_FRAME]);
    running_frame = pointer_from_u64(running_frame[FRAME_SAVED_FRAME]);
    console(", rip: ");
    print_u64(running_frame[FRAME_RIP]);
    console("\n");
}

#define switch_stack(__s, __target) {                   \
        asm ("mov %0, %%rdx": :"r"(__s):"%rdx");        \
        asm ("mov %0, %%rax": :"r"(__target));          \
        asm ("mov %%rdx, %%rsp"::);                     \
        asm ("jmp *%%rax"::);                           \
    }

void runloop() __attribute__((noreturn));
void kernel_sleep();
void process_bhqueue();
void install_fallback_fault_handler(fault_handler h);

// xxx - hide
struct queue {
    u64 count;
    u64 write;
    u64 read;
    u64 size;
    heap h;
    void *buf[];
};

void msi_format(u32 *address, u32 *data, int vector);
void register_interrupt(int vector, thunk t);
extern heap interrupt_vectors;
