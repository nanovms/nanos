#pragma once

#define STACK_ALIGNMENT     16
#define KERNEL_STACK_PAGES  32
#define FAULT_STACK_PAGES   8
#define INT_STACK_PAGES     8
#define BH_STACK_PAGES      8
#define SYSCALL_STACK_PAGES 8

#define VIRTUAL_ADDRESS_BITS 48

#define KERNEL_CODE_SELECTOR 0x08
#define USER_CODE32_SELECTOR 0x18

#define TSC_DEADLINE_MSR 0x6e0

#define EFER_MSR         0xc0000080
#define EFER_SCE         0x0001
#define EFER_LME         0x0100
#define EFER_LMA         0x0400
#define EFER_NXE         0x0800
#define EFER_SVME        0x1000
#define EFER_LMSLE       0x2000
#define EFER_FFXSR       0x4000
#define EFER_TCE         0x8000
#define STAR_MSR         0xc0000081
#define LSTAR_MSR        0xc0000082
#define SFMASK_MSR       0xc0000084

#define FS_MSR           0xc0000100
#define GS_MSR           0xc0000101
#define KERNEL_GS_MSR    0xc0000102

#define C0_WP   0x00010000

#define FLAG_INTERRUPT 9

static inline void compiler_barrier(void)
{
    asm volatile("" ::: "memory");
}

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

context allocate_frame(heap h);

typedef struct cpuinfo {
    /* For accessing cpuinfo via %gs:0; must be first */
    void * self;

    /* This points to the frame of the current, running context. Entry
       points expect this to be the second (+8) field here. */
    context running_frame;

    /* syscall_enter switches to this stack before calling syscall. It
       must be the third field (+16). */
    void * syscall_stack;

    /* common_handler switches to this stack when calling process_bhqueue */
    void * bh_stack;

    /* The default frame for when we're not in a thread or bh context. */
    context misc_frame;

    /* for bh processing, where page faults must be supported */
    context bh_frame;

    u32 id;
    boolean in_bh;              /* temporary, probably bh will go away? */
    boolean in_int;             /* to catch exceptions during int processing */
    volatile boolean online;
    volatile boolean ipi_wakeup;

    /* The following fields are used rarely or only on initialization. */

    /* stack for page faults, switched by hardware */
    void * fault_stack;

    /* stack for int handlers, switched by hardware */
    void * int_stack;
} *cpuinfo;

extern struct cpuinfo cpuinfos[];

static inline void cpu_setgs(int cpu)
{
    u64 addr = u64_from_pointer(&cpuinfos[cpu]);
    write_msr(KERNEL_GS_MSR, 0); /* clear user GS */
    write_msr(GS_MSR, addr);
}

static inline cpuinfo current_cpu(void)
{
    u64 addr;
    asm volatile("movq %%gs:0, %0":"=r"(addr));
    return (cpuinfo)pointer_from_u64(addr);
}

static inline context get_running_frame(void)
{
    return current_cpu()->running_frame;
}

static inline void set_running_frame(context f)
{
    current_cpu()->running_frame = f;
}

static inline void frame_push(context new)
{
    new[FRAME_SAVED_FRAME] = u64_from_pointer(get_running_frame());
    set_running_frame(new);
}

static inline void frame_push_keep_handler(context new)
{
    // XXX check asm for no gs repeat
    new[FRAME_FAULT_HANDLER] = get_running_frame()[FRAME_FAULT_HANDLER];
    frame_push(new);
}

static inline void frame_pop(void)
{
    set_running_frame(pointer_from_u64(get_running_frame()[FRAME_SAVED_FRAME]));
}

#define switch_stack(__s, __target) {                           \
        asm volatile("mov %0, %%rdx": :"r"(__s):"%rdx");        \
        asm volatile("mov %0, %%rax": :"r"(__target));          \
        asm volatile("mov %%rdx, %%rsp"::);                     \
        asm volatile("jmp *%%rax"::);                           \
    }

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
    asm volatile("sfence" ::: "memory");
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
    write_msr(LSTAR_MSR, u64_from_pointer(syscall_entry));
    u32 selectors = ((USER_CODE32_SELECTOR | 0x3) << 16) | KERNEL_CODE_SELECTOR;
    write_msr(STAR_MSR, (u64)selectors << 32);
    write_msr(SFMASK_MSR, U64_FROM_BIT(FLAG_INTERRUPT));
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
}

static inline void set_page_write_protect(boolean enable)
{
    word cr0;
    mov_from_cr("cr0", cr0);
    cr0 = enable ? (cr0 | C0_WP) : (cr0 & ~C0_WP);
    mov_to_cr("cr0", cr0);
}


static inline u64 read_flags(void)
{
    u64 out;
    asm volatile("pushfq");
    asm volatile("popq %0":"=g"(out));
    return out;
}

static inline u64 irq_disable_save(void)
{
    u64 flags = read_flags();
    disable_interrupts();
    return flags;
}

static inline void irq_restore(u64 flags)
{
    if ((flags & U64_FROM_BIT(FLAG_INTERRUPT)))
        enable_interrupts();
}

static inline void kern_pause(void)
{
    asm volatile("pause");
}

#include <vdso.h>
#define __vdso_dat (&(VVAR_REF(vdso_dat)))

static inline u64
_rdtscp(void)
{
    u32 a, d;
    asm volatile("rdtscp" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

static inline u64
_rdtsc(void)
{
    u32 a, d;
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

static inline u64
rdtsc(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();
    return _rdtsc();
}

static inline u64
rdtsc_precise(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();

    asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx"); /* serialize execution */
    return _rdtsc();
}

#undef __vdso_dat

typedef struct queue *queue;
extern queue runqueue;
extern queue bhqueue;
extern queue deferqueue;

heap physically_backed(heap meta, heap virtual, heap physical, heap pages, u64 pagesize);
void physically_backed_dealloc_virtual(heap h, u64 x, bytes length);
void print_stack(context c);
void print_frame(context f);

typedef closure_type(fault_handler, context, context);

void configure_timer(timestamp rate, thunk t);

void runloop() __attribute__((noreturn));
void kernel_sleep();
void kernel_delay(timestamp delta);

void init_clock(void);
boolean init_hpet(kernel_heaps kh);

void process_bhqueue();
void install_fallback_fault_handler(fault_handler h);

void msi_format(u32 *address, u32 *data, int vector);

u64 allocate_interrupt(void);
void deallocate_interrupt(u64 irq);
void register_interrupt(int vector, thunk t);
void unregister_interrupt(int vector);
void triple_fault(void) __attribute__((noreturn));
void start_cpu(heap h, heap pages, int index, void (*ap_entry)());
void * allocate_stack(heap pages, int npages);
void install_idt(void);

#define IST_INTERRUPT 1         /* for all interrupts */
#define IST_PAGEFAULT 2         /* page fault specific */

void set_ist(int cpu, int i, u64 sp);
void install_gdt64_and_tss(u64 cpu);

static inline void wake_cpu(int cpu)
{
    // XXX send ipi
}

void kern_lock(void);
void kern_unlock(void);
