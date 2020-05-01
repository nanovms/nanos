/* main header for kernel objects */
#include <runtime.h>
#include <kernel_heaps.h>

// belong here? share with nasm
// currently maps to the linux gdb frame layout for convenience
#include "frame.h"

#define HUGE_PAGESIZE 0x100000000ull

typedef u64 *context;

context allocate_frame(heap h);
void deallocate_frame(context);

typedef struct cpuinfo {
    /*** Fields accessed by low-level entry points. Don't move them. ***/

    /* For accessing cpuinfo via %gs:0; must be first */
    void *self;

    /* This points to the frame of the current, running context. +8 */
    context running_frame;

    /* Default frame installed at kernel entry points (init, syscall)
       and calls to runloop. Used only to capture (terminal) faults
       and never returned to. +16 */
    context kernel_frame;

    /* Stack installed at kernel entry points and runloop. Offset +24. */
    void * kernel_stack;

    /* One temporary for syscall enter to use so that we don't need to touch the user stack. +32 */
    u64 tmp;

    /*** End of fields touched by kernel entries ***/

    u32 id;
    int state;
    boolean have_kernel_lock;
    u64 frcount;

    /* The following fields are used rarely or only on initialization. */

    /* Stack for page faults, switched by hardware

       This could just be the kernel stack, but we might like to have
       a safe stack to run on should we get a fault in kernel space,
       or even in an interrupt handler. */
    void *fault_stack;

    /* Stack for exceptions (aside from page fault) and interrupts,
       switched by hardware */
    void *int_stack;

    /* leaky unix stuff */
    void *current_thread;
} *cpuinfo;

#define cpu_not_present 0
#define cpu_idle 1
#define cpu_kernel 2
#define cpu_interrupt 3
#define cpu_user 4

extern struct cpuinfo cpuinfos[];

static inline cpuinfo cpuinfo_from_id(int cpu)
{
    assert(cpu >= 0 && cpu < MAX_CPUS);
    return &cpuinfos[cpu];
}

static inline void cpu_setgs(int cpu)
{
    u64 addr = u64_from_pointer(cpuinfo_from_id(cpu));
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

void runloop_internal() __attribute__((noreturn));

static inline __attribute__((noreturn)) void runloop(void)
{
    set_running_frame(current_cpu()->kernel_frame);
    switch_stack(current_cpu()->kernel_stack, runloop_internal);
    while(1);                   /* kill warning */
}

#define BREAKPOINT_INSTRUCTION 00
#define BREAKPOINT_WRITE 01
#define BREAKPOINT_IO 10
#define BREAKPOINT_READ_WRITE 11

boolean breakpoint_insert(u64 a, u8 type, u8 length);
boolean breakpoint_remove(u32 a);

void frame_return(context frame) __attribute__((noreturn));

void msi_map_vector(int slot, int msislot, int vector);

void syscall_enter(void);

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

typedef struct queue *queue;
extern queue bhqueue;
extern queue runqueue;
extern queue thread_queue;
timerheap runloop_timers;

heap physically_backed(heap meta, heap virtual, heap physical, u64 pagesize);
void physically_backed_dealloc_virtual(heap h, u64 x, bytes length);
void print_stack(context c);
void print_frame(context f);

typedef closure_type(fault_handler, context, context);

void configure_timer(timestamp rate, thunk t);

void kernel_sleep();
void kernel_delay(timestamp delta);

void init_clock(void);
boolean init_hpet(kernel_heaps kh);

void process_bhqueue();
void install_fallback_fault_handler(fault_handler h);

void msi_format(u32 *address, u32 *data, int vector);

u64 allocate_interrupt(void);
void deallocate_interrupt(u64 irq);
void register_interrupt(int vector, thunk t, const char *name);
void unregister_interrupt(int vector);
void triple_fault(void) __attribute__((noreturn));
void start_cpu(heap h, heap stackheap, int index, void (*ap_entry)());
void *allocate_stack(heap pages, u64 size);
void install_idt(void);

#define IST_INTERRUPT 1         /* for all interrupts */
#define IST_PAGEFAULT 2         /* page fault specific */

void set_ist(int cpu, int i, u64 sp);
void install_gdt64_and_tss(u64 cpu);

void kern_lock(void);
boolean kern_try_lock(void);
void kern_unlock(void);
void init_scheduler(heap);
void mm_service(void);

extern void interrupt_exit(void);
extern char **state_strings;

// static inline void schedule_frame(context f) stupid header deps
#define schedule_frame(__f)  do { assert((__f)[FRAME_QUEUE] != INVALID_PHYSICAL); enqueue((queue)pointer_from_u64((__f)[FRAME_QUEUE]), pointer_from_u64((__f)[FRAME_RUN])); } while(0)

void kernel_unlock();

extern u64 idle_cpu_mask;
extern u64 total_processors;

static inline boolean is_protection_fault(context f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_P) != 0;
}

static inline boolean is_usermode_fault(context f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_US) != 0;
}

static inline boolean is_write_fault(context f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_RW) != 0;
}

static inline boolean is_instruction_fault(context f)
{
    return (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_ID) != 0;
}

/* page table integrity check? open to interpretation for other archs... */
static inline boolean is_pte_error(context f)
{
    /* XXX check sdm before merging - seems suspicious */
    return (is_protection_fault(f) && (f[FRAME_ERROR_CODE] & FRAME_ERROR_PF_RSV));
}

static inline u64 frame_return_address(context f)
{
    return f[FRAME_RIP];
}

static inline u64 fault_address(context f)
{
    return f[FRAME_CR2];
}

static inline u64 total_frame_size(void)
{
    return FRAME_EXTENDED_SAVE * sizeof(u64) + xsave_frame_size();
}

extern int shutdown_vector;
