/* main header for kernel objects */
#include <runtime.h>
#include <kernel_machine.h>
#include <kernel_heaps.h>

// belong here? share with nasm
// currently maps to the linux gdb frame layout for convenience
#include "frame.h"

#include "klib.h"

#define HUGE_PAGESIZE 0x100000000ull

typedef u64 *context;

#define KERNEL_STACK_WORDS (KERNEL_STACK_SIZE / sizeof(u64))
typedef struct kernel_context {
    u64 stackbase[KERNEL_STACK_WORDS];
    u64 frame[0];
} *kernel_context;

typedef struct nanos_thread {
    thunk pause;
} *nanos_thread;

#ifdef CONFIG_FTRACE
struct ftrace_graph_entry;
#endif

typedef struct cpuinfo {
    /*** Fields accessed by low-level entry points. ***/
    /* Don't move these without updating gs-relative accesses in crt0.s ***/

    /* For accessing cpuinfo via %gs:0; must be first */
    void *self;

    /* This points to the frame of the current, running context. +8 */
    context running_frame;

    /* Default frame and stack installed at kernel entry points (init,
       syscall) and calls to runloop. +16 */
    kernel_context kernel_context;

    /* One temporary for syscall enter to use so that we don't need to touch the user stack. +24 */
    u64 tmp;

    /*** End of fields touched by kernel entries ***/

    u32 id;
    int state;
    boolean have_kernel_lock;
    queue thread_queue;
    timestamp last_timer_update;
    u64 frcount;

    /* The following fields are used rarely or only on initialization. */

    /* Stack for exceptions (which may occur in interrupt handlers) */
    void *exception_stack;

    /* Stack for interrupts */
    void *int_stack;

#ifdef CONFIG_FTRACE
    int graph_idx;
    struct ftrace_graph_entry * graph_stack;
#endif
} *cpuinfo;

#define cpu_not_present 0
#define cpu_idle 1
#define cpu_kernel 2
#define cpu_interrupt 3
#define cpu_user 4

extern struct cpuinfo cpuinfos[];

static inline __attribute__((always_inline)) cpuinfo cpuinfo_from_id(int cpu)
{
    assert(cpu >= 0 && cpu < MAX_CPUS);
    return &cpuinfos[cpu];
}

static inline __attribute__((always_inline)) void cpu_setgs(int cpu)
{
    u64 addr = u64_from_pointer(cpuinfo_from_id(cpu));
    write_msr(KERNEL_GS_MSR, 0); /* clear user GS */
    write_msr(GS_MSR, addr);
}

static inline __attribute__((always_inline)) cpuinfo current_cpu(void)
{
    u64 addr;
    asm volatile("movq %%gs:0, %0":"=r"(addr));
    return (cpuinfo)pointer_from_u64(addr);
}

static inline __attribute__((always_inline)) boolean is_current_kernel_context(context f)
{
    return f == current_cpu()->kernel_context->frame;
}

static inline __attribute__((always_inline)) context get_running_frame(void)
{
    return current_cpu()->running_frame;
}

static inline __attribute__((always_inline)) void set_running_frame(context f)
{
    current_cpu()->running_frame = f;
}

static inline __attribute__((always_inline)) nanos_thread get_current_thread()
{
    context f = current_cpu()->kernel_context->frame;
    return pointer_from_u64(f[FRAME_THREAD]);
}

static inline __attribute__((always_inline)) void set_current_thread(nanos_thread t)
{
    context f = current_cpu()->kernel_context->frame;
    f[FRAME_THREAD] = u64_from_pointer(t);
}

static inline __attribute__((always_inline)) void *stack_from_kernel_context(kernel_context c)
{
    return ((void*)c->stackbase) + KERNEL_STACK_SIZE - STACK_ALIGNMENT;
}

void runloop_internal() __attribute__((noreturn));

static inline boolean this_cpu_has_kernel_lock(void)
{
    return current_cpu()->have_kernel_lock;
}

NOTRACE static inline __attribute__((always_inline)) __attribute__((noreturn)) void runloop(void)
{
    set_running_frame(current_cpu()->kernel_context->frame);
    switch_stack(stack_from_kernel_context(current_cpu()->kernel_context),
                 runloop_internal);
    while(1);                   /* kill warning */
}

#define BREAKPOINT_INSTRUCTION 00
#define BREAKPOINT_WRITE 01
#define BREAKPOINT_IO 10
#define BREAKPOINT_READ_WRITE 11

boolean breakpoint_insert(u64 a, u8 type, u8 length);
boolean breakpoint_remove(u32 a);

context allocate_frame(heap h);
void deallocate_frame(context);
void *allocate_stack(heap h, u64 size);
void deallocate_stack(heap h, u64 size, void *stack);
kernel_context allocate_kernel_context(heap h);
void deallocate_kernel_context(kernel_context c);
void init_kernel_contexts(heap backed);
kernel_context suspend_kernel_context(void);
void resume_kernel_context(kernel_context c);
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

#ifdef KERNEL
#define _IRQSAFE_1(rtype, name, t0)              \
    static inline rtype name ## _irqsafe (t0 a0) \
    {                                            \
        u64 flags = irq_disable_save();          \
        rtype r = name(a0);                      \
        irq_restore(flags);                      \
        return r;                                \
    }

#define _IRQSAFE_2(rtype, name, t0, t1)                 \
    static inline rtype name ## _irqsafe (t0 a0, t1 a1) \
    {                                                   \
        u64 flags = irq_disable_save();                 \
        rtype r = name(a0, a1);                         \
        irq_restore(flags);                             \
        return r;                                       \
    }

_IRQSAFE_2(boolean, enqueue, queue, void *);
_IRQSAFE_2(boolean, enqueue_single, queue, void *);

_IRQSAFE_1(void *, dequeue, queue);
_IRQSAFE_1(void *, dequeue_single, queue);

/* may not need irqsafe variants of these ... but it doesn't hurt to add */
_IRQSAFE_1(u64, queue_length, queue);
_IRQSAFE_1(boolean, queue_empty, queue);
_IRQSAFE_1(boolean, queue_full, queue);
_IRQSAFE_1(void *, queue_peek, queue);
#undef _IRQSAFE_1
#undef _IRQSAFE_2
#endif

extern queue bhqueue;
extern queue runqueue;
extern timerheap runloop_timers;

heap physically_backed(heap meta, heap virtual, heap physical, u64 pagesize);
void physically_backed_dealloc_virtual(heap h, u64 x, bytes length);
heap locking_heap_wrapper(heap meta, heap parent);

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
void install_idt(void);

#define IST_EXCEPTION 1
#define IST_INTERRUPT 2

void set_ist(int cpu, int i, u64 sp);
void install_gdt64_and_tss(u64 cpu);

void kern_lock(void);
boolean kern_try_lock(void);
void kern_unlock(void);
void init_scheduler(heap);
void mm_service(void);

kernel_heaps get_kernel_heaps(void);

tuple get_environment(void);

extern void interrupt_exit(void);
extern char **state_strings;

// static inline void schedule_frame(context f) stupid header deps
#define schedule_frame(__f)  do { assert((__f)[FRAME_QUEUE] != INVALID_PHYSICAL); assert(enqueue((queue)pointer_from_u64((__f)[FRAME_QUEUE]), pointer_from_u64((__f)[FRAME_RUN]))); } while(0)

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

/* TODO mach dep */
static inline u64 total_frame_size(void)
{
    return FRAME_EXTENDED_SAVE * sizeof(u64) + xsave_frame_size();
}

extern void xsave(context f);

extern int shutdown_vector;
