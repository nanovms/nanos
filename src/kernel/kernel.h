/* main header for kernel objects */
#include <runtime.h>
#include <kernel_heaps.h>
#include <kernel_machine.h>
#include <management.h>
#include <page.h>
#include "klib.h"

typedef struct nanos_thread {
    thunk pause;
} *nanos_thread;

#define cpu_not_present 0
#define cpu_idle 1
#define cpu_kernel 2
#define cpu_interrupt 3
#define cpu_user 4

/* per-cpu, architecture-independent invariants */
typedef struct cpuinfo {
    struct cpuinfo_machine m;
    u32 id;
    int state;
    boolean have_kernel_lock;
    queue thread_queue;
    timestamp last_timer_update;
    u64 frcount;
    u64 inval_gen; /* Generation number for invalidates */
    queue cpu_queue;
#ifdef CONFIG_FTRACE
    int graph_idx;
    struct ftrace_graph_entry * graph_stack;
#endif
} *cpuinfo;

typedef closure_type(fault_handler, context, context);

extern vector cpuinfos;

/* subsume with introspection */
struct mm_stats {
    word minor_faults;
    word major_faults;
};

extern struct mm_stats mm_stats;

static inline cpuinfo cpuinfo_from_id(int cpu)
{
    return vector_get(cpuinfos, cpu);
}

static inline boolean is_current_kernel_context(context f)
{
    return f == current_cpu()->m.kernel_context->frame;
}

static inline boolean in_interrupt(void)
{
    return current_cpu()->state == cpu_interrupt;
}

static inline __attribute__((always_inline)) context get_running_frame(cpuinfo ci)
{
    return ci->m.running_frame;
}

static inline __attribute__((always_inline)) void set_running_frame(cpuinfo ci, context f)
{
    ci->m.running_frame = f;
}

static inline __attribute__((always_inline)) kernel_context get_kernel_context(cpuinfo ci)
{
    return ci->m.kernel_context;
}

static inline __attribute__((always_inline)) void set_kernel_context(cpuinfo ci, kernel_context kc)
{
    ci->m.kernel_context = kc;
}

static inline __attribute__((always_inline)) nanos_thread get_current_thread()
{
    context f = current_cpu()->m.kernel_context->frame;
    return pointer_from_u64(f[FRAME_THREAD]);
}

static inline __attribute__((always_inline)) void set_current_thread(nanos_thread t)
{
    context f = current_cpu()->m.kernel_context->frame;
    f[FRAME_THREAD] = u64_from_pointer(t);
}

static inline __attribute__((always_inline)) context frame_from_kernel_context(kernel_context c)
{
    return c->frame;
}

static inline __attribute__((always_inline)) void *stack_from_kernel_context(kernel_context c)
{
    return ((void*)c->stackbase) + KERNEL_STACK_SIZE - STACK_ALIGNMENT;
}

static inline __attribute__((always_inline)) void set_fault_handler(kernel_context kc, fault_handler h)
{
    context f = frame_from_kernel_context(kc);
    f[FRAME_FAULT_HANDLER] = u64_from_pointer(h);
}

static inline void count_minor_fault(void)
{
    fetch_and_add(&mm_stats.minor_faults, 1);
}

static inline void count_major_fault(void)
{
    fetch_and_add(&mm_stats.major_faults, 1);
}

void runloop_internal() __attribute__((noreturn));

NOTRACE static inline __attribute__((always_inline)) __attribute__((noreturn)) void runloop(void)
{
    cpuinfo ci = current_cpu();
    kernel_context kc = get_kernel_context(ci);
    set_running_frame(ci, frame_from_kernel_context(kc));
    switch_stack(stack_from_kernel_context(kc), runloop_internal);
    while(1);                   /* kill warning */
}

#define BREAKPOINT_INSTRUCTION 00
#define BREAKPOINT_WRITE 01
#define BREAKPOINT_IO 10
#define BREAKPOINT_READ_WRITE 11

void init_cpuinfo_machine(cpuinfo ci, heap backed);
void kernel_runtime_init(kernel_heaps kh);
void read_kernel_syms(void);
void reclaim_regions(void);

boolean breakpoint_insert(heap h, u64 a, u8 type, u8 length, thunk completion);
boolean breakpoint_remove(heap h, u32 a, thunk completion);

context allocate_frame(heap h);
void deallocate_frame(context);
void *allocate_stack(heap h, u64 size);
void deallocate_stack(heap h, u64 size, void *stack);
cpuinfo init_cpuinfo(heap backed, int cpu);
kernel_context allocate_kernel_context(heap h);
void deallocate_kernel_context(kernel_context c);
void init_kernel_contexts(heap backed);
boolean kernel_suspended(void);
kernel_context suspend_kernel_context(void);
void resume_kernel_context(kernel_context c);
void frame_return(context frame) __attribute__((noreturn));

void init_interrupts(kernel_heaps kh);
void msi_map_vector(int slot, int msislot, int vector);

void syscall_enter(void);

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

#define _IRQSAFE_3(rtype, name, t0, t1, t2)                     \
    static inline rtype name ## _irqsafe (t0 a0, t1 a1, t2 a2)  \
    {                                                           \
        u64 flags = irq_disable_save();                         \
        rtype r = name(a0, a1, a2);                             \
        irq_restore(flags);                                     \
        return r;                                               \
    }

_IRQSAFE_2(boolean, enqueue, queue, void *);
_IRQSAFE_2(boolean, enqueue_single, queue, void *);

_IRQSAFE_1(void *, dequeue, queue);
_IRQSAFE_1(void *, dequeue_single, queue);

_IRQSAFE_3(boolean, enqueue_n, queue, void *, int);
_IRQSAFE_3(boolean, enqueue_n_single, queue, void *, int);

_IRQSAFE_3(boolean, dequeue_n, queue, void **, int);
_IRQSAFE_3(boolean, dequeue_n_single, queue, void **, int);

/* may not need irqsafe variants of these ... but it doesn't hurt to add */
_IRQSAFE_1(u64, queue_length, queue);
_IRQSAFE_1(boolean, queue_empty, queue);
_IRQSAFE_1(boolean, queue_full, queue);
_IRQSAFE_1(void *, queue_peek, queue);
#undef _IRQSAFE_1
#undef _IRQSAFE_2

/* Acquires 2 locks, guarding against potential deadlock resulting from a concurrent thread trying
 * to acquire the same locks. */
static inline void spin_lock_2(spinlock l1, spinlock l2)
{
    spin_lock(l1);
    while (!spin_try(l2)) {
        spin_unlock(l1);
        kern_pause();
        spin_lock(l1);
    }
}

#endif

typedef struct queue *queue;
extern queue bhqueue;
extern queue bhqueue_async_1;
extern queue runqueue;
extern queue runqueue_async_1;
extern timerqueue kernel_timers;
extern thunk timer_interrupt_handler;

backed_heap mem_debug_backed(heap m, backed_heap bh, u64 padsize);

backed_heap allocate_page_backed_heap(heap meta, heap virtual, heap physical,
                                      u64 pagesize, boolean locking);
void page_backed_dealloc_virtual(backed_heap bh, u64 x, bytes length);

backed_heap allocate_linear_backed_heap(heap meta, id_heap physical);

static inline boolean is_linear_backed_address(u64 address)
{
    return address >= LINEAR_BACKED_BASE && address < LINEAR_BACKED_LIMIT;
}

static inline boolean intersects_linear_backed(range r)
{
    return ranges_intersect(r, irange(LINEAR_BACKED_BASE, LINEAR_BACKED_LIMIT));
}

static inline u64 virt_from_linear_backed_phys(u64 address)
{
    assert(address < LINEAR_BACKED_BASE);
    return address | LINEAR_BACKED_BASE;
}

static inline u64 phys_from_linear_backed_virt(u64 virt)
{
    return virt & ~LINEAR_BACKED_BASE;
}

void unmap_and_free_phys(u64 virtual, u64 length);

static inline void bhqueue_enqueue_irqsafe(thunk t)
{
    /* an interrupted enqueue and competing enqueue from int handler could cause a
       deadlock; disable ints for safe enqueue from any context */
    u64 flags = irq_disable_save();
    enqueue(bhqueue, t);
    irq_restore(flags);
}

static inline void schedule_timer_service(void)
{
    if (compare_and_swap_boolean(&kernel_timers->service_scheduled, false, true))
        enqueue(bhqueue, kernel_timers->service);
}

#if !defined(BOOT)

heap allocate_tagged_region(kernel_heaps kh, u64 tag);
heap locking_heap_wrapper(heap meta, heap parent);

#endif

void print_stack(context c);
void print_frame(context f);

void configure_timer(timestamp rate, thunk t);

void kernel_sleep();
void kernel_delay(timestamp delta);
timestamp kern_now(clock_id id);    /* klibs must use this instead of now() */

void init_clock(void);

void process_bhqueue();
void install_fallback_fault_handler(fault_handler h);

void msi_format(u32 *address, u32 *data, int vector);

u64 allocate_ipi_interrupt(void);
void deallocate_ipi_interrupt(u64 irq);
void register_interrupt(int vector, thunk t, const char *name);
void unregister_interrupt(int vector);

u64 allocate_shirq(void);
void register_shirq(int vector, thunk t, const char *name);

void kern_lock(void);
boolean kern_try_lock(void);
void kern_unlock(void);
void init_scheduler(heap);
void init_scheduler_cpus(heap h);
void mm_service(void);

typedef closure_type(balloon_deflater, u64, u64);
void mm_register_balloon_deflater(balloon_deflater deflater);

kernel_heaps get_kernel_heaps(void);

struct filesystem *get_root_fs(void);
tuple get_root_tuple(void);
tuple get_environment(void);
void register_root_notify(symbol s, set_value_notify n);

boolean first_boot(void);

extern void interrupt_exit(void);
extern char **state_strings;

// static inline void schedule_frame(context f) stupid header deps
#define schedule_frame(___f)  do { context __f = ___f; assert((__f)[FRAME_QUEUE] != INVALID_PHYSICAL); if ((__f)[FRAME_THREAD]) apply(((nanos_thread)(__f)[FRAME_THREAD])->pause); assert(enqueue_irqsafe((queue)pointer_from_u64((__f)[FRAME_QUEUE]), pointer_from_u64((__f)[FRAME_RUN]))); } while(0)

void kernel_unlock();

extern bitmap idle_cpu_mask;
extern u64 total_processors;
extern u64 present_processors;
extern void xsave(context f);

void cpu_init(int cpu);
void start_secondary_cores(kernel_heaps kh);
void count_cpus_present(void);
void detect_hypervisor(kernel_heaps kh);
void detect_devices(kernel_heaps kh, storage_attach sa);

typedef closure_type(shutdown_handler, void, int, merge);
void add_shutdown_completion(shutdown_handler h);
extern int shutdown_vector;
extern boolean shutting_down;
void wakeup_or_interrupt_cpu_all();

typedef closure_type(halt_handler, void, int);
extern halt_handler vm_halt;

void early_debug(const char *s);
void early_debug_u64(u64 n);
void early_dump(void *p, unsigned long length);

#ifdef KERNEL
typedef closure_type(async_1, void, u64);

typedef struct applied_async_1 {
    async_1 a;
    u64 arg0;
} *applied_async_1;

static inline boolean async_apply_1(async_1 a, queue q, void *arg0)
{
    struct applied_async_1 aa;
    aa.a = a;
    aa.arg0 = u64_from_pointer(arg0);
    return enqueue_n_irqsafe(q, &aa, sizeof(aa) / sizeof(u64));
}

#define async_apply_status_handler async_apply_1
#endif
