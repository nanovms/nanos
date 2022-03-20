/* main header for kernel objects */
#include <runtime.h>
#include <kernel_heaps.h>
#ifdef KERNEL
#include <debug.h>
#endif

#ifdef KERNEL
void runloop_target(void) __attribute__((noreturn));
#endif

#include <kernel_machine.h>

#ifdef CONFIG_TRACELOG
#include <tracelog.h>
#else
void tprintf(symbol tag, tuple attrs, const char *format, ...);
#endif

//#define CONTEXT_DEBUG
#ifdef CONTEXT_DEBUG
#define context_debug(x, ...) do {tprintf(sym(context), 0, x, ##__VA_ARGS__);} while(0)
#else
#define context_debug(x, ...)
#endif

/* per-cpu info, saved contexts and stacks */
declare_closure_struct(1, 0, void, kernel_context_return,
                       struct kernel_context *, kc);

declare_closure_struct(3, 0, void, free_kernel_context,
                       struct kernel_context *, kc, cpuinfo, orig_ci, boolean, queued);

typedef struct kernel_context {
    struct context context;
    closure_struct(kernel_context_return, kernel_return);
    closure_struct(free_kernel_context, free);
} *kernel_context;

#include <management.h>
#include <page.h>
#include "klib.h"

#define cpu_not_present 0
#define cpu_idle 1
#define cpu_kernel 2
#define cpu_interrupt 3
#define cpu_user 4

extern boolean shutting_down;

/* per-cpu, architecture-independent invariants */
typedef struct cpuinfo *cpuinfo;

struct cpuinfo {
    struct cpuinfo_machine m;
    u32 id;
    int state;
    queue cpu_queue;
    queue thread_queue;
    timestamp last_timer_update;
    u64 frcount;
    u64 inval_gen; /* Generation number for invalidates */

    cpuinfo mcs_prev;
    cpuinfo mcs_next;
    boolean mcs_waiting;

    /* multiple producers, single consumer */
    queue free_kernel_contexts;
    queue free_syscall_contexts;
#ifdef CONFIG_FTRACE
    int graph_idx;
    struct ftrace_graph_entry * graph_stack;
#endif
#ifdef CONFIG_TRACELOG
    void *tracelog_buffer;
#endif
};

extern vector cpuinfos;

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

extern const char *context_type_strings[CONTEXT_TYPE_MAX];

static inline boolean is_kernel_context(context c)
{
    return c->type == CONTEXT_TYPE_KERNEL;
}

static inline boolean is_syscall_context(context c)
{
    return c->type == CONTEXT_TYPE_SYSCALL;
}

static inline boolean is_thread_context(context c)
{
    return c->type == CONTEXT_TYPE_THREAD;
}

static inline __attribute__((always_inline)) context get_current_context(cpuinfo ci)
{
    return ci->m.current_context;
}

static inline __attribute__((always_inline)) void set_current_context(cpuinfo ci, context c)
{
    ci->m.current_context = c;
}

#ifdef KERNEL
extern queue bhqueue;
extern queue runqueue;
extern queue async_queue_1;
extern timerqueue kernel_timers;
extern thunk timer_interrupt_handler;

typedef closure_type(async_1, void, u64);

typedef struct applied_async_1 {
    async_1 a;
    u64 arg0;
} *applied_async_1;

static inline boolean async_apply_1(void *a, void *arg0)
{
    struct applied_async_1 aa;
    aa.a = a;
    aa.arg0 = u64_from_pointer(arg0);
    return enqueue_n_irqsafe(async_queue_1, &aa, sizeof(aa) / sizeof(u64));
}
#define async_apply_status_handler async_apply_1

#define CONTEXT_RESUME_SPIN_LIMIT (1ull << 24)

void init_context_machine(context c);
kernel_context allocate_kernel_context(cpuinfo ci);
void deallocate_kernel_context(kernel_context kc);
void init_kernel_contexts(heap backed);
void frame_return(context_frame f);

#define CONTEXT_FRAME_SIZE (FRAME_SIZE * sizeof(u64))

static inline void zero_context_frame(context_frame f)
{
    zero(f, CONTEXT_FRAME_SIZE);
}

static inline void init_context(context c, int type)
{
    c->type = type;
    c->transient_heap = 0;
    c->waiting_on = 0;
    list_init_member(&c->mutex_l);
    c->active_cpu = -1;
    zero_context_frame(c->frame);
    init_context_machine(c);
}

static inline void __attribute__((always_inline)) context_reserve_refcount(context ctx)
{
    refcount_reserve(&ctx->refcount);
}

static inline void __attribute__((always_inline)) context_release_refcount(context ctx)
{
    refcount_release(&ctx->refcount);
}

static inline void __attribute__((always_inline)) context_acquire(context ctx, cpuinfo ci)
{
    context_debug("%s: ctx %p, cpu %d\n", __func__, ctx, ci->id);
    assert(ctx->active_cpu != ci->id);
    u64 remain = CONTEXT_RESUME_SPIN_LIMIT;
    while (ctx->active_cpu != -1u) {
        kern_pause();
        assert(remain-- > 0);
    }
    ctx->active_cpu = ci->id;
    context_debug("%s: ctx %p, cpu %d acquired\n", __func__, ctx, ci->id);
}

static inline void __attribute__((always_inline)) context_release(context ctx)
{
    if (shutting_down)
        return;
    if (ctx->active_cpu == -1u)
        halt("%s: already paused c %p, type %d\n", __func__, ctx, ctx->type);
    assert(ctx->active_cpu == current_cpu()->id); /* XXX tmp for bringup */
    ctx->active_cpu = -1u;
}

static inline void __attribute__((always_inline)) context_pause(context ctx)
{
    context_debug("%s: ctx %p\n", __func__, ctx);
    if (shutting_down)
        return;
    if (ctx->pause)
        ctx->pause(ctx);
}

static inline void __attribute__((always_inline)) context_resume(context ctx)
{
    context_debug("%s: ctx %p\n", __func__, ctx);
    cpuinfo ci = current_cpu();
    if (!shutting_down)
        context_acquire(ctx, ci);
    set_current_context(ci, ctx);
    if (!shutting_down && ctx->resume)
        ctx->resume(ctx);
}

static inline void context_pre_suspend(context ctx)
{
    if (ctx->pre_suspend)
        ctx->pre_suspend(ctx);
}

void context_suspend(void);

static inline void context_schedule_return(context ctx)
{
    assert(ctx->schedule_return);
    ctx->schedule_return(ctx);
}

static inline void context_reschedule(context ctx)
{
    context_debug("%s: suspend ctx %p, cpu %d\n", __func__, ctx, current_cpu()->id);
    context_pre_suspend(ctx);
    context_schedule_return(ctx);
    context_suspend();
    context_debug("%s: resume ctx %p, cpu %d\n", __func__, ctx, current_cpu()->id);
}

void __attribute__((noreturn)) context_switch_finish(context prev, context next, void *a, u64 arg0, u64 arg1);

/* TODO: make into varargs / macro to avoid unneeded arg copies */
static inline void __attribute__((always_inline)) __attribute__((noreturn))
context_switch_and_branch(context ctx, void * a, u64 arg0, u64 arg1)
{
    cpuinfo ci = current_cpu();
    context prev = get_current_context(ci);
    context_debug("%s: prev %p, next %p, a %p, arg0 0x%lx, arg1 0x%lx\n",
                  __func__, prev, ctx, a, arg0, arg1);
    if (ctx != prev) {
        context_pause(prev);
        if (!shutting_down)
            context_acquire(ctx, ci);
    }
    switch_stack_5(frame_get_stack_top(ctx->frame), context_switch_finish, prev, ctx, a, arg0, arg1);
    while(1);                   /* kill warning */
}

static inline void __attribute__((always_inline)) context_switch(context ctx)
{
    assert(ctx);
    cpuinfo ci = current_cpu();
    context prev = get_current_context(ci);
    if (ctx != prev) {
        context_pause(prev);
        context_resume(ctx);
        context_release(prev);
    }
}

static inline void use_fault_handler(fault_handler h)
{
    context ctx = get_current_context(current_cpu());
    assert(is_kernel_context(ctx));
    assert(!frame_is_full(ctx->frame));
    assert(!ctx->fault_handler);
    ctx->fault_handler = h;
}

static inline void clear_fault_handler(void)
{
    context ctx = get_current_context(current_cpu());
    ctx->fault_handler = 0;
}

// XXX enable this later after checking existing uses of transient
// #define transient (get_current_context(current_cpu())->transient)

#define contextual_closure(__name, ...) ({                              \
            context __ctx = get_current_context(current_cpu());         \
            context_debug("contextual_closure(%s, ...) ctx %p type %d\n", #__name, __ctx, __ctx->type); \
            heap __h = __ctx->transient_heap;                           \
            struct _closure_##__name * __n = allocate(__h, sizeof(struct _closure_##__name)); \
            __closure((u64_from_pointer(__ctx) |                        \
                       (CLOSURE_COMMON_CTX_DEALLOC_ON_FINISH | CLOSURE_COMMON_CTX_IS_CONTEXT)), \
                      __n, sizeof(struct _closure_##__name), __name, ##__VA_ARGS__);}) 

#define contextual_closure_alloc(__name, __var) \
    do {                                                                \
        context __ctx = get_current_context(current_cpu());             \
        context_debug("contextual_closure_alloc(%s, ...) ctx %p\n", #__name, __ctx); \
        heap __h = __ctx->transient_heap;                               \
        __var = allocate(__h, sizeof(struct _closure_##__name));        \
        if (__var != INVALID_ADDRESS) {                                 \
            __var->__apply = __name;                                    \
            __var->__c.name = #__name;                                  \
            __var->__c.ctx = ctx_from_context(__ctx);                   \
            __var->__c.size = sizeof(struct _closure_##__name);         \
        }                                                               \
    } while (0);

static inline boolean is_contextual_closure(void *p)
{
    struct _closure_common *c = p + sizeof(void *); /* skip __apply */
    return (c->ctx & CLOSURE_COMMON_CTX_IS_CONTEXT) != 0;
}

static inline context context_from_closure(void *p)
{
    struct _closure_common *c = p + sizeof(void *); /* skip __apply */
    return (c->ctx & CLOSURE_COMMON_CTX_IS_CONTEXT) ?
        pointer_from_u64(c->ctx & ~CLOSURE_COMMON_CTX_FLAGS_MASK) : 0;
}

/* not for allocated closures */
static inline void *apply_context_to_closure(void *p, context ctx)
{
    struct _closure_common *c = p + sizeof(void *); /* skip __apply */
    assert(c->ctx == 0);
    c->ctx = u64_from_pointer(ctx) | CLOSURE_COMMON_CTX_IS_CONTEXT;
    return p;
}

static inline void count_minor_fault(void)
{
    fetch_and_add(&mm_stats.minor_faults, 1);
}

static inline void count_major_fault(void)
{
    fetch_and_add(&mm_stats.major_faults, 1);
}

void runloop_internal(void) __attribute__((noreturn));

NOTRACE static inline __attribute__((always_inline)) __attribute__((noreturn)) void runloop(void)
{
    cpuinfo ci = current_cpu();
    context ctx = ci->m.kernel_context;
    context_switch_and_branch(ctx, runloop_internal, 0, 0);
}

/* call with ints disabled */
static inline void context_apply(context ctx, thunk t)
{
    assert(ctx->type != CONTEXT_TYPE_KERNEL);
    context_switch_and_branch(ctx, *(void**)t, u64_from_pointer(t), 0);
}

static inline void context_apply_1(context ctx, async_1 a, u64 arg0)
{
    assert(ctx->type != CONTEXT_TYPE_KERNEL);
    context_switch_and_branch(ctx, *(void**)a, u64_from_pointer(a), arg0);
}

static inline __attribute__((always_inline))  __attribute__((noreturn)) void kern_yield(void)
{
    runloop();
}

static inline void schedule_timer_service(void)
{
    if (compare_and_swap_boolean(&kernel_timers->service_scheduled, false, true))
        enqueue(bhqueue, kernel_timers->service);
}
#endif /* KERNEL */

#define BREAKPOINT_INSTRUCTION 00
#define BREAKPOINT_WRITE 01
#define BREAKPOINT_IO 10
#define BREAKPOINT_READ_WRITE 11

#define BOOTSTRAP_BASE  KMEM_BASE

u64 init_bootstrap_heap(u64 phys_length);
id_heap init_physical_id_heap(heap h);
void init_kernel_heaps(void);
void init_platform_devices(kernel_heaps kh);
void init_cpuinfo_machine(cpuinfo ci, heap backed);
void kernel_runtime_init(kernel_heaps kh);
void read_kernel_syms(void);
void reclaim_regions(void);

boolean breakpoint_insert(heap h, u64 a, u8 type, u8 length, thunk completion);
boolean breakpoint_remove(heap h, u32 a, thunk completion);
void destruct_context(context c);
void *allocate_stack(heap h, u64 size);
void deallocate_stack(heap h, u64 size, void *stack);
cpuinfo init_cpuinfo(heap backed, int cpu);
void init_interrupts(kernel_heaps kh);
void msi_map_vector(int slot, int msislot, int vector);

void print_frame_trace(u64 *fp);
void print_frame_trace_from_here(void);

void syscall_enter(void);

backed_heap mem_debug_backed(heap m, backed_heap bh, u64 padsize, boolean nohdr);

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

#if !defined(BOOT)

heap allocate_tagged_region(kernel_heaps kh, u64 tag, bytes pagesize);
heap locking_heap_wrapper(heap meta, heap parent);

#endif

void dump_context(context c);

void configure_timer(timestamp rate, thunk t);

void kernel_sleep();
void kernel_delay(timestamp delta);
timestamp kern_now(clock_id id);    /* klibs must use this instead of now() */

void init_clock(void);

void process_bhqueue();

void msi_format(u32 *address, u32 *data, int vector);

u64 allocate_ipi_interrupt(void);
void deallocate_ipi_interrupt(u64 irq);
void register_interrupt(int vector, thunk t, const char *name);
void unregister_interrupt(int vector);

u64 allocate_shirq(void);
void register_shirq(int vector, thunk t, const char *name);

boolean dev_irq_enable(u32 dev_id, int vector);
void dev_irq_disable(u32 dev_id, int vector);

static inline boolean in_interrupt(void)
{
    return current_cpu()->state == cpu_interrupt;
}

void init_scheduler(heap);
void init_scheduler_cpus(heap h);
void mm_service(void);

typedef closure_type(balloon_deflater, u64, u64);
void mm_register_balloon_deflater(balloon_deflater deflater);

kernel_heaps get_kernel_heaps(void);

static inline boolean is_low_memory_machine(kernel_heaps kh)
{
    return (heap_total((heap)heap_physical(kh)) < LOW_MEMORY_THRESHOLD);
}

struct filesystem *get_root_fs(void);
tuple get_root_tuple(void);
tuple get_environment(void);
void register_root_notify(symbol s, set_value_notify n);

boolean first_boot(void);

extern void interrupt_exit(void);
extern const char * const * const state_strings;

void kernel_unlock();

extern bitmap idle_cpu_mask;
extern u64 total_processors;
extern u64 present_processors;

void cpu_init(int cpu);
void start_secondary_cores(kernel_heaps kh);
void count_cpus_present(void);
void detect_hypervisor(kernel_heaps kh);
void detect_devices(kernel_heaps kh, storage_attach sa);

typedef closure_type(shutdown_handler, void, int, merge);
void add_shutdown_completion(shutdown_handler h);
extern int shutdown_vector;
void wakeup_or_interrupt_cpu_all();

typedef closure_type(halt_handler, void, int);
extern halt_handler vm_halt;

void early_debug(const char *s);
void early_debug_u64(u64 n);
void early_dump(void *p, unsigned long length);
