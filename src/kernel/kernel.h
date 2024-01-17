/* main header for kernel objects */
#include <runtime.h>
#include <kernel_heaps.h>
#ifdef KERNEL
#include <debug.h>
#endif

typedef closure_type(cmdline_handler, void, const char *, int);

#ifdef KERNEL
void runloop_target(void) __attribute__((noreturn));
#endif

#include <kernel_machine.h>

#include <log.h>
#ifdef CONFIG_TRACELOG
#include <tracelog.h>
#else
void tprintf(symbol tag, tuple attrs, sstring format, ...);
#endif

#ifdef LOCK_STATS
#include <lockstats.h>
#endif

//#define CONTEXT_DEBUG
#ifdef CONTEXT_DEBUG
#define context_debug(x, ...) do {tprintf(sym(context), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define context_debug(x, ...)
#endif

/* per-cpu info, saved contexts and stacks */
declare_closure_struct(0, 0, void, kernel_context_return);

declare_closure_struct(2, 0, void, free_kernel_context,
                       queue, free_ctx_q, boolean, queued);

typedef struct kernel_context {
    struct context context;
    closure_struct(kernel_context_return, kernel_return);
    closure_struct(free_kernel_context, free);
    u64 size;
    u64 err_frame[ERR_FRAME_SIZE];  /* must contain all callee-saved registers */
} *kernel_context;

void init_kernel_context(kernel_context kc, int type, int size, queue free_ctx_q);

#include <management.h>
#include <page.h>
#include "klib.h"

#define cpu_not_present 0
#define cpu_idle 1
#define cpu_kernel 2
#define cpu_interrupt 3
#define cpu_user 4

extern u32 shutting_down;

#define SHUTDOWN_POWER   (1<<0) // shutdown triggered externally
#define SHUTDOWN_ONGOING (1<<1) // process termination already triggered

void kernel_powerdown(void);

typedef struct sched_task {
    thunk t;
    timestamp runtime;
} *sched_task;

typedef struct sched_queue {
    pqueue q;
    timestamp min_runtime;
    struct spinlock lock;
} *sched_queue;

/* per-cpu, architecture-independent invariants */
typedef struct cpuinfo *cpuinfo;

struct cpuinfo {
    struct cpuinfo_machine m;
    u32 id;
    int state;
    queue cpu_queue;
    struct sched_queue thread_queue;
    timestamp last_timer_update;
    u64 frcount;
    u64 inval_gen; /* Generation number for invalidates */

    cpuinfo mcs_prev;
    cpuinfo mcs_next;
    boolean mcs_waiting;

    /* multiple producers, single consumer */
    queue free_kernel_contexts;
    queue free_syscall_contexts;
    queue free_process_contexts;
#ifdef CONFIG_FTRACE
    int graph_idx;
    struct ftrace_graph_entry * graph_stack;
#endif
#ifdef CONFIG_TRACELOG
    void *tracelog_buffer;
#endif
#ifdef LOCK_STATS
    boolean lock_stats_disable;
    table lock_stats_table;
    heap lock_stats_heap;
#endif
};

extern vector cpuinfos;

#if defined(KERNEL) && defined(SMP_ENABLE)
static inline boolean spin_try(spinlock l)
{
    boolean success = compare_and_swap_64(&l->w, 0, 1);
#ifdef LOCK_STATS
    LOCKSTATS_RECORD_LOCK(l->s, success, 0, 0);
#endif
    return success;
}

static inline void spin_lock(spinlock l)
{
    volatile u64 *p = (volatile u64 *)&l->w;
#ifdef LOCK_STATS
    u64 spins = 0;
    while (*p || !compare_and_swap_64(&l->w, 0, 1)) {
        spins++;
        kern_pause();
    }
    LOCKSTATS_RECORD_LOCK(l->s, true, spins, 0);
#else
    while (*p || !compare_and_swap_64(&l->w, 0, 1))
        kern_pause();
#endif
}

static inline void spin_unlock(spinlock l)
{
#ifdef LOCK_STATS
    LOCKSTATS_RECORD_UNLOCK(l->s);
#endif
    compiler_barrier();
    *(volatile u64 *)&l->w = 0;
}

static inline boolean spin_tryrlock(rw_spinlock l)
{
    if (*(volatile word *)&l->l.w)
        return false;
    fetch_and_add(&l->readers, 1);
    if (!*(volatile word *)&l->l.w)
        return true;
    fetch_and_add(&l->readers, -1);
    return false;
}

static inline void spin_rlock(rw_spinlock l)
{
    while (1) {
        if (*(volatile word *)&l->l.w) {
            kern_pause();
            continue;
        }
        fetch_and_add(&l->readers, 1);
        if (!*(volatile word *)&l->l.w)
            return;
        fetch_and_add(&l->readers, -1);
    }
}

static inline void spin_runlock(rw_spinlock l)
{
    fetch_and_add(&l->readers, -1);
}

static inline boolean spin_trywlock(rw_spinlock l)
{
    if (*(volatile word *)&l->readers || !spin_try(&l->l))
        return false;
    if (!*(volatile word *)&l->readers)
        return true;
    spin_unlock(&l->l);
    return false;
}

static inline void spin_wlock(rw_spinlock l)
{
    spin_lock(&l->l);
    while (*(volatile word *)&l->readers)
        kern_pause();
}

static inline void spin_wunlock(rw_spinlock l)
{
    spin_unlock(&l->l);
}
#else
#ifdef SPIN_LOCK_DEBUG_NOSMP
u64 get_program_counter(void);

static inline boolean spin_try(spinlock l)
{
    if (l->w)
        return false;
    l->w = get_program_counter();
    return true;
}

static inline void spin_lock(spinlock l)
{
    if (l->w != 0) {
        print_frame_trace_from_here();
        halt("spin_lock: lock %p already locked by 0x%lx\n", l, l->w);
    }
    l->w = get_program_counter();
}

static inline void spin_unlock(spinlock l)
{
    assert(l->w != 1);
    l->w = 0;
}

static inline boolean spin_tryrlock(rw_spinlock l)
{
    if (l->l.w)
        return false;
    l->readers++;
    return true;
}

static inline void spin_rlock(rw_spinlock l) {
    assert(l->l.w == 0);
    assert(l->readers == 0);
    l->readers++;
}

static inline void spin_runlock(rw_spinlock l) {
    assert(l->readers == 1);
    assert(l->l.w == 0);
    l->readers--;
}

static inline boolean spin_trywlock(rw_spinlock l)
{
    if (l->readers || l->l.w)
        return false;
    assert(spin_try(&l->l));
    return true;
}

static inline void spin_wlock(rw_spinlock l) {
    assert(l->readers == 0);
    spin_lock(&l->l);
}

static inline void spin_wunlock(rw_spinlock l) {
    assert(l->readers == 0);
    spin_unlock(&l->l);
}
#else
#define spin_try(x) (true)
#define spin_lock(x) ((void)x)
#define spin_unlock(x) ((void)x)
#define spin_trywlock(x) (true)
#define spin_wlock(x) ((void)x)
#define spin_wunlock(x) ((void)x)
#define spin_tryrlock(x) (true)
#define spin_rlock(x) ((void)x)
#define spin_runlock(x) ((void)x)
#endif
#endif

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

static inline u64 spin_lock_irq(spinlock l)
{
    u64 flags = irq_disable_save();
    spin_lock(l);
    return flags;
}

static inline void spin_unlock_irq(spinlock l, u64 flags)
{
    spin_unlock(l);
    irq_restore(flags);
}

static inline u64 spin_wlock_irq(rw_spinlock l)
{
    u64 flags = irq_disable_save();
    spin_wlock(l);
    return flags;
}

static inline void spin_wunlock_irq(rw_spinlock l, u64 flags)
{
    spin_wunlock(l);
    irq_restore(flags);
}

static inline u64 spin_rlock_irq(rw_spinlock l)
{
    u64 flags = irq_disable_save();
    spin_rlock(l);
    return flags;
}

static inline void spin_runlock_irq(rw_spinlock l, u64 flags)
{
    spin_runlock(l);
    irq_restore(flags);
}

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

extern const sstring context_type_strings[CONTEXT_TYPE_MAX];

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
static inline boolean in_interrupt(void)
{
    return current_cpu()->state == cpu_interrupt;
}

extern queue bhqueue;
extern queue runqueue;
extern queue async_queue_1;
extern timerqueue kernel_timers;
extern thunk timer_interrupt_handler;

typedef closure_type(clock_timer, void, timestamp);

extern clock_timer platform_timer;

void register_percpu_init(thunk t);
void run_percpu_init(void);

static inline void register_platform_clock_timer(clock_timer ct, thunk percpu_init)
{
    platform_timer = ct;
    register_percpu_init(percpu_init);
}

static inline void set_platform_timer(timestamp duration)
{
    apply(platform_timer, duration);
}

static inline void async_apply(thunk t)
{
    assert(!in_interrupt());
    assert(enqueue(runqueue, t));
}

static inline void async_apply_bh(thunk t)
{
    assert(enqueue_irqsafe(bhqueue, t));
}

typedef closure_type(async_1, void, u64);

typedef struct applied_async_1 {
    async_1 a;
    u64 arg0;
} *applied_async_1;

static inline void async_apply_1(void *a, void *arg0)
{
    struct applied_async_1 aa;
    aa.a = a;
    aa.arg0 = u64_from_pointer(arg0);
    assert(enqueue_n_irqsafe(async_queue_1, &aa, sizeof(aa) / sizeof(u64)));
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
    context_debug("%s: ctx %p, cpu %d\n", func_ss, ctx, ci->id);
    assert(ctx->active_cpu != ci->id);
    u64 remain = CONTEXT_RESUME_SPIN_LIMIT;
    volatile u32 *ac = &ctx->active_cpu;
    while (*ac != -1u) {
        kern_pause();
        assert(remain-- > 0);
    }
    ctx->active_cpu = ci->id;
    context_debug("%s: ctx %p, cpu %d acquired\n", func_ss, ctx, ci->id);
}

static inline void __attribute__((always_inline)) context_release(context ctx)
{
    if (ctx->active_cpu == -1u)
        halt("%s: already paused c %p, type %d\n", func_ss, ctx, ctx->type);
    assert(ctx->active_cpu == current_cpu()->id); /* XXX tmp for bringup */
    ctx->active_cpu = -1u;
}

static inline void __attribute__((always_inline)) context_pause(context ctx)
{
    context_debug("%s: ctx %p\n", func_ss, ctx);
    if (ctx->pause)
        ctx->pause(ctx);
}

static inline void __attribute__((always_inline)) context_resume(context ctx)
{
    context_debug("%s: ctx %p\n", func_ss, ctx);
    cpuinfo ci = current_cpu();
    context_acquire(ctx, ci);
    set_current_context(ci, ctx);
    if (ctx->resume)
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
    context_debug("%s: suspend ctx %p, cpu %d\n", func_ss, ctx, current_cpu()->id);
    context_pre_suspend(ctx);
    context_schedule_return(ctx);
    context_suspend();
    context_debug("%s: resume ctx %p, cpu %d\n", func_ss, ctx, current_cpu()->id);
}

void __attribute__((noreturn)) context_switch_finish(context prev, context next, void *a, u64 arg0, u64 arg1);

/* TODO: make into varargs / macro to avoid unneeded arg copies */
static inline void __attribute__((always_inline)) __attribute__((noreturn))
context_switch_and_branch(context ctx, void * a, u64 arg0, u64 arg1)
{
    cpuinfo ci = current_cpu();
    context prev = get_current_context(ci);
    context_debug("%s: prev %p, next %p, a %p, arg0 0x%lx, arg1 0x%lx\n",
                  func_ss, prev, ctx, a, arg0, arg1);
    if (ctx != prev) {
        context_pause(prev);
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

__attribute__((returns_twice)) boolean err_frame_save(context_frame err_f);
void err_frame_apply(context_frame err_f, context_frame f);

#define context_set_err(ctx)    err_frame_save(((kernel_context)(ctx))->err_frame)

static inline boolean context_err_is_set(context ctx)
{
    return (((kernel_context)ctx)->err_frame[ERR_FRAME_FULL] != 0);
}

static inline void context_clear_err(context ctx)
{
    ((kernel_context)ctx)->err_frame[ERR_FRAME_FULL] = 0;
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

#define closure_from_context(__ctx, __name, ...) ({                                             \
            heap __h = (__ctx)->transient_heap;                                                 \
            struct _closure_##__name * __n = allocate(__h, sizeof(struct _closure_##__name));   \
            __closure((u64_from_pointer(__ctx) |                                                \
                       (CLOSURE_COMMON_CTX_DEALLOC_ON_FINISH | CLOSURE_COMMON_CTX_IS_CONTEXT)), \
                      __n, sizeof(struct _closure_##__name), __name, ##__VA_ARGS__);})

#define contextual_closure(__name, ...) ({                              \
            context __ctx = get_current_context(current_cpu());         \
            context_debug("contextual_closure(%s, ...) ctx %p type %d\n", ss(#__name),  \
                          __ctx, __ctx->type);                                          \
            closure_from_context(__ctx, __name, ##__VA_ARGS__);})

#define contextual_closure_alloc(__name, __var) \
    do {                                                                \
        context __ctx = get_current_context(current_cpu());             \
        context_debug("contextual_closure_alloc(%s, ...) ctx %p\n", ss(#__name), __ctx);    \
        heap __h = __ctx->transient_heap;                               \
        __var = allocate(__h, sizeof(struct _closure_##__name));        \
        if (__var != INVALID_ADDRESS) {                                 \
            __var->__apply = __name;                                    \
            __var->__c.ctx = ctx_from_context(__ctx);                   \
            __var->__c.size = sizeof(struct _closure_##__name);         \
        }                                                               \
    } while (0);


#define contextual_closure_init(__name, __var, ...)                                 \
    do {                                                                            \
        context __ctx = get_current_context(current_cpu());                         \
        __closure(u64_from_pointer(__ctx) | CLOSURE_COMMON_CTX_IS_CONTEXT, (__var), \
                  sizeof(struct _closure_##__name), __name, ##__VA_ARGS__);         \
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

static inline void closure_set_context(void *p, context ctx)
{
    struct _closure_common *c = p + sizeof(void *); /* skip __apply */
    c->ctx = u64_from_pointer(ctx) | CLOSURE_COMMON_CTX_IS_CONTEXT;
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
    if (compare_and_swap_32(&kernel_timers->service_scheduled, false, true))
        async_apply_bh(kernel_timers->service);
}

static inline boolean is_kernel_memory(void *a)
{
    if ((u64)a < KMEM_BASE || (u64)a > KERNEL_LIMIT)
        return false;
    return true;
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

int cmdline_parse(char *cmdline_start, int cmdline_len, sstring opt_name, cmdline_handler h);
void cmdline_apply(char *cmdline_start, int cmdline_len, tuple t);

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

backed_heap allocate_linear_backed_heap(heap meta, id_heap physical, range mapped_virt);

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
void page_free_phys(u64 phys);

#if !defined(BOOT)

heap allocate_tagged_region(kernel_heaps kh, u64 tag, bytes pagesize, boolean locking);
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
int msi_get_vector(u32 data);

u64 allocate_ipi_interrupt(void);
void deallocate_ipi_interrupt(u64 irq);
void register_interrupt(int vector, thunk t, sstring name);
void unregister_interrupt(int vector);

u64 allocate_shirq(void);
void register_shirq(int vector, thunk t, sstring name);

boolean dev_irq_enable(u32 dev_id, int vector);
void dev_irq_disable(u32 dev_id, int vector);

#define TARGET_EXCLUSIVE_BROADCAST  (-1ull)

void send_ipi(u64 cpu, u8 vector);

void init_scheduler(heap);
void init_scheduler_cpus(heap h);
void mm_service(boolean flush);

boolean sched_queue_init(sched_queue sq, heap h);
void sched_enqueue(sched_queue sq, sched_task task);
sched_task sched_dequeue(sched_queue sq);
u64 sched_queue_length(sched_queue sq);

static inline boolean sched_queue_empty(sched_queue sq)
{
    return (sched_queue_length(sq) == 0);
}

typedef closure_type(mem_cleaner, u64, u64);
boolean mm_register_mem_cleaner(mem_cleaner cleaner);

kernel_heaps get_kernel_heaps(void);

#define heap_malloc()  (get_kernel_heaps()->malloc)

static inline boolean is_low_memory_machine(void)
{
    return (heap_total((heap)heap_physical(get_kernel_heaps())) < LOW_MEMORY_THRESHOLD);
}

struct filesystem *get_root_fs(void);
tuple get_root_tuple(void);
tuple get_environment(void);
void register_root_notify(symbol s, set_value_notify n);

boolean first_boot(void);

extern void interrupt_exit(void);
extern const sstring * const state_strings;

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

void early_debug_sstring(sstring s);
#define early_debug(s)  early_debug_sstring(ss(s))

void early_debug_u64(u64 n);
void early_dump(void *p, unsigned long length);
