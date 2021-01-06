/* main header for kernel objects */
#include <runtime.h>
#include <kernel_heaps.h>
#include <kernel_machine.h>

typedef struct nanos_thread {
    thunk pause;
} *nanos_thread;

#define cpu_not_present 0
#define cpu_idle 1
#define cpu_kernel 2
#define cpu_interrupt 3
#define cpu_user 4

static inline boolean is_current_kernel_context(context f)
{
    return f == current_cpu()->kernel_context->frame;
}

static inline context get_running_frame(void)
{
    return current_cpu()->running_frame;
}

static inline void set_running_frame(context f)
{
    current_cpu()->running_frame = f;
}

static inline void *stack_from_kernel_context(kernel_context c)
{
    return ((void*)c->stackbase) + KERNEL_STACK_SIZE - STACK_ALIGNMENT;
}

void runloop_internal() __attribute__((noreturn));

static inline __attribute__((noreturn)) void runloop(void)
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

void kernel_runtime_init(kernel_heaps kh);
void read_kernel_syms(void);
void reclaim_regions(void);

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

typedef struct queue *queue;
extern queue bhqueue;
extern queue runqueue;
extern queue thread_queue;
extern timerheap runloop_timers;

static inline void bhqueue_enqueue_irqsafe(thunk t)
{
    /* an interrupted enqueue and competing enqueue from int handler could cause a
       deadlock; disable ints for safe enqueue from any context */
    u64 flags = irq_disable_save();
    enqueue(bhqueue, t);
    irq_restore(flags);
}

extern boolean runtime_initialized;

heap allocate_tagged_region(kernel_heaps kh, u64 tag);
heap physically_backed(heap meta, heap virtual, heap physical, u64 pagesize);
void physically_backed_dealloc_virtual(heap h, u64 x, bytes length);
void print_stack(context c);
void print_frame(context f);

typedef closure_type(fault_handler, context, context);

void configure_timer(timestamp rate, thunk t);

void kernel_sleep();
void kernel_delay(timestamp delta);

void init_clock(heap h);
boolean init_hpet(kernel_heaps kh);

void process_bhqueue();
void install_fallback_fault_handler(fault_handler h);

void msi_format(u32 *address, u32 *data, int vector);

u64 allocate_interrupt(void);
void deallocate_interrupt(u64 irq);
boolean reserve_interrupt(u64 irq);
void register_interrupt(int vector, thunk t, const char *name);
void unregister_interrupt(int vector);

void kern_lock(void);
boolean kern_try_lock(void);
void kern_unlock(void);
void init_scheduler(heap);
void mm_service(void);

void interrupt_exit(void);
extern char **state_strings;

// static inline void schedule_frame(context f) stupid header deps
#define schedule_frame(__f)  do { assert((__f)[FRAME_QUEUE] != INVALID_PHYSICAL); enqueue((queue)pointer_from_u64((__f)[FRAME_QUEUE]), pointer_from_u64((__f)[FRAME_RUN])); } while(0)

void kernel_unlock();

extern u64 idle_cpu_mask;
extern u64 total_processors;
extern int shutdown_vector;
