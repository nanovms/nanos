typedef u64 *context_frame;
typedef closure_type(fault_handler, context, context);

#define CONTEXT_TYPE_UNDEFINED 0
#define CONTEXT_TYPE_KERNEL    1
#define CONTEXT_TYPE_SYSCALL   2
#define CONTEXT_TYPE_THREAD    3
#define CONTEXT_TYPE_MAX       4

struct context {
    u64 frame[FRAME_SIZE]; /* must be first */
    thunk pause;
    thunk resume;
    thunk pre_suspend;
    thunk schedule_return;
    fault_handler fault_handler;
    heap transient_heap;
    u32 active_cpu;
    u8 type;
};
