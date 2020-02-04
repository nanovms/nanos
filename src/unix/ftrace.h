#ifdef CONFIG_FTRACE

#include <runtime.h>
#include <unix_internal.h>

#define FTRACE_TRACE_DIR                "/sys/kernel/debug/tracing"
#define FTRACE_TRACER_DIR(tracer)       FTRACE_TRACE_DIR "/" #tracer

#define FTRACE_TRACE_PORT               9090
#define FTRACE_TRACE_URI                "ftrace"

typedef sysreturn (ftrace_open_fn)(file);
typedef sysreturn (ftrace_close_fn)(file);
typedef sysreturn (ftrace_read_fn)(file, void *, u64, u64);
typedef sysreturn (ftrace_write_fn)(file, void *, u64, u64);
typedef u32 (ftrace_events_fn)(file);

static inline sysreturn 
ftrace_open_nop(file f) 
{
    return 0;
}

static inline sysreturn 
ftrace_close_nop(file f) 
{
    return 0;
}

#define FTRACE_PASTER(a, b) a ## _ ## b
#define FTRACE_EVALUATOR(a, b) FTRACE_PASTER(a, b)
#define FTRACE_FN(name, operation)\
    FTRACE_EVALUATOR( FTRACE_EVALUATOR(ftrace, name), operation)

#define FTRACE_SPECIAL_PROTOTYPES(name)\
    ftrace_open_fn FTRACE_FN(name, open);\
    ftrace_close_fn FTRACE_FN(name, close);\
    ftrace_read_fn FTRACE_FN(name, read);\
    ftrace_write_fn FTRACE_FN(name, write);\
    ftrace_events_fn FTRACE_FN(name, events);

#define FTRACE_SPECIAL_FILE(name) \
    {\
        .path    = FTRACE_TRACER_DIR(name),\
        .open    = ftrace_open_nop,\
        .close   = ftrace_close_nop,\
        .read    = FTRACE_FN(name, read),\
        .write   = FTRACE_FN(name, write),\
        .events  = FTRACE_FN(name, events)\
    }

#define FTRACE_SPECIAL_FILE_OC(name) \
    {\
        .path    = FTRACE_TRACER_DIR(name),\
        .open    = FTRACE_FN(name, open),\
        .close   = FTRACE_FN(name, close),\
        .read    = FTRACE_FN(name, read),\
        .write   = FTRACE_FN(name, write),\
        .events  = FTRACE_FN(name, events)\
    }

#define FTRACE_SPECIAL_FILES \
    /* files without open/close callbacks */\
    FTRACE_SPECIAL_FILE(available_tracers),\
    FTRACE_SPECIAL_FILE(current_tracer),\
    FTRACE_SPECIAL_FILE(trace_clock),\
    FTRACE_SPECIAL_FILE(tracing_on),\
    /* files with open/close callbacks */\
    FTRACE_SPECIAL_FILE_OC(trace),\
    FTRACE_SPECIAL_FILE_OC(trace_pipe)\

FTRACE_SPECIAL_PROTOTYPES(available_tracers);
FTRACE_SPECIAL_PROTOTYPES(current_tracer);
FTRACE_SPECIAL_PROTOTYPES(trace_clock);
FTRACE_SPECIAL_PROTOTYPES(trace_pipe);
FTRACE_SPECIAL_PROTOTYPES(trace);
FTRACE_SPECIAL_PROTOTYPES(tracing_on);

int ftrace_init(unix_heaps uh, filesystem fs);
void ftrace_deinit(void);
int ftrace_thread_init(thread t);
void ftrace_thread_deinit(thread out, thread in);
void ftrace_thread_switch(thread out, thread in);

#define ftrace_thread_noreturn(t) ftrace_thread_switch(t, t)

void ftrace_enable(void);

#else

static inline int 
ftrace_init(unix_heaps uh, filesystem fs)
{
    return 0;
}

static inline void
ftrace_deinit(void)
{}

static inline int
ftrace_thread_init(thread t)
{
    return 0;
}

static inline void
ftrace_thread_deinit(thread out, thread in)
{}

static inline void
ftrace_thread_switch(thread out, thread in)
{}

static inline void
ftrace_thread_noreturn(thread t)
{}

static inline void 
ftrace_enable(void)
{}

#define FTRACE_SPECIAL_FILES

#endif
