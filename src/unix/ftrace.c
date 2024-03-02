#include <unix_internal.h>
#include <ftrace.h>
#include <symtab.h>
#include <http.h>

#define FTRACE_DEBUG
#ifdef FTRACE_DEBUG
#define ft_debug(x, ...) do {rprintf("FTRACE: " x, ##__VA_ARGS__);} while(0)
#else
#define ft_debug(x, ...)
#endif

#define DEFAULT_TRACE_ARRAY_SIZE_KB     (DEFAULT_TRACE_ARRAY_SIZE >> 10)

#define TRACE_TASK_WIDTH    15
#define TRACE_PID_WIDTH     5

/* 4KB; will grow dynamically */
#define TRACE_PRINTER_INIT_SIZE (1ULL << 12)

/* Larger than 1MB buffers not currently supported on general heap */
#define TRACE_PRINTER_MAX_SIZE  (1ULL << 19)

/* Special context switch event */
#define TRACE_GRAPH_SWITCH_DEPTH (unsigned short)(-1)

/* can't trace depths longer than this ... */
#define FTRACE_RETFUNC_DEPTH 128

/* special disable idx */
#define FTRACE_THREAD_DISABLE_IDX (int)-1

#define UNTIMED (-1ULL)
/* helper to create a buffer on the stack with a pointer to
 * contents that exist elsewhere
 */
#define stack_buffer_name(__n) {\
    .contents = (__n),\
    .start = 0,\
    .end = sizeof(__n)-1,\
    .length = sizeof(__n)-1\
};

static heap ftrace_heap;
static heap rbuf_heap;

/* whether or not to write into the ring buffer */
boolean tracing_on = false;

/* currently running tracer */
struct ftrace_tracer * current_tracer = 0;

/* http listener */
static http_listener ftrace_hl;

struct rbuf_entry_function {
    unsigned long ip;
    unsigned long parent_ip;
    unsigned long ts; /* XXX only supports tsc at the moment */
    unsigned short cpu;
    int tid;
    symbol sym_name;
};

struct rbuf_entry_function_graph {
    unsigned short depth; /* must be first */
    unsigned long ip;
    timestamp duration;
    unsigned short cpu;
    unsigned char has_child;
    unsigned char flush;
    unsigned long tid;
};

struct rbuf_entry_switch {
    unsigned short depth; /* must be first */
    unsigned short cpu;
    int tid_in;
    int tid_out;
    symbol sym_name_in;
    symbol sym_name_out;
};

struct rbuf_entry {
    union {
        struct rbuf_entry_function func;
        struct rbuf_entry_function_graph graph;
        struct rbuf_entry_switch sw;
    };
};

struct rbuf {
    struct rbuf_entry * trace_array;
    struct spinlock rb_lock;
    unsigned long count; /* current number of unconsumed items */
    unsigned long total_written; /* total items ever written */
    unsigned long size;
    unsigned long read_idx;
    unsigned long local_idx;    /* index while iterating (but not consuming) */
    unsigned long write_idx;
    cpuinfo ci;
};

/* This structure is designed to simplify the process of efficiently flushing
 * buffers to userspace/http response handlers
 *
 * This is also needed to persist rbuf contents across multiple destructive
 * reads; e.g., if the user reads 4KB of data, it's very likely that the last
 * line of text is going to split an rbuf entry, and we need to maintain at
 * least that half line of data in the buffer b for the likely subsequent call
 * to read with an incremented offset
 */

struct ftrace_printer {
    buffer b;
    u64 local_offset;
    u64 max_size; /* stop printing if the buffer reaches this size */
    struct timer t;

    /* listed below */
    unsigned long flags;
};

#define TRACE_FLAG_FILE         0x1 /* file based access */
#define TRACE_FLAG_HTTP         0x2 /* http based access */
#define TRACE_FLAG_HEADER       0x4 /* print a header along with the data */
#define TRACE_FLAG_DESTRUCTIVE  0x8 /* reads consume the buffer data */

struct ftrace_tracer {
    /* human readable */
    sstring name;

    /* trace_fn must be marked as NOTRACE or else you're gonna blow up the call
     * stack and crash
     *
     * mcount_toggle should be as well as a performance optimization
     */
    void (*trace_fn)(unsigned long, unsigned long);
    void (*mcount_toggle)(boolean enable);
    void (*print_header_fn)(struct ftrace_printer * p, struct rbuf * r);
    void (*print_entry_fn)(struct ftrace_printer * p, struct rbuf_entry * e);
};

struct ftrace_routine {
    /* human readable */
    sstring relative_uri;

    /* some routines need a specific printer */
    struct ftrace_printer * printer;

    sysreturn (*init_fn)(struct ftrace_printer * p, u64 flags);
    sysreturn (*deinit_fn)(struct ftrace_printer * p);
    sysreturn (*get_fn)(struct ftrace_printer * p);
    sysreturn (*put_fn)(struct ftrace_printer * p);
};

/* Structure for function_graph tracing */
struct ftrace_graph_entry {
    unsigned long retaddr; /* retaddr in caller */
    unsigned long func; /* function being traced */
    timestamp entry_ts; /* entry timestamp */
    timestamp return_ts; /* return timestamp */
    unsigned long fp; /* frame pointer (just used for sanity checking) */
    unsigned short depth; /* depth on the call stack */
    unsigned char has_child; /* did this function call anything? */
    unsigned char flush; /* expicitly flushed during reschedule event */
    //unsigned long overrun; /* XXX do we use? */
    //unsigned long * retp; /* address of where retaddr sits on the stack */
    unsigned long tid;
    unsigned short cpu;
};

extern void ftrace_stub(unsigned long, unsigned long);

typedef void (*ftrace_function_t)(unsigned long, unsigned long);
typedef void (*ftrace_graph_t)(struct ftrace_graph_entry * );

/*
 * These three pointers are queried by mcount() to determine if tracing is
 * enabled for function, function_graph, or neither
 *
 * They should be set to these stubs, or the associated trace function if
 * active
 */

ftrace_function_t  __ftrace_function_fn = ftrace_stub;
ftrace_graph_t  __ftrace_graph_entry_fn = (ftrace_graph_t)ftrace_stub;
ftrace_graph_t __ftrace_graph_return_fn = (ftrace_graph_t)ftrace_stub;


static vector cpu_rbufs;

/*
 * helper to write a buffer to userspace, paying attention
 * to length and offset conditions
 *
 * b: the buffer to write
 * buf: the user address to write to
 * length: the length of the user buffer
 * buffer_offset: how far into b we should start writing from
 *
 * return: number of bytes written
 */
static u64
write_to_user_offset(buffer b, void * buf, u64 length, u64 buffer_offset)
{
    u64 len = (u64)buffer_length(b);

    /* adjust for length */
    if (len > length)
        len = length;

    /* if the offset is past the end, nothing to do */
    if (len <= buffer_offset)
        return 0;

    runtime_memcpy(buf, buffer_ref(b, buffer_offset), len);
    return len;
}

#define printer_buffer(p)           (p)->b
#define printer_length(p)           (u64)buffer_length(printer_buffer(p))
#define printer_size(p)             (p)->max_size

static inline __attribute__((always_inline)) void
printer_set_size(struct ftrace_printer * p, u64 size)
{
    if (size > TRACE_PRINTER_MAX_SIZE)
        size = TRACE_PRINTER_MAX_SIZE;

    p->max_size = size;
}

static int
printer_init(struct ftrace_printer * p, unsigned long flags)
{
    p->b = allocate_buffer(ftrace_heap, TRACE_PRINTER_INIT_SIZE);
    if (p->b == INVALID_ADDRESS) {
        msg_err("failed to allocate ftrace buffer\n");
        return -1;
    }
    init_timer(&p->t);
    p->local_offset = 0;
    p->flags = flags;
    return 0;
}

static void
printer_deinit(struct ftrace_printer * p)
{
    /* HTTP based freeing is done somewhere within the http/tcp/udp code?? */
    if (p->flags & TRACE_FLAG_FILE)
        deallocate_buffer(p->b);
}

/*
 * Set the printer's local offset
 */
static void
printer_reset(struct ftrace_printer * p, u64 offset)
{
    u64 poff = p->local_offset;

    if (offset < poff)
        buffer_clear(printer_buffer(p));
    else
        buffer_consume(printer_buffer(p), offset - poff);

    p->local_offset = offset;
}

/*
 * helper to flush printer contents to userspace
 *
 * if the user offset is higher than anything the printer covers, drop
 * the data and update the printer's local offset
 */
static u64
printer_flush_user(struct ftrace_printer * p, void * buf, u64 len, u64 offset)
{
    u64 ret;
    u64 poff, plen, pend;

    poff = p->local_offset;
    plen = printer_length(p);
    pend = poff + plen;

    /* nothing to write */
    if (pend < offset) {
        /* "consume" this data by bumping the printer offset up by the length
         * of the printer
         */
        printer_reset(p, poff + plen);
        return 0;
    }

    /* printer is now aligned with this offset */
    printer_reset(p, offset);

    /* write the printer */
    ret = write_to_user_offset(
        printer_buffer(p),
        buf, len,
        0
    );

    /* always consume anything written */
    printer_reset(p, offset + ret);

    return ret;
}

/*
 * Write some data into the printer
 *
 * p: printer to write to
 * fmt (...) : formatted string and args
*/
#define printer_write(p, fmt, ...) \
    bprintf(printer_buffer(p), fmt, ##__VA_ARGS__)
#define printer_write_sstring(p, fmt, ...)  \
    bprintf_sstring(printer_buffer(p), fmt, ##__VA_ARGS__)

/* right-adjust the str within a width of 'width' characters and
 * print to buffer
 */
static inline __attribute__((always_inline)) void
printer_print_right_adjusted(struct ftrace_printer *p, sstring str,
                             u16 width)
{
    int len = str.len;

    if (len > width) {
        len = width;
        str.len = len;
    }

    while (len < width) {
        printer_write(p, " ");
        width--;
    }

    printer_write_sstring(p, str);
}

static inline __attribute__((always_inline)) sstring
function_name(unsigned long ip)
{
    u64 offset, len;
    return find_elf_sym(ip, &offset, &len);
}

static inline __attribute__((always_inline)) void
printer_print_sym(struct ftrace_printer * p, unsigned long ip)
{
    sstring name = function_name(ip);
    if (!sstring_is_null(name))
        printer_write_sstring(p, name);
    else
        printer_write(p, "<< unknown symbol >>");
}

/* write timestamp in "num" in usecs to the printer as follows:
 * "<usec>.<remainder> us"
 *
 * The whole string should consume width bytes -- this will be
 * accomplished either by truncating the usec/remainder, or padding
 * blank spaces after the us
 */
static inline __attribute__((always_inline)) void
printer_print_duration_usec(struct ftrace_printer * p, timestamp num, u16 width)
{
    buffer b = little_stack_buffer(64);
    u64 usec, nsec, len;

    nsec = nsec_from_timestamp(num);
    usec = nsec / THOUSAND;
    nsec = nsec % THOUSAND;

    /* print a symbol to highlight the timescale */
    printer_write(p, "%c ",
        (usec >= 100000) ? '@' :
        (usec >= 10000)  ? '*' :
        (usec >= 1000)   ? '#' :
        (usec >= 100)    ? '!' :
        (usec >= 10)     ? '+' : ' '
    );

    bprintf(b, "%ld.", usec);

    /* add in leading 0s */
    if (nsec < 100)
        bprintf(b, "0");
    if (nsec < 10)
        bprintf(b, "0");

    bprintf(b, "%ld", nsec);

    /* truncate the buffer after "width"-3 digits */
    len = buffer_length(b);
    if (len > width - 3)
        b->end = b->start + width - 3;

    printer_write(p, "%b us", b);

    /* add spaces if needed */
    while (len < width - 3) {
        printer_write(p, " ");
        len++;
    }
}

#define rbuf_next_idx(r, idx)   (idx == r->size - 1) ? 0 : idx + 1
#define rbuf_next_write_idx(r)  rbuf_next_idx(r, r->write_idx)
#define rbuf_next_read_idx(r)   rbuf_next_idx(r, r->read_idx)

static inline __attribute__((always_inline)) void
rbuf_lock(struct rbuf * rbuf) {
    spin_lock(&rbuf->rb_lock);
}
static inline __attribute__((always_inline)) void
rbuf_unlock(struct rbuf * rbuf) {
    spin_unlock(&rbuf->rb_lock);
}

static void
rbuf_reset(struct rbuf * rbuf)
{
    rbuf->count = 0;
    rbuf->local_idx = 0;
    rbuf->read_idx = 0;
    rbuf->write_idx = 0;
    rbuf->total_written = 0;
}

static int
rbuf_init(struct rbuf * rbuf, unsigned long buffer_size_kb)
{
    unsigned long buffer_size = buffer_size_kb << 10;

    rbuf->size = buffer_size / sizeof(struct rbuf_entry);
    rbuf->trace_array = allocate(rbuf_heap,
            sizeof(struct rbuf_entry) * rbuf->size);
    if (rbuf->trace_array == INVALID_ADDRESS) {
        msg_err("failed to allocate ftrace trace array\n");
        return -ENOMEM;
    }
    spin_lock_init(&rbuf->rb_lock);
    rbuf_reset(rbuf);

    return 0;
}

static struct rbuf *
allocate_rbuf(heap h, unsigned long buffer_size_kb)
{
    struct rbuf *rb = allocate_zero(h, sizeof(struct rbuf));
    if (rb == INVALID_ADDRESS)
        return rb;
    if (rbuf_init(rb, buffer_size_kb)) {
        deallocate(h, rb, sizeof(struct rbuf));
        return INVALID_ADDRESS;
    }
    return rb;
}

static inline __attribute__((always_inline)) void
rbuf_disable(struct rbuf * rbuf)
{
    /* trace is disabled on cpu on first disable */
    fetch_and_add(&rbuf->ci->m.ftrace_disable_cnt, 1);
}

static inline __attribute__((always_inline)) void
rbuf_enable(struct rbuf * rbuf)
{
    /* trace is enabled on cpu on last enable */
    assert(fetch_and_add(&rbuf->ci->m.ftrace_disable_cnt, -1) > 0);
}

static inline __attribute__((always_inline)) boolean
rbuf_enabled(struct rbuf * rbuf)
{
    return (rbuf->ci->m.ftrace_disable_cnt == 0);
}

static inline __attribute__((always_inline)) void
global_rbuf_enable(void)
{
    struct rbuf *rb;
    vector_foreach(cpu_rbufs, rb)
        rbuf_enable(rb);
}

static inline __attribute__((always_inline)) void
global_rbuf_disable(void)
{
    struct rbuf *rb;
    vector_foreach(cpu_rbufs, rb)
        rbuf_disable(rb);
}

/* must be locked before calling */
static inline __attribute__((always_inline)) boolean
__rbuf_acquire_write_entry(struct rbuf * rbuf, struct rbuf_entry ** acquired)
{
    if (rbuf->count == rbuf->size - 1)
        return false;

    *acquired = &(rbuf->trace_array[rbuf->write_idx]);

    rbuf->write_idx = rbuf_next_write_idx(rbuf);
    rbuf->count++;
    rbuf->total_written++;
    if (rbuf->count == rbuf->size - 1)
        ft_debug("FTRACE: buffer full (cpu %d)\n", current_cpu()->id);

    return true;
}

/* must be locked before calling */
static inline __attribute__((always_inline)) boolean
__rbuf_acquire_read_entry(struct rbuf * rbuf, struct rbuf_entry ** acquired)
{
    if (rbuf->count == 0)
        return false;

    *acquired = &(rbuf->trace_array[rbuf->read_idx]);

    rbuf->read_idx = rbuf_next_read_idx(rbuf);
    rbuf->count--;
    return true;
}

/*** Start tracer callbacks */

/* nop tracer */
NOTRACE static void
nop_toggle(boolean enable)
{
    __ftrace_function_fn = ftrace_stub;
    __ftrace_graph_entry_fn = (ftrace_graph_t)ftrace_stub;
    __ftrace_graph_return_fn = (ftrace_graph_t)ftrace_stub;
}

static void
nop_print_header(struct ftrace_printer * p, struct rbuf * rbuf)
{
    printer_write(p, "# tracer: nop\n");
    printer_write(p, "#\n");
    printer_write(p, "#\n");
    printer_write(p, "#           TASK-PID   CPU#     TIMESTAMP  FUNCTION\n");
    printer_write(p, "#              | |       |         |         |\n");
}

NOTRACE static void
function_trace(unsigned long ip, unsigned long parent_ip)
{
    struct rbuf *rb = vector_get(cpu_rbufs, current_cpu()->id);
    assert(rb != 0);
    struct rbuf_entry * entry;
    struct rbuf_entry_function * func;

    /* disable any more events while we're in here */
    rbuf_disable(rb);

    rbuf_lock(rb);
    if (!__rbuf_acquire_write_entry(rb, &entry)) {
        rbuf_unlock(rb);
        goto drop;
    }

    func = &(entry->func);
    func->cpu = current_cpu()->id;
    func->tid = current->tid;
    func->ip = ip;
    func->parent_ip = parent_ip;

    /* XXX function tracer just supports tsc for now */
    func->ts = rdtsc();

    /* alloca is broken here ... */
    if (current->name[0] != '\0') {
        struct buffer b = stack_buffer_name(current->name);
        func->sym_name = intern(&b);
    }
    else
        func->sym_name = 0;

    rbuf_unlock(rb);
    rbuf_enable(rb);
    return;
drop:
    /* XXX count the drop */
    return;
}

NOTRACE static void
function_toggle(boolean enable)
{
    if (enable)
        __ftrace_function_fn = function_trace;
    else
        __ftrace_function_fn = ftrace_stub;
}

static void
function_print_header(struct ftrace_printer * p, struct rbuf * rbuf)

{
    printer_write(p, "# tracer: function\n");
    printer_write(p, "#\n");
    printer_write(p, "#\n");
    printer_write(p, "#           TASK-PID   CPU#     TIMESTAMP  FUNCTION\n");
    printer_write(p, "#              | |       |         |         |\n");
}

static void
function_print_entry(struct ftrace_printer * p, struct rbuf_entry * entry)
{
    struct rbuf_entry_function * func = &(entry->func);
    sstring name = (func->sym_name)
        ? buffer_to_sstring(symbol_string(func->sym_name))
        : ss("tid");

    printer_write(p, " ");
    printer_print_right_adjusted(p, name, TRACE_TASK_WIDTH);
    printer_write(p, "-%d", func->tid);

    /* pad with spaces as needed */
    {
        int tid, blanks;

        for (tid = func->tid,
             blanks = (tid) ? TRACE_PID_WIDTH : TRACE_PID_WIDTH-1;
             tid > 0;
             tid /= 10)
        {
            blanks--;
        }

        while (blanks-- > 0)
            printer_write(p, " ");
    }

    /* CPU number */
    printer_write(p, " [%03d] ", func->cpu);

    /* timestamp */
    printer_write(p, " %ld: ", func->ts);

    /* function and parent */
    printer_print_sym(p, func->ip);
    printer_write(p, " <-");
    printer_print_sym(p, func->parent_ip);

    printer_write(p, "\n");
}

/*
 * This must always called with rbuf already disabled
 */
NOTRACE static void
function_graph_trace_switch(thread out, thread in)
{
    struct rbuf *rb = vector_get(cpu_rbufs, current_cpu()->id);
    assert(rb != 0);
    struct rbuf_entry * entry;
    struct rbuf_entry_switch * sw;

    rbuf_lock(rb);
    if (!__rbuf_acquire_write_entry(rb, &entry)) {
        rbuf_unlock(rb);
        goto drop;
    }

    sw = &(entry->sw);
    sw->depth = TRACE_GRAPH_SWITCH_DEPTH;
    sw->cpu = current_cpu()->id;
    sw->tid_in = in ? in->tid : 0;
    sw->tid_out = out ? out->tid : 0;

    if (in && in->name[0] != '\0') {
        struct buffer b = stack_buffer_name(in->name);
        sw->sym_name_in = intern(&b);
    } else
        sw->sym_name_in = 0;

    if (out && out->name[0] != '\0') {
        struct buffer b = stack_buffer_name(out->name);
        sw->sym_name_out = intern(&b);
    } else
        sw->sym_name_out = 0;

    rbuf_unlock(rb);
    return;
drop:
    /* XXX count the drop */
    return;
}

/*
 * This must always called with rbuf already disabled
 */
NOTRACE static void
function_graph_trace_entry(struct ftrace_graph_entry * stack_entry)
{
    struct rbuf *rb = vector_get(cpu_rbufs, current_cpu()->id);
    assert(rb != 0);
    struct rbuf_entry * entry;
    struct rbuf_entry_function_graph * graph;

    rbuf_lock(rb);
    if (!__rbuf_acquire_write_entry(rb, &entry)) {
        rbuf_unlock(rb);
        goto drop;
    }

    graph = &(entry->graph);
    graph->ip = stack_entry->func;
    graph->duration = UNTIMED;
    graph->cpu = stack_entry->cpu;
    graph->depth = stack_entry->depth;
    graph->has_child = 1;
    graph->tid = stack_entry->tid;

    rbuf_unlock(rb);
    return;
drop:
    /* XXX count the drop */
    return;
}

/*
 * This must always called with rbuf already disabled
 */
NOTRACE static void
function_graph_trace_return(struct ftrace_graph_entry * stack_entry)
{
    struct rbuf *rb = vector_get(cpu_rbufs, current_cpu()->id);
    assert(rb != 0);
    struct rbuf_entry * entry;
    struct rbuf_entry_function_graph * graph;

    rbuf_lock(rb);
    if (!__rbuf_acquire_write_entry(rb, &entry)) {
        rbuf_unlock(rb);
        goto drop;
    }

    graph = &(entry->graph);
    graph->depth = stack_entry->depth;
    graph->ip = stack_entry->func;
    graph->duration = (stack_entry->return_ts - stack_entry->entry_ts);
    graph->cpu = stack_entry->cpu;
    graph->has_child = stack_entry->has_child;
    graph->flush = graph->has_child; //stack_entry->flush;
    graph->tid = stack_entry->tid;

    rbuf_unlock(rb);
    return;
drop:
    /* XXX count the drop */
    return;
}

NOTRACE static void
function_graph_toggle(boolean enable)
{
    if (enable) {
        __ftrace_graph_entry_fn = function_graph_trace_entry;
        __ftrace_graph_return_fn = function_graph_trace_return;
    } else {
        __ftrace_graph_entry_fn = (ftrace_graph_t)ftrace_stub;
        __ftrace_graph_return_fn = (ftrace_graph_t)ftrace_stub;
    }
}

static void
print_switch_event(struct ftrace_printer * p, struct rbuf_entry_switch * sw)
{
    /* XXX thread switches are wrong right now so don't print them out yet */
    #if 0
    sstring name_in, name_out;
    sstring tid = ss("tid");

    name_in = (sw->sym_name_in)
        ? buffer_to_sstring(symbol_string(sw->sym_name_in)) : tid;
    name_out = (sw->sym_name_out)
        ? buffer_to_sstring(symbol_string(sw->sym_name_out)) : tid;

    printer_write(p, "------------------------------------------\n");
    printer_write(p, " %d) %s-%d  => %s-%d\n",
        sw->cpu,
        name_out,
        sw->tid_out,
        name_in,
        sw->tid_in
    );
    printer_write(p, "------------------------------------------\n");
    #endif
}

static void
function_graph_print_entry(struct ftrace_printer * p,
                           struct rbuf_entry * entry)
{
    struct rbuf_entry_function_graph * graph = &(entry->graph);

    /* check for special switch event */
    if (graph->depth == TRACE_GRAPH_SWITCH_DEPTH) {
        print_switch_event(p, &(entry->sw));
        return;
    }

    printer_write(p, " %d) ", graph->cpu);

    /* duration */
    if (!graph->has_child || graph->duration != UNTIMED) {
        assert(graph->duration != UNTIMED);
        printer_print_duration_usec(p, graph->duration, 11);
    } else
        printer_write(p, "             ");

    printer_write(p, " |  ");

    /* 2 spaces per depth */
    {
        int d;
        for (d = 0; d < graph->depth; d++) {
            printer_write(p, "  ");
        }
    }

    /* if duration is UNTIMED, this is a graph of a function
     * that has children
     */
    if (graph->duration == UNTIMED) {
        assert(graph->has_child);
        /* function graph */
        printer_write(p, "%s() {", function_name(graph->ip));
    } else {
        /* either a close of a function that called something, or
         * an graph+return wihout children */
        if (graph->has_child) {
            printer_write(p, "}");
            if (graph->flush)
                printer_write(p, " /* %s */", function_name(graph->ip));
        } else {
            printer_write(p, "%s();", function_name(graph->ip));
        }
    }

    printer_write(p, "\n");
}

static boolean
ftrace_print_rbuf_destructive(struct ftrace_printer * p, struct rbuf * rbuf,
                              struct ftrace_tracer * tracer)
{
    struct rbuf_entry * entry;

    while (__rbuf_acquire_read_entry(rbuf, &entry)) {
        tracer->print_entry_fn(p, entry);
        if (printer_length(p) >= printer_size(p))
            break;
    }

    return rbuf->count > 0;     /* more */
}

static boolean
ftrace_print_rbuf_nondestructive(struct ftrace_printer * p, struct rbuf * rbuf,
                                 struct ftrace_tracer * tracer)
{
    struct rbuf_entry * entry;
    unsigned long idx;

    idx = rbuf->local_idx;
    while (idx != rbuf->write_idx) {
        entry = &(rbuf->trace_array[idx]);
        idx  = rbuf_next_idx(rbuf, idx);

        tracer->print_entry_fn(p, entry);
        if (printer_length(p) >= printer_size(p))
            break;
    }

    rbuf->local_idx = idx;
    return idx != rbuf->write_idx; /* more */
}

static void
function_graph_print_header(struct ftrace_printer * p, struct rbuf * rbuf)
{
    printer_write(p, "# tracer: function_graph\n");
    printer_write(p, "#\n");
    printer_write(p, "# CPU  DURATION                  FUNCTION CALLS\n");
    printer_write(p, "# |     |   |                     |   |   |   |\n");
}

static boolean
ftrace_print_rbuf(struct ftrace_printer * p, struct rbuf * rbuf,
                  struct ftrace_tracer * tracer)
{
    if (p->flags & TRACE_FLAG_HEADER)
        if (tracer->print_header_fn)
            tracer->print_header_fn(p, rbuf);

    if (!tracer->print_entry_fn)
        return false;

    if (p->flags & TRACE_FLAG_DESTRUCTIVE)
        return ftrace_print_rbuf_destructive(p, rbuf, tracer);
    else
        return ftrace_print_rbuf_nondestructive(p, rbuf, tracer);
}

#define FTRACE_TRACER(_name, _mcount_toggle, _header_fn, _entry_fn)\
{\
    .name = ss_static_init(_name),\
    .mcount_toggle = _mcount_toggle,\
    .print_header_fn = _header_fn,\
    .print_entry_fn = _entry_fn\
}
static struct ftrace_tracer
tracer_list[] = {
    /* nop must be first */
    FTRACE_TRACER("nop", nop_toggle, nop_print_header, 0
    ),
    FTRACE_TRACER("function", function_toggle, function_print_header,
        function_print_entry
    ),
    FTRACE_TRACER("function_graph", function_graph_toggle,
        function_graph_print_header, function_graph_print_entry
    )
};
#define FTRACE_FUNCTION_IDX 1
#define FTRACE_FUNCTION_GRAPH_IDX 2
#define FTRACE_NR_TRACERS (sizeof(tracer_list) / sizeof(struct ftrace_tracer))

/**** Start interface operations ****/

static sysreturn
FTRACE_FN(available_tracers, get)(struct ftrace_printer * p)
{
    int i;

    for (i = 0; i < FTRACE_NR_TRACERS; i++) {
        struct ftrace_tracer * tracer = &(tracer_list[i]);

        if (i)
            printer_write(p, " ");
        printer_write_sstring(p, tracer->name);
    }

    printer_write(p, "\n");
    return 0;
}


/* write space-delimited list of tracer names */
sysreturn
FTRACE_FN(available_tracers, read)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;
    struct ftrace_printer p;

    if (printer_init(&p, TRACE_FLAG_FILE))
        return -ENOMEM;

    ret = FTRACE_FN(available_tracers, get)(&p);
    if (ret != 0)
        goto out;

    ret = printer_flush_user(&p, buf, length, offset);

out:
    printer_deinit(&p);
    return ret;
}

sysreturn
FTRACE_FN(available_tracers, write)(file f, void * buf, u64 length, u64 offset)
{
    return 0;
}

u32
FTRACE_FN(available_tracers, events)(file f)
{
    return EPOLLIN;
}

/*
 * current_tracer callbacks
 */

static sysreturn
FTRACE_FN(current_tracer, get)(struct ftrace_printer * p)
{
    printer_write(p, "%s\n", current_tracer->name);
    return 0;
}

static sysreturn
FTRACE_FN(current_tracer, put)(struct ftrace_printer * p)
{
    int i;
    sstring str = buffer_to_sstring(printer_buffer(p));
    int ret;
    struct rbuf *rb;

    for (i = 0; i < FTRACE_NR_TRACERS; i++) {
        struct ftrace_tracer * tracer = &(tracer_list[i]);

        if (runtime_strcmp(tracer->name, str) == 0) {
            if (tracer != current_tracer) {
                global_rbuf_disable();

                /* clear the rbuf */
                vector_foreach(cpu_rbufs, rb)
                    rbuf_reset(rb);
                current_tracer = tracer;

                global_rbuf_enable();
            }
            ret = 0;
            goto out;
        }
    }

    ret = -EFAULT;

out:
    return ret;
}

sysreturn
FTRACE_FN(current_tracer, read)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;
    struct ftrace_printer p;

    if (printer_init(&p, TRACE_FLAG_FILE))
        return -ENOMEM;

    ret = FTRACE_FN(current_tracer, get)(&p);
    if (ret != 0)
        goto out;

    ret = printer_flush_user(&p, buf, length, offset);

out:
    printer_deinit(&p);
    return ret;
}

sysreturn
FTRACE_FN(current_tracer, write)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;
    struct ftrace_printer p;

    /* write with an offset > 0 doesn't make much sense here */
    if (offset > 0)
        return 0;

    if (printer_init(&p, TRACE_FLAG_FILE))
        return -ENOMEM;

    assert(buffer_write(printer_buffer(&p), buf, length));
    ret = FTRACE_FN(current_tracer, put)(&p);
    printer_deinit(&p);

    if (ret != 0)
        return ret;

    return length;
}

u32
FTRACE_FN(current_tracer, events)(file f)
{
    return EPOLLIN | EPOLLOUT;
}


/*
 * trace callbacks
 *
 * trace reads are non-destructive and read the whole buffer; for correct
 * operation we need to make sure the buffer doesn't update while we're
 * reading -- the user may even issue multiple reads that we need to
 * prevent updates across
 */
static struct ftrace_printer trace_printer;
static boolean trace_is_open = false;

static sysreturn
FTRACE_FN(trace, init)(struct ftrace_printer * p, u64 flags)
{
    struct rbuf *rb;

    if (trace_is_open)
        return -EBUSY;

    if (printer_init(p, flags | TRACE_FLAG_HEADER))
        return -ENOMEM;

    global_rbuf_disable();
    vector_foreach(cpu_rbufs, rb)
        rb->local_idx = rb->read_idx;
    trace_is_open = true;

    return 0;
}

static sysreturn
FTRACE_FN(trace, deinit)(struct ftrace_printer * p)
{
    struct rbuf *rb;

    assert(trace_is_open);
    trace_is_open = false;
    printer_deinit(p);
    vector_foreach(cpu_rbufs, rb)
        rb->local_idx = -1ull;
    global_rbuf_enable();
    return 0;
}

sysreturn
FTRACE_FN(trace, open)(file f)
{
    return FTRACE_FN(trace, init)(&trace_printer, TRACE_FLAG_FILE);
}

sysreturn
FTRACE_FN(trace, close)(file f)
{
    return FTRACE_FN(trace, deinit)(&trace_printer);
}

static sysreturn
FTRACE_FN(trace, get)(struct ftrace_printer * p)
{
    sysreturn rv = 0;
    struct rbuf *rb;

    vector_foreach(cpu_rbufs, rb) {
        rbuf_lock(rb);
        if (ftrace_print_rbuf(p, rb, current_tracer))
            rv = 1;             /* more to print */
        rbuf_unlock(rb);
        if (rv)
            break;
    }

    return rv;
}

static sysreturn
FTRACE_FN(trace, put)(struct ftrace_printer * p)
{
    struct rbuf *rb;

    /* writes clear the trace buffer */
    vector_foreach(cpu_rbufs, rb) {
        rbuf_lock(rb);
        rbuf_reset(rb);
        rbuf_unlock(rb);
    }

    return 0;
}

/* 32 KB: amount of data we will readahead on all queries of trace data. This
 * is especially necessary for non-destructive reads, long sequences of which
 * would otherwise require us to re-generate a lot of buffer entries on every
 * system call
 */
#define TRACE_READ_GRANULARITY  (1ULL << 15)

static u64
get_trace_readahead_size(u64 length, u64 offset)
{
    /* the amount we'll necessarily need to read just to serve "length" bytes */
    u64 toread = length + offset;
    return toread + TRACE_READ_GRANULARITY;
}

/* see if we can serve a read from the existing trace buffer */
static boolean
printer_can_serve_read(struct ftrace_printer * p, u64 length, u64 offset)
{
    u64 pend, uend;

    /* user _could_ have moved its offset back, I suppose */
    if (offset < p->local_offset)
        return false;

    pend = p->local_offset + printer_length(p);
    uend = offset + length;

    /* does printer reach past what the user wants? */
    if (pend >= uend)
        return true;

    return false;
}

sysreturn
FTRACE_FN(trace, read)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;

    /* see if we can handle this with the pre-generated printer data */
    if (printer_can_serve_read(&trace_printer, length, offset)) {
        ret = printer_flush_user(&trace_printer, buf, length, offset);
        assert(ret == length);
        return ret;
    }

    /* ... gotta re-generate it */
    printer_reset(&trace_printer, 0);

    /* set the max size of the printer to the amount that we want */
    printer_set_size(&trace_printer, get_trace_readahead_size(length, offset));

    ret = FTRACE_FN(trace, get)(&trace_printer);
    if (ret < 0)
        return ret;

    return printer_flush_user(&trace_printer, buf, length, offset);
}

sysreturn
FTRACE_FN(trace, write)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;

    printer_reset(&trace_printer, 0);

    ret = FTRACE_FN(trace, put)(&trace_printer);
    if (ret != 0)
        return ret;

    return length;
}

u32
FTRACE_FN(trace, events)(file f)
{
    return EPOLLIN | EPOLLOUT;
}

static sysreturn
FTRACE_FN(trace_clock, get)(struct ftrace_printer * p)
{
    printer_write(p, "x86-tsc\n");
    return 0;
}

/*
 * trace_clock callbacks
 */
sysreturn
FTRACE_FN(trace_clock, read)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;
    struct ftrace_printer p;

    if (printer_init(&p, TRACE_FLAG_FILE))
        return -ENOMEM;

    ret = FTRACE_FN(trace_clock, get)(&p);
    if (ret != 0)
        return ret;

    ret = printer_flush_user(&p, buf, length, offset);
    printer_deinit(&p);
    return ret;
}

sysreturn
FTRACE_FN(trace_clock, write)(file f, void * buf, u64 length, u64 offset)
{
    return 0;
}

u32
FTRACE_FN(trace_clock, events)(file f)
{
    return EPOLLIN;
}

/*
 * trace_pipe callbacks
 *
 * On Linux the differences between trace and trace_pipe are that reads on the
 * latter are destructive and do not disable tracing while the file is open
 */
static struct ftrace_printer trace_pipe_printer;
static boolean trace_pipe_is_open = false;

static sysreturn
FTRACE_FN(trace_pipe, init)(struct ftrace_printer * p, u64 flags)
{
    struct rbuf *rb;

    if (trace_pipe_is_open)
        return -EBUSY;

    if (printer_init(p, flags | TRACE_FLAG_DESTRUCTIVE))
        return -ENOMEM;

    vector_foreach(cpu_rbufs, rb)
        rb->local_idx = rb->read_idx;
    trace_pipe_is_open = true;
    return 0;
}

static sysreturn
FTRACE_FN(trace_pipe, deinit)(struct ftrace_printer * p)
{
    struct rbuf *rb;

    assert(trace_pipe_is_open);
    trace_pipe_is_open = false;
    printer_deinit(p);
    vector_foreach(cpu_rbufs, rb)
        rb->local_idx = -1ull;
    return 0;
}

/* having trace_pipe open does not disable tracing, but
 * to prevent this from running forever we've got to disable
 * it here
 */
static sysreturn
FTRACE_FN(trace_pipe, get)(struct ftrace_printer * p)
{
    struct rbuf *rb;
    sysreturn rv = 0;

    global_rbuf_disable();
    vector_foreach(cpu_rbufs, rb) {
        rbuf_lock(rb);
        if (ftrace_print_rbuf(p, rb, current_tracer))
            rv = 1;             /* more to print */
        rbuf_unlock(rb);
        if (rv)
            break;
    }
    global_rbuf_enable();

    return rv;
}

sysreturn
FTRACE_FN(trace_pipe, open)(file f)
{
    return FTRACE_FN(trace_pipe, init)(&trace_pipe_printer, TRACE_FLAG_FILE);
}

sysreturn
FTRACE_FN(trace_pipe, close)(file f)
{
    return FTRACE_FN(trace_pipe, deinit)(&trace_pipe_printer);
}

sysreturn
FTRACE_FN(trace_pipe, read)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;

    /* destructive -- no nead to do any readahead */
    printer_reset(&trace_pipe_printer, offset);
    printer_set_size(&trace_pipe_printer, length);

    ret = FTRACE_FN(trace_pipe, get)(&trace_pipe_printer);
    if (ret < 0)
        return ret;

    /* this is supposed to block, just send -EAGAIN */
    if (printer_length(&trace_pipe_printer) == 0)
        return -EAGAIN;

    return printer_flush_user(&trace_pipe_printer, buf, length, offset);
}

sysreturn
FTRACE_FN(trace_pipe, write)(file f, void * buf, u64 length, u64 offset)
{
    return -EINVAL;
}

u32
FTRACE_FN(trace_pipe, events)(file f)
{
    u32 mask = 0;
    struct rbuf *rb;

    vector_foreach(cpu_rbufs, rb) {
        rbuf_lock(rb);
        if (rb->count != 0)
            mask |= EPOLLIN;
        rbuf_unlock(rb);
        if (mask)
            break;
    }

    return mask;
}

/*
 * tracing_on callbacks
 */
static sysreturn
FTRACE_FN(tracing_enable_on, get)(struct ftrace_printer * p)
{
    rprintf("ftrace recording on\n");
    tracing_on = 1;
    return 0;
}

static sysreturn
FTRACE_FN(tracing_enable_off, get)(struct ftrace_printer * p)
{
    tracing_on = 0;
    rprintf("ftrace recording off\n");
    return 0;
}

static sysreturn
FTRACE_FN(tracing_on, get)(struct ftrace_printer * p)
{
    printer_write(p, "%d\n", (tracing_on) ? 1 : 0);
    return 0;
}

static sysreturn
FTRACE_FN(tracing_on, put)(struct ftrace_printer * p)
{
    char * str = (char *)buffer_ref(printer_buffer(p), 0);
    boolean old;

    old = tracing_on;
    if (str[0] == '0')
        tracing_on = false;
    else if (str[0]== '1')
        tracing_on = true;
    else
        return -EINVAL;

    if (old != tracing_on) {
        if (tracing_on)
            global_rbuf_enable();
        else
            global_rbuf_disable();
    }

    return 0;
}

sysreturn
FTRACE_FN(tracing_on, read)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;
    struct ftrace_printer p;

    if (printer_init(&p, TRACE_FLAG_FILE))
        return -ENOMEM;

    ret = FTRACE_FN(tracing_on, get)(&p);
    if (ret != 0)
        return ret;

    ret = printer_flush_user(&p, buf, length, offset);
    printer_deinit(&p);
    return ret;
}

sysreturn
FTRACE_FN(tracing_on, write)(file f, void * buf, u64 length, u64 offset)
{
    sysreturn ret;
    struct ftrace_printer p;

    /* write with an offset > 0 doesn't make much sense here */
    if (offset > 0)
        return 0;

    if (length != 1)
        return -EINVAL;

    if (printer_init(&p, TRACE_FLAG_FILE))
        return -ENOMEM;

    assert(buffer_write(printer_buffer(&p), buf, length));
    ret = FTRACE_FN(tracing_on, put)(&p);
    printer_deinit(&p);

    if (ret != 0)
        return ret;

    return length;
}

u32
FTRACE_FN(tracing_on, events)(file f)
{
    return EPOLLIN | EPOLLOUT;
}

#define _INIT(name)     FTRACE_FN(name, init)
#define _DEINIT(name)   FTRACE_FN(name, deinit)
#define _GET(name)      FTRACE_FN(name, get)
#define _PUT(name)      FTRACE_FN(name, put)

#define FTRACE_ROUTINE(a, b, c, d, e, f)\
{\
    .relative_uri = ss_static_init(a),  \
    .init_fn = b,\
    .deinit_fn = c,\
    .get_fn = d,\
    .put_fn = e,\
    .printer = f\
}

static struct ftrace_routine
routine_list[] = {
    FTRACE_ROUTINE(
        "available_tracers", 0, 0, _GET(available_tracers), 0, 0
    ),
    FTRACE_ROUTINE(
        "current_tracer", 0, 0, _GET(current_tracer), _PUT(current_tracer), 0
    ),
    FTRACE_ROUTINE(
        "trace_clock", 0, 0, _GET(trace_clock), 0, 0
    ),
    FTRACE_ROUTINE(
        "tracing_on", 0, 0, _GET(tracing_on), _PUT(tracing_on), 0
    ),
    /* XXX a hack until body content/puts are easily handled */
    FTRACE_ROUTINE(
        "tracing_enable/on", 0, 0, _GET(tracing_enable_on), 0, 0
    ),
    FTRACE_ROUTINE(
        "tracing_enable/off", 0, 0, _GET(tracing_enable_off), 0, 0
    ),
    FTRACE_ROUTINE(
        "trace", _INIT(trace), _DEINIT(trace), _GET(trace), _PUT(trace),
        &trace_printer
    ),
    FTRACE_ROUTINE(
        "trace_pipe", _INIT(trace_pipe), _DEINIT(trace_pipe), _GET(trace_pipe),
        0, &trace_pipe_printer
    )
};
#define FTRACE_NR_ROUTINES (sizeof(routine_list) / sizeof(struct ftrace_routine))

static int
ftrace_find_routine(buffer relative_uri, struct ftrace_routine ** routine_p)
{
    int i;

    for (i = 0; i < FTRACE_NR_ROUTINES; i++) {
        struct ftrace_routine * routine = &(routine_list[i]);

        if (!buffer_compare_with_sstring(relative_uri, routine->relative_uri)) {
            *routine_p = routine;
            return 0;
        }
    }

    return -EINVAL;
}

static buffer
format_usage_buffer(void)
{
    buffer b = allocate_buffer(ftrace_heap, 128);

    bprintf(b, "ftrace files available:\n");
    bprintf(b, "\tTODO list them out\n");

    return b;
}

static void
ftrace_send_http_chunked_response(http_responder handler)
{
    status s;

    s = send_http_chunked_response(handler, timm("ContentType", "text/html"));
    if (!is_ok(s))
        msg_err("ftrace: failed to send HTTP response\n");
}

static void
ftrace_send_http_response(http_responder handler, buffer b)
{
    status s;

    s = send_http_response(handler, timm("ContentType", "text/html"), b);
    if (!is_ok(s))
        msg_err("ftrace: failed to send HTTP response\n");
}

static void
ftrace_send_http_uri_not_found(http_responder handler)
{
    status s;

    s = send_http_response(handler, timm("status", "404 Not Found"),
           aprintf(ftrace_heap, "<html><head><title>404 Not Found</title></head>"
                   "<body><h1>Not Found</h1></body></html>\r\n")
    );
    if (!is_ok(s))
        msg_err("ftrace: failed to send HTTP response\n");
}

static void
ftrace_send_http_no_method(http_responder handler, http_method method)
{
    status s;

    s = send_http_response(handler, timm("status", "501 Not Implemented"),
           aprintf(ftrace_heap, "<html><head><title>501 Not Implemented</title></head>"
                   "<body><h1>Not Implemented</h1></body></html>\r\n")
    );
    if (!is_ok(s))
        msg_err("ftrace: failed to send HTTP response\n");
}

static void
ftrace_send_http_server_error(http_responder handler)
{
    status s;

    s = send_http_response(handler, timm("status", "500 Internal Server Error"),
           aprintf(ftrace_heap, "<html><head><title>500 Internal Server Error</title></head>"
                   "<body><h1>Internal Server Error</h1></body></html>\r\n")
    );
    if (!is_ok(s))
        msg_err("ftrace: failed to send HTTP response\n");
}


static boolean
__ftrace_send_http_chunk_internal(struct ftrace_routine * routine, struct ftrace_printer * p,
                                  boolean local_printer, http_responder out)
{
    sysreturn ret;
    ret = routine->get_fn(p);

    /* no real error handling for http get here */
    if (ret < 0) {
        msg_err("get failed with %d\n", ret);
        return false;
    }

    status s = send_http_chunk(out, printer_buffer(p));
    if (!is_ok(s))
        goto send_http_chunk_failed;

    if (ret) {
        /* reset printer for next chunk */
        p->flags &= ~TRACE_FLAG_HEADER;
        if (printer_init(p, p->flags) < 0) {
            msg_err("printer_init failed (alloc)\n");
            return false;
        }

        /* ret > 0, so more to send */
        return true;
    }

    /* no more data --> done */
    s = send_http_chunk(out, 0);

    if (routine->deinit_fn) {
        /* deinit without init? */
        assert(routine->init_fn);
        (void)routine->deinit_fn(p);
    }

    if (local_printer)
        printer_deinit(p);

    if (!is_ok(s))
        goto send_http_chunk_failed;

    /* XXX re-enable tracing --- ideally this would move to a completion handler */
    global_rbuf_enable();

    return false;

send_http_chunk_failed:
    msg_err("send_http_chunk failed with %v\n", s);
    return false;
}

#define SEND_HTTP_CHUNK_INTERVAL_MS     (milliseconds(75))

/* simultaneous requests might present issues, so ... don't do them?? */
closure_function(4, 2, void, __ftrace_send_http_chunk,
                 struct ftrace_routine *, routine, struct ftrace_printer *, p,
                 boolean, local_printer, http_responder, out,
                 u64 expiry, u64 overruns)
{
    if (overruns != timer_disabled &&
        __ftrace_send_http_chunk_internal(bound(routine), bound(p),
                                          bound(local_printer), bound(out))) {
        register_timer(kernel_timers, &bound(p)->t, CLOCK_ID_MONOTONIC, SEND_HTTP_CHUNK_INTERVAL_MS,
                       false, 0, (timer_handler)closure_self());
    } else {
        closure_finish();
    }
}

static void
__ftrace_do_http_method(http_responder out, struct ftrace_routine * routine,
                        boolean is_put, buffer put_data)
{
    sysreturn ret;
    struct ftrace_printer local_p;
    struct ftrace_printer * p;
    boolean local_printer;

    /* init */
    if (routine->init_fn) {
        assert(routine->printer);
        ret = routine->init_fn(routine->printer, TRACE_FLAG_HTTP);
        if (ret != 0)
            goto internal_err;

        local_printer = false;
        p = routine->printer;
    } else {
        ret = printer_init(&local_p, TRACE_FLAG_HTTP);
        if (ret != 0)
            goto internal_err;

        local_printer = true;
        p = &local_p;
    }

    /* no caching for now -- maybe we'll need lengths/offsets at some point ... */
    printer_reset(p, 0);

    /* set the max size of the printer to the largest possible */
    printer_set_size(p, TRACE_PRINTER_MAX_SIZE);

    /* XXX disable any more tracing while we're spooling this out ... */
    global_rbuf_disable();

    /* get/put */
    if (is_put) {
        if (put_data)
            printer_write_sstring(p, buffer_to_sstring(put_data));
        ret = routine->put_fn(p);
        if (ret != 0) {
            if (routine->deinit_fn) {
                /* deinit without init? */
                assert(routine->init_fn);
                (void)routine->deinit_fn(p);
            }

            if (local_printer)
                printer_deinit(p);

            goto internal_err;
        }
        ftrace_send_http_response(out, printer_buffer(p));
    } else {
        ftrace_send_http_chunked_response(out);
        if (__ftrace_send_http_chunk_internal(routine, p, local_printer, out))
        {
            timer_handler t = closure(ftrace_heap, __ftrace_send_http_chunk, routine,
                p, local_printer, out);
            register_timer(kernel_timers, &p->t, CLOCK_ID_MONOTONIC, SEND_HTTP_CHUNK_INTERVAL_MS, false, 0, t);
        }
    }

    return;

internal_err:
    if (ret != 0)
        ftrace_send_http_server_error(out);
}

static void
ftrace_do_http_get(http_responder handler, struct ftrace_routine * routine)
{
    __ftrace_do_http_method(handler, routine, false, 0);
}


static void
ftrace_do_http_put(http_responder handler, struct ftrace_routine * routine,
                   buffer put_data)
{
    __ftrace_do_http_method(handler, routine, true, put_data);
}

closure_func_basic(http_request_handler, void, ftrace_http_request,
                   http_method method, http_responder handler, value val)
{
    buffer relative_uri;
    struct ftrace_routine * routine;
    int ret;

    relative_uri = table_find(val, sym(relative_uri));
    if (relative_uri == 0) {
        ftrace_send_http_response(handler, format_usage_buffer());
        return;
    }

    ret = ftrace_find_routine(relative_uri, &routine);
    if (ret != 0) {
        ftrace_send_http_uri_not_found(handler);
        return;
    }

    switch (method) {
    case HTTP_REQUEST_METHOD_GET:
        assert(routine->get_fn);
        ftrace_do_http_get(handler, routine);
        break;

    case HTTP_REQUEST_METHOD_PUT:
        /* XXX: no PUT support yet */
        if (1 || !routine->put_fn)
            goto no_method;

        ftrace_do_http_put(handler, routine, 0);
        break;

    no_method:
    default:
        ftrace_send_http_no_method(handler, method);
        break;
    }
}

static int
init_http_listener(void)
{
    status s;

    ftrace_hl = allocate_http_listener(ftrace_heap, FTRACE_TRACE_PORT);
    if (ftrace_hl == INVALID_ADDRESS) {
        msg_err("could not allocate ftrace HTTP listener\n");
        return -1;
    }

    http_register_uri_handler(
        ftrace_hl,
        ss(FTRACE_TRACE_URI),
        closure_func(ftrace_heap, http_request_handler, ftrace_http_request)
    );

    s = listen_port(ftrace_heap, FTRACE_TRACE_PORT,
        connection_handler_from_http_listener(ftrace_hl)
    );
    if (!is_ok(s)) {
        msg_err("listen_port(port=%d) failed for ftrace HTTP listener\n",
            FTRACE_TRACE_PORT
        );
        deallocate_http_listener(ftrace_heap, ftrace_hl);
        return -1;
    }

    rprintf("started DEBUG http listener on port %d\n", FTRACE_TRACE_PORT);

    return 0;
}

int
ftrace_init(unix_heaps uh, filesystem fs)
{
    int ret;
    cpuinfo ci;

    ftrace_heap = heap_locked(&(uh->kh));
    rbuf_heap = (heap)heap_page_backed(&(uh->kh));

    cpu_rbufs = allocate_vector(ftrace_heap, total_processors);
    if (cpu_rbufs == INVALID_ADDRESS) {
        msg_err("unable to allocate rbufs vector\n");
        return -1;
    }
    u64 per_cpu_kb = DEFAULT_TRACE_ARRAY_SIZE_KB / total_processors;

    vector_foreach(cpuinfos, ci) {
        struct rbuf *rb = allocate_rbuf(ftrace_heap, per_cpu_kb);
        if (rb == INVALID_ADDRESS) {
            msg_err("unable to allocate cpu rbuf\n");
            return -1;
        }
        vector_set(cpu_rbufs, ci->id, rb);
        rb->ci = ci;
    }

    /* init http listener */
    ret = init_http_listener();
    if (ret != 0)
        return ret;

    /* nop tracer */
    current_tracer = &(tracer_list[0]);
    vector_foreach(cpuinfos, ci) {
        if (ftrace_cpu_init(ci) != 0)
            return -1;
    }
    return 0;
}

void
ftrace_deinit(void)
{
    cpuinfo ci;
    vector_foreach(cpuinfos, ci) {
        ftrace_cpu_deinit(ci);
    }
    deallocate_http_listener(ftrace_heap, ftrace_hl);
}

int
ftrace_cpu_init(cpuinfo ci)
{
    ci->graph_stack = allocate(ftrace_heap,
        sizeof(struct ftrace_graph_entry) * FTRACE_RETFUNC_DEPTH
    );
    if (ci->graph_stack == INVALID_ADDRESS) {
        msg_err("failed to allocare ftrace return stack array\n");
        return -ENOMEM;
    }

    ci->graph_idx = 0;
    ci->m.ftrace_disable_cnt = 1;
    return 0;
}

NOTRACE void
ftrace_cpu_deinit(cpuinfo ci)
{
    struct rbuf *rb = vector_get(cpu_rbufs, ci->id);
    assert(rb != 0);
    rbuf_disable(rb);
    timestamp t = now(CLOCK_ID_MONOTONIC_RAW);
    while (ci->graph_idx > 0) {
        struct ftrace_graph_entry * stack_ent =
                &(ci->graph_stack[--ci->graph_idx]);
        stack_ent->return_ts = t;
        if (ci->graph_idx == 0)
        stack_ent->flush = 1;
        function_graph_trace_return(stack_ent);
    }

    deallocate(ftrace_heap, ci->graph_stack,
        sizeof(struct ftrace_graph_entry) * FTRACE_RETFUNC_DEPTH
    );

    ci->graph_idx = FTRACE_THREAD_DISABLE_IDX;
    ci->graph_stack = 0;

    rbuf_enable(rb);
}

/*
 * Record the switch event, and record completion times for any functions
 * on the incoming thread's call stack
 */
NOTRACE void
ftrace_thread_switch(thread out, thread in)
{
    struct rbuf *rb = vector_get(cpu_rbufs, current_cpu()->id);
    assert(rb != 0);
    if (!rbuf_enabled(rb) ||
        (current_tracer != &tracer_list[FTRACE_FUNCTION_GRAPH_IDX]))
    {
        current_cpu()->graph_idx = 0;
        return;
    }

    rbuf_disable(rb);

    /* complete any outstanding function calls for outgoing thread */
    timestamp t = now(CLOCK_ID_MONOTONIC_RAW);
    cpuinfo ci = current_cpu();
    while (ci->graph_idx > 0) {
        struct ftrace_graph_entry * stack_ent =
                &(ci->graph_stack[--ci->graph_idx]);
        stack_ent->return_ts = t;
        if (ci->graph_idx == 0)
        stack_ent->flush = 1; //(out != in); /* just controls a printing option */
        function_graph_trace_return(stack_ent);
    }
    /* generate a ctx switch event */
    if (out != in)
        function_graph_trace_switch(out, in);

    rbuf_enable(rb);
}

/* defined in src/x86_64/ftrace.s */
extern void return_to_handler(void);

/*
 * Assume init_unix calls mcache_alloc
 * self  : IP in mcache_alloc() where mcount is invoked
 * parent: stack address where return address sits (from mcache_alloc
 *      back into init_unix; i.e., *parent is an address in init_unix)
 * frame_pointer: frame_pointer during call to mcache_alloc()
 *      - i.e., *(frame_pointer+8) is the return address to get back
 *       from init_unix() to its own parent (in this case, startup())
 *
 * What this function does is moves *parent so that mcache_alloc() returns
 * to a stub of ours that can record the time, before jumping back into
 * init_unix()
 *
 * We save the original return address as well as the frame_pointer on the
 * current thread structure before redirecting the return path to a stub
 * function, return_to_handler (defined in ftrace.s). return_to_handler invokes
 * ftrace_return_to_handler(), defined below, which queries the original return
 * address from the thread structure and jumps directly to it after recording
 * whatever tracing info it needs
 *
 * The frame pointer is just passed so we can sanity check it on function
 * return
 */
NOTRACE void
prepare_ftrace_return(unsigned long self, unsigned long * parent,
                      unsigned long frame_pointer)
{
    struct ftrace_graph_entry * stack_ent;
    unsigned long old;
    int depth;
    cpuinfo ci = current_cpu();
    struct rbuf *rb = vector_get(cpu_rbufs, ci->id);
    assert(rb != 0);

    if (!rbuf_enabled(rb) ||
        (ci->graph_idx == FTRACE_THREAD_DISABLE_IDX))
        return;

    rbuf_disable(rb);

    if (ci->graph_idx == FTRACE_RETFUNC_DEPTH) {
        /* We could just drop it, but let's yell because a call stack this long
         * in kernel code is asking for a stack overflow
         */
        halt("Encountered function call at depth %d!!\n",
            FTRACE_RETFUNC_DEPTH
        );
    }

    /* swap our stub in at retaddr to interpose function return path */
    old = *parent;
    *parent = (unsigned long)&return_to_handler;

    /* save and increment depth */
    depth = ci->graph_idx++;
    stack_ent = &(ci->graph_stack[depth]);
    stack_ent->retaddr = old;
    stack_ent->func = self;
    stack_ent->entry_ts = now(CLOCK_ID_MONOTONIC_RAW);
    stack_ent->fp = frame_pointer;
    stack_ent->depth = depth;
    stack_ent->has_child = 0;
    //stack_ent->retp = parent;
    stack_ent->tid = current ? current->tid : 0;
    stack_ent->cpu = ci->id;

    /* whatever called us has a child */
    if (depth > 0) {
        struct ftrace_graph_entry * parent_ent =
                &(ci->graph_stack[depth - 1]);

        /* push parent onto rbuf if this is the first function it's called */
        if (parent_ent->has_child == 0) {
            parent_ent->has_child = 1;
            function_graph_trace_entry(parent_ent);
        }
    }

    rbuf_enable(rb);
}

/* easier to catch with gdb when this has its own function */
static void frame_halt(struct ftrace_graph_entry * entry, unsigned long fp2)
{
    halt("ftrace: bad frame pointer (0x%lx != 0x%lx); this is a BUG\n"
          " entry->func = %p\n",
        entry->fp, fp2, entry->func
    );
}

NOTRACE unsigned long
ftrace_return_to_handler(unsigned long frame_pointer)
{
    struct ftrace_graph_entry * stack_ent;
    unsigned long retaddr;
    cpuinfo ci = current_cpu();
    struct rbuf *rb = vector_get(cpu_rbufs, ci->id);
    assert(rb != 0);

    rbuf_disable(rb);

    /* restore and decrement depth */
    stack_ent = &(ci->graph_stack[--ci->graph_idx]);

    /* sanity check frame pointer */
    if (stack_ent->fp != frame_pointer)
        frame_halt(stack_ent, frame_pointer);

    stack_ent->return_ts = now(CLOCK_ID_MONOTONIC_RAW);
    stack_ent->flush = 0;
    retaddr = stack_ent->retaddr;

    /* it's possible the current tracer changed after we modified some return
     * addresses, and one of those returns is hitting now ...
     */
    if (current_tracer == &tracer_list[FTRACE_FUNCTION_GRAPH_IDX])
        function_graph_trace_return(stack_ent);

    rbuf_enable(rb);
    return retaddr;
}

/* XXX: remove once we have http PUT support */
void
ftrace_enable(void)
{
    current_tracer = &(tracer_list[FTRACE_FUNCTION_GRAPH_IDX]);
    global_rbuf_enable();
    current_tracer->mcount_toggle(true);
}
