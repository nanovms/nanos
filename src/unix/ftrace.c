#include <runtime.h>
#include <unix_internal.h>
#include <ftrace.h>
#include <x86_64.h>
#include <symtab.h>
#include <http.h>

/* 1MB default size for the user's trace array */
#define DEFAULT_TRACE_ARRAY_SIZE        (64ULL << 20)
#define DEFAULT_TRACE_ARRAY_SIZE_KB     (DEFAULT_TRACE_ARRAY_SIZE >> 10)

#define TRACE_TASK_WIDTH    15
#define TRACE_PID_WIDTH     5

/* 4KB; will grow dynamically */
#define TRACE_PRINTER_INIT_SIZE (1ULL << 12)

/* MAX size: larger than 1MB buffers not currently supported on general heap */
#define TRACE_PRINTER_MAX_SIZE  (1ULL << 19)

static heap ftrace_heap;
static heap rbuf_heap;

/* whether or not to write into the ring buffer */
static boolean tracing_on = false;

/* http listener */
static http_listener ftrace_hl;

struct rbuf_entry {
    unsigned long ip;
    unsigned long parent_ip;
    unsigned long tsc;
    unsigned short cpu;
    int tid;
    char name[15]; /* unfortunate but safer than accessing a thread pointer */
};

struct rbuf {
    struct rbuf_entry * trace_array;
    unsigned long count; /* current number of unconsumed items */
    unsigned long total_written; /* total items ever written */
    unsigned long size;
    unsigned long read_idx;
    unsigned long local_idx;    /* index while iterating (but not consuming) */
    unsigned long write_idx;
    word disable_cnt;
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

    /* listed below */
    unsigned long flags;
};

#define TRACE_FLAG_FILE         0x1 /* file based access */
#define TRACE_FLAG_HTTP         0x2 /* http based access */
#define TRACE_FLAG_HEADER       0x4 /* print a header along with the data */
#define TRACE_FLAG_DESTRUCTIVE  0x8 /* reads consume the buffer data */

struct ftrace_tracer {
    /* human readable */
    const char * name;

    /* trace_fn must be marked as 'no_instrument_function' or else you're gonna
     * blow up the call stack and crash
     */
    void (*trace_fn)(unsigned long, unsigned long);
    void (*mcount_update)(void);
    boolean (*print_fn)(struct ftrace_printer * p, struct rbuf * rbuf);
};

struct ftrace_routine {
    /* human readable */
    const char * relative_uri;

    /* some routines need a specific printer */
    struct ftrace_printer * printer;

    sysreturn (*init_fn)(struct ftrace_printer * p, u64 flags);
    sysreturn (*deinit_fn)(struct ftrace_printer * p);
    sysreturn (*get_fn)(struct ftrace_printer * p);
    sysreturn (*put_fn)(struct ftrace_printer * p);
};

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

static inline void
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

/* right-adjust the str within a width of 'width' characters and
 * print to buffer
 */
static inline void
printer_print_right_adjusted(struct ftrace_printer * p, char * str,
                             u16 width)
{
    int len = runtime_strlen(str);

    if (len > width) {
        len = width;
        str[len] = '\0';
    }

    while (len < width) {
        printer_write(p, " ");
        width--;
    }

    printer_write(p, str);
}

static inline void
printer_print_sym(struct ftrace_printer * p, unsigned long ip)
{
    char * name;
    u64 offset, len;

    name = find_elf_sym(ip, &offset, &len);
    if (name)
        printer_write(p, name);
    else
        printer_write(p, "<< unknown symbol >>");
}


#define rbuf_next_idx(r, idx)   (idx == r->size - 1) ? 0 : idx + 1
#define rbuf_next_write_idx(r)  rbuf_next_idx(r, r->write_idx)
#define rbuf_next_read_idx(r)   rbuf_next_idx(r, r->read_idx)

/* these are nops for now, as interrupts are always disabled when
 * we're in kernel
 */
static inline void
rbuf_lock(struct rbuf * rbuf) {}
static inline void
rbuf_unlock(struct rbuf * rbuf) {}

static void
rbuf_reset(struct rbuf * rbuf)
{
    rbuf->count = 0;
    rbuf->read_idx = 0;
    rbuf->write_idx = 0;
    rbuf->total_written = 0;
    rbuf->disable_cnt = 0;
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

    rbuf_reset(rbuf);
    return 0;
}

static inline void
rbuf_disable(struct rbuf * rbuf)
{
    fetch_and_add(&rbuf->disable_cnt, 1);
}

static inline void
rbuf_enable(struct rbuf * rbuf)
{
    assert(fetch_and_add(&rbuf->disable_cnt, -1) > 0);
}

static inline boolean
rbuf_enabled(struct rbuf * rbuf)
{
    return (rbuf->disable_cnt == 0);
}

/* must be locked before calling */
static inline boolean
__rbuf_acquire_write_entry(struct rbuf * rbuf, struct rbuf_entry ** acquired)
{
    if (rbuf->count == rbuf->size - 1)
        return false;

    *acquired = &(rbuf->trace_array[rbuf->write_idx]);

    rbuf->write_idx = rbuf_next_write_idx(rbuf);
    rbuf->count++;
    rbuf->total_written++;

    return true;
}

/* must be locked before calling */
static inline boolean
__rbuf_acquire_read_entry(struct rbuf * rbuf, struct rbuf_entry ** acquired)
{
    if (rbuf->count == 0)
        return false;

    *acquired = &(rbuf->trace_array[rbuf->read_idx]);

    rbuf->read_idx = rbuf_next_read_idx(rbuf);
    rbuf->count--;
    return true;
}

/*
 * These two pointers are queried by mcount() to determine if we've currently
 * enabled tracing
 *
 * They should be set to ftrace_stub to disable tracing, or the associated
 * trace function if active
 */
ftrace_func_t __current_ftrace_trace_fn = ftrace_stub;
ftrace_func_t __current_ftrace_graph_return = ftrace_stub;

/* just a single rbuf for now, though this might need to be per-cpu once we
 * have smp
 */
static struct rbuf global_rbuf;


/*** Start tracer callbacks */

/* nop tracer */
static void
nop_set_mcount(void)
{
    __current_ftrace_trace_fn = ftrace_stub;
    __current_ftrace_graph_return = ftrace_stub;
}

static boolean
nop_print(struct ftrace_printer * p, struct rbuf * rbuf)
{
    if (p->flags & TRACE_FLAG_HEADER) {
        printer_write(p, "# tracer: nop\n");
        printer_write(p, "#\n");
        printer_write(p,
            "# entries-in-buffer/entries-written: %ld/%ld    #P:%d\n",
            global_rbuf.count, global_rbuf.total_written, 1
        );
        printer_write(p, "#\n");
        printer_write(p, "#           TASK-PID   CPU#     TIMESTAMP  FUNCTION\n");
        printer_write(p, "#              | |       |         |         |\n");
    }

    return false;
}

/*
 * Be careful modifying this function.
 *
 * Anything it calls __must__ be marked no_instrument_function
 * or inlined
 */
__attribute__((no_instrument_function)) static void
function_trace(unsigned long ip, unsigned long parent_ip)
{
    struct rbuf_entry * entry;

    if (!tracing_on || !rbuf_enabled(&global_rbuf))
        return;

    /* disable any more events while we're in here */
    rbuf_disable(&global_rbuf);

    rbuf_lock(&global_rbuf);
    if (!__rbuf_acquire_write_entry(&global_rbuf, &entry))
        goto drop;

    entry->cpu = 0;
    entry->tid = current->tid;
    entry->ip = ip;
    entry->parent_ip = parent_ip;
    entry->tsc = rdtsc();
    runtime_memcpy(entry->name, current->name, 15);

out_enable:
    rbuf_unlock(&global_rbuf);
    rbuf_enable(&global_rbuf);
    return;
drop:
    /* XXX count the drop */
    goto out_enable;
}

static void
function_set_mcount(void)
{
    __current_ftrace_trace_fn = function_trace;
}

static inline void
function_print_entry(struct ftrace_printer * p, struct rbuf_entry * entry)
{
    printer_write(p, " ");
    printer_print_right_adjusted(p, entry->name, TRACE_TASK_WIDTH);
    printer_write(p, "-%d", entry->tid);

    /* pad with spaces as needed */
    {
        int tid, blanks;

        for (tid = entry->tid, 
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
    assert(entry->cpu == 0);
    printer_write(p, " [000] ");

    /* timestamp */
    printer_write(p, " %ld: ", entry->tsc);

    /* function and parent */
    printer_print_sym(p, entry->ip);
    printer_write(p, " <-");
    printer_print_sym(p, entry->parent_ip);

    printer_write(p, "\n");
}

static boolean
function_print_nondestructive(struct ftrace_printer * p, struct rbuf * rbuf)
{
    struct rbuf_entry * entry;
    unsigned long idx;

    for (idx  = rbuf->local_idx;
         idx != rbuf->write_idx;
         idx  = rbuf_next_idx(rbuf, idx))
    {
        entry = &(rbuf->trace_array[idx]);
        function_print_entry(p, entry);
        if (printer_length(p) >= printer_size(p))
            break;
    }
    rbuf->local_idx = idx;

    return idx != rbuf->write_idx; /* more */
}

static boolean
function_print_destructive(struct ftrace_printer * p, struct rbuf * rbuf)
{
    struct rbuf_entry * entry;

    while (__rbuf_acquire_read_entry(rbuf, &entry)) {
        function_print_entry(p, entry);
        if (printer_length(p) >= printer_size(p))
            break;
    }

    return rbuf->count > 0;     /* more */
}

static boolean
function_print(struct ftrace_printer * p, struct rbuf * rbuf)

{
    if (p->flags & TRACE_FLAG_HEADER) {
        printer_write(p, "# tracer: function\n");
        printer_write(p, "#\n");
        printer_write(p,
            "# entries-in-buffer/entries-written: %ld/%ld    #P:%d\n",
            global_rbuf.count, global_rbuf.total_written, 1
        );
        printer_write(p, "#\n");
        printer_write(p, "#           TASK-PID   CPU#     TIMESTAMP  FUNCTION\n");
        printer_write(p, "#              | |       |         |         |\n");
        p->flags &= ~TRACE_FLAG_HEADER;
    }

    if (p->flags & TRACE_FLAG_DESTRUCTIVE)
        return function_print_destructive(p, rbuf);
    else
        return function_print_nondestructive(p, rbuf);
}

/*
 * Be careful modifying this function.
 *
 * Anything it calls __must__ be marked no_instrument_function
 * or inlined
 */
__attribute__((no_instrument_function)) static void
function_graph_trace(unsigned long ip, unsigned long parent_ip)
{
    if (!tracing_on)
        return;
}

static void
function_graph_set_mcount(void)
{
    __current_ftrace_trace_fn = ftrace_stub;
    __current_ftrace_graph_return = function_graph_trace;
}

static boolean
function_graph_print(struct ftrace_printer * p, struct rbuf * rbuf)
{
    if (p->flags & TRACE_FLAG_HEADER) {
        printer_write(p, "# tracer: function_graph\n");
        printer_write(p, "#\n");
        printer_write(p, "# CPU  DURATION                  FUNCTION CALLS\n");
        printer_write(p, "# |     |   |                     |   |   |   |\n");
        p->flags &= ~TRACE_FLAG_HEADER;
    }

    /* TODO */
    return false;
}

#define FTRACE_TRACER(_name, _trace_fn, _mcount_update, _print_fn)\
{\
    .name = _name,\
    .trace_fn = _trace_fn,\
    .mcount_update = _mcount_update,\
    .print_fn = _print_fn\
}
static struct ftrace_tracer
tracer_list[] = {
    /* nop must be first */
    FTRACE_TRACER("nop", ftrace_stub, nop_set_mcount, nop_print
    ),
    FTRACE_TRACER("function", function_trace, function_set_mcount,
            function_print
    ),
    FTRACE_TRACER("function_graph", function_graph_trace,
            function_graph_set_mcount, function_graph_print
    )
};
#define FTRACE_NR_TRACERS (sizeof(tracer_list) / sizeof(struct ftrace_tracer))

/* currently running tracer */
struct ftrace_tracer * current_tracer = &(tracer_list[0]);

/**** Start interface operations ****/

static sysreturn
FTRACE_FN(available_tracers, get)(struct ftrace_printer * p)
{
    int i;

    for (i = 0; i < FTRACE_NR_TRACERS; i++) {
        struct ftrace_tracer * tracer = &(tracer_list[i]);

        if (i)
            printer_write(p, " ");
        printer_write(p, tracer->name);
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
    char * str;
    int ret;

    str = allocate(ftrace_heap, printer_length(p) + 1);
    if (str == INVALID_ADDRESS)
        return -ENOMEM;

    runtime_memcpy(str, buffer_ref(printer_buffer(p), 0), printer_length(p));
    str[printer_length(p)] = '\0';

    for (i = 0; i < FTRACE_NR_TRACERS; i++) {
        struct ftrace_tracer * tracer = &(tracer_list[i]);

        if (runtime_strcmp(tracer->name, str) == 0) {
            current_tracer = tracer;
            current_tracer->mcount_update();
            ret = 0;
            goto out;
        }
    }

    ret = -EFAULT;

out:
    deallocate(ftrace_heap, str, printer_length(p) + 1);
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

    buffer_write(printer_buffer(&p), buf, length);
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
    if (trace_is_open)
        return -EBUSY;

    if (printer_init(p, flags | TRACE_FLAG_HEADER))
        return -ENOMEM;

    rbuf_disable(&global_rbuf);
    global_rbuf.local_idx = global_rbuf.read_idx;
    trace_is_open = true;

    return 0;
}

static sysreturn
FTRACE_FN(trace, deinit)(struct ftrace_printer * p)
{
    assert(trace_is_open);
    trace_is_open = false;
    printer_deinit(p);
    global_rbuf.local_idx = -1ull;
    rbuf_enable(&global_rbuf);
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

    rbuf_lock(&global_rbuf);
    {
        if (current_tracer->print_fn(p, &global_rbuf))
            rv = 1;             /* more to print */
    }
    rbuf_unlock(&global_rbuf);

    return rv;
}

static sysreturn
FTRACE_FN(trace, put)(struct ftrace_printer * p)
{
    /* writes clear the trace buffer */
    rbuf_lock(&global_rbuf);
    {
        rbuf_reset(&global_rbuf);
    }
    rbuf_unlock(&global_rbuf);

    return 0;
}

/* 32 KB: amount of data we will readahead on all queries of trace data. This
 * is especailly necessary for non-destructive reads, long sequences of which
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


/* having trace_pipe open does not disable tracing, but 
 * to prevent this from running forever we've got to disable
 * it here 
 */
static sysreturn
FTRACE_FN(trace_pipe, init)(struct ftrace_printer * p, u64 flags)
{
    if (trace_pipe_is_open)
        return -EBUSY;

    if (printer_init(p, flags | TRACE_FLAG_DESTRUCTIVE))
        return -ENOMEM;

    rbuf_disable(&global_rbuf);
    global_rbuf.local_idx = global_rbuf.read_idx;
    trace_pipe_is_open = true;
    return 0;
}

static sysreturn
FTRACE_FN(trace_pipe, deinit)(struct ftrace_printer * p)
{
    assert(trace_pipe_is_open);
    trace_pipe_is_open = false;
    printer_deinit(p);
    global_rbuf.local_idx = -1ull;
    rbuf_enable(&global_rbuf);
    return 0;
}

static sysreturn
FTRACE_FN(trace_pipe, get)(struct ftrace_printer * p)
{
    sysreturn rv = 0;

    rbuf_lock(&global_rbuf);
    {
        if (current_tracer->print_fn(p, &global_rbuf))
            rv = 1;             /* more to print */
    }
    rbuf_unlock(&global_rbuf);
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
    if (ret != 0)
        return ret;

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
    rbuf_lock(&global_rbuf);
    {
        if (global_rbuf.count != 0)
            mask |= EPOLLIN;
    }
    rbuf_unlock(&global_rbuf);

    return mask;
}

/*
 * tracing_on callbacks
 */
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
    if (str[0] == '0')
        tracing_on = false;
    else if (str[0]== '1')
        tracing_on = true;
    else
        return -EINVAL;

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

    buffer_write(printer_buffer(&p), buf, length);
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
    .relative_uri = a,\
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

        if (buffer_compare_with_cstring(relative_uri, routine->relative_uri)) {
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
ftrace_send_http_chunked_response(buffer_handler handler)
{
    status s;

    s = send_http_chunked_response(handler, timm("ContentType", "text/html"));
    if (!is_ok(s))
        msg_err("ftrace: failed to send HTTP response\n");
}

static void 
ftrace_send_http_response(buffer_handler handler, buffer b)
{
    status s;

    s = send_http_response(handler, timm("ContentType", "text/html"), b);
    if (!is_ok(s))
        msg_err("ftrace: failed to send HTTP response\n");
}

static void
ftrace_send_http_uri_not_found(buffer_handler handler)
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
ftrace_send_http_no_method(buffer_handler handler, http_method method)
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
ftrace_send_http_server_error(buffer_handler handler)
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
                                  boolean local_printer, buffer_handler out)
{
    sysreturn ret;
    ret = routine->get_fn(p);

    /* no real error handling for http get here */
    if (ret < 0) {
        msg_err("%s: get failed with %d\n", __func__, ret);
        return false;
    }

    status s = send_http_chunk(out, printer_buffer(p));
    if (!is_ok(s))
        goto send_http_chunk_failed;

    if (ret == 0) {
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
        return false;
    }

    /* reset printer for next chunk */
    if (printer_init(p, p->flags) < 0) {
        msg_err("%s: printer_init failed (alloc)\n", __func__);
        return false;
    }

    /* ret > 0, so more to send */
    return true;
  send_http_chunk_failed:
    msg_err("%s: send_http_chunk failed with %v\n", __func__, s);
    return false;
}

/* simultaneous requests might present issues, so ... don't do them?? */
closure_function(4, 0, void, __ftrace_send_http_chunk,
                 struct ftrace_routine *, routine, struct ftrace_printer *, p, boolean, local_printer, buffer_handler, out)
{
    if (__ftrace_send_http_chunk_internal(bound(routine), bound(p), bound(local_printer), bound(out))) {
        assert(enqueue(runqueue, closure_self()));
    } else {
        closure_finish();
    }
}

static void
__ftrace_do_http_method(buffer_handler out, struct ftrace_routine * routine,
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

    /* get/put */
    if (is_put) {
        printer_write(p, buffer_ref(put_data, 0));
        ret = routine->put_fn(p);
        if (ret != 0) {
            if (routine->deinit_fn) {
                /* deinit without init? */
                assert(routine->init_fn);
                (void)routine->deinit_fn(p);
            }

            if (local_printer)
                printer_deinit(p);
        }
        ftrace_send_http_response(out, printer_buffer(p));
    } else {
        ftrace_send_http_chunked_response(out);
        if (__ftrace_send_http_chunk_internal(routine, p, local_printer, out)) {
            thunk t = closure(ftrace_heap, __ftrace_send_http_chunk, routine, p, local_printer, out);
            assert(enqueue(runqueue, t));
        }
    }
    return;
internal_err:
    if (ret != 0)
        ftrace_send_http_server_error(out);
}


static void
ftrace_do_http_get(buffer_handler handler, struct ftrace_routine * routine)
{
    __ftrace_do_http_method(handler, routine, false, 0);
}


static void
ftrace_do_http_put(buffer_handler handler, struct ftrace_routine * routine,
                   buffer put_data)
{
    __ftrace_do_http_method(handler, routine, true, put_data);
}

closure_function(0, 3, void, ftrace_http_request,
                 http_method, method, buffer_handler, handler, value, val)
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
        FTRACE_TRACE_URI, 
        closure(ftrace_heap, ftrace_http_request)
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

    return 0;
}

int
ftrace_init(unix_heaps uh, filesystem fs)
{
    int ret;

    ftrace_heap = heap_general(&(uh->kh));
    rbuf_heap = heap_backed(&(uh->kh));

    /* init http listener */
    ret = init_http_listener();
    if (ret != 0)
        return ret;

    rbuf_init(&global_rbuf, DEFAULT_TRACE_ARRAY_SIZE_KB);

    /* XXX: remove once we have http PUT support */
    current_tracer = &(tracer_list[1]);
    current_tracer->mcount_update();
    tracing_on = true;

    return 0;
}

void
ftrace_deinit(void)
{
    deallocate_http_listener(ftrace_heap, ftrace_hl);
}
