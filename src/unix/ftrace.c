#include <runtime.h>
#include <unix_internal.h>
#include <ftrace.h>
#include <x86_64.h>
#include <symtab.h>

/* 1MB default size for the user's trace array */
#define DEFAULT_TRACE_ARRAY_SIZE        (1ULL << 20)
#define DEFAULT_TRACE_ARRAY_SIZE_KB     (DEFAULT_TRACE_ARRAY_SIZE >> 10)

#define TRACE_TASK_WIDTH                15
#define TRACE_PID_WIDTH                 5

/* prevent buffers from growing to unbounded sizes */
#define TRACE_PRINTER_INIT_SIZE         (1ULL << 12) /* 4KB */
#define TRACE_PRINTER_FLUSH_SIZE        (1ULL << 18) /* 256KB */

static heap ftrace_heap;

/* whether or not to write into the ring buffer */
static boolean tracing_on = false;

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
    unsigned long max_entries; /* size of buffer */
    unsigned long read_idx;
    unsigned long write_idx;

    unsigned long disable_cnt;
    unsigned long wait_cnt;
    timer trace_timer;
    blockq bq;
};

/* This structure is designed to simply the process of efficiently
 * writing buffers to userspace when the user issues multiple reads
 * with changing offsets
 *
 * This is also needed to persist rbuf contents across calls to read
 * when destructive reads are issued (e.g., if the user reads 4KB of
 * data, it's very likely that the last line of text is going to
 * split an rbuf entry, and we need to maintain at least that half
 * line of data in the buffer b for the liekly subsequent call to
 * read with an incremented offset
 */
struct ftrace_printer {
    buffer b;
    u64 local_offset;
};

struct ftrace_tracer {
    /* human readable */
    const char * name;

    /* trace_fn must be marked as 'no_instrument_function' or else you're gonna
     * blow up the call stack and crash
     */
    void (*trace_fn)(unsigned long, unsigned long);
    void (*mcount_update)(void);

    /* return number of bytes written to user */
    u64 (*print_fn)(struct ftrace_printer * p, struct rbuf * rbuf,
                    boolean header, boolean destructive,
                    void * buf, u64 length, u64 offset);

    /* XXX what else */
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
static inline u64
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

#define printer_offset(p)           (p)->local_offset
#define printer_set_offset(p, o)    (p)->local_offset = o
#define printer_buffer(p)           (p)->b
#define printer_length(p)           (u64)buffer_length(printer_buffer(p))

/*
 * Set the printer's local offset
 */
static inline void
printer_reset(struct ftrace_printer * p, u64 offset)
{
    u64 poff = printer_offset(p);

    if (offset < poff)
        buffer_clear(printer_buffer(p));
    else
        buffer_consume(printer_buffer(p), offset - poff);

    printer_set_offset(p, offset);
}

/*
 * helper to flush printer contents to userspace
 *
 * if the user offset is higher than anything the printer covers, drop
 * the data and update the printer's local offset
 */
static inline u64
printer_write_to_user_offset(struct ftrace_printer * p, void * buf, u64 len,
                             u64 offset)
{
    u64 ret;
    u64 poff, plen, pend;

    poff = printer_offset(p);
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

static inline u64
printer_print_entry(struct ftrace_printer * p, struct rbuf_entry * entry,
                    void (*print_entry)(
                        struct ftrace_printer *,
                        struct rbuf_entry *
                    ),
                    void * buf, u64 length, u64 offset)
{
    u64 len;

    print_entry(p, entry);

    /* no need to print every line to userspace individually, but
     * prevent the buffer from growing overly large with this check
     */
    len = printer_length(p);
    if (len < TRACE_PRINTER_FLUSH_SIZE)
        return 0;

    /* flush to user and reset the printer to the new offset */
    return printer_write_to_user_offset(
        p, buf, length, offset
    );
}

#define rbuf_next_idx(r, idx)   (idx == r->max_entries - 1) ? 0 : idx + 1
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
    rbuf->wait_cnt = 0;
    rbuf->trace_timer = 0;

    /* wake any waiters */
    while (blockq_wake_one(rbuf->bq) != INVALID_ADDRESS);
}

static int
rbuf_init(struct rbuf * rbuf, unsigned long buffer_size_kb)
{
    unsigned long buffer_size = buffer_size_kb << 10;

    rbuf->max_entries = buffer_size / sizeof(struct rbuf_entry);
    rbuf->trace_array = allocate(ftrace_heap,
            sizeof(struct rbuf_entry) * rbuf->max_entries);
    if (rbuf->trace_array == INVALID_ADDRESS) {
        msg_err("failed to allocate ftrace trace array\n");
        return -ENOMEM;
    }

    rbuf->bq = allocate_blockq(ftrace_heap, "ftrace_rbuf");
    if (rbuf->bq == INVALID_ADDRESS) {
        msg_err("failed to allocate ftrace blockq\n");
        deallocate(ftrace_heap, rbuf->trace_array,
            sizeof(struct rbuf_entry) * rbuf->max_entries);
        return -ENOMEM;
    }

    rbuf_reset(rbuf);
    return 0;
}

static inline void
rbuf_disable(struct rbuf * rbuf)
{
    rbuf->disable_cnt++;
}

static inline void
rbuf_enable(struct rbuf * rbuf)
{
    assert(rbuf->disable_cnt);
    rbuf->disable_cnt--;
}

static inline boolean
rbuf_enabled(struct rbuf * rbuf)
{
    return (rbuf->disable_cnt == 0);
}

static inline void
rbuf_wait(struct rbuf * rbuf)
{
    rbuf->wait_cnt++;
}

static inline void
rbuf_release(struct rbuf * rbuf)
{
    assert(rbuf->wait_cnt);
    rbuf->wait_cnt--;
}

static inline boolean
rbuf_has_waiters(struct rbuf * rbuf)
{
    return (rbuf->wait_cnt != 0);
}

/* must be locked before calling */
static inline boolean
__rbuf_acquire_write_entry(struct rbuf * rbuf, struct rbuf_entry ** acquired)
{

    if (rbuf->count == rbuf->max_entries)
        return false;

    rbuf->write_idx = rbuf_next_write_idx(rbuf);
    *acquired = &(rbuf->trace_array[rbuf->write_idx]);
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

    rbuf->read_idx = rbuf_next_read_idx(rbuf);
    *acquired = &(rbuf->trace_array[rbuf->read_idx]);
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

static u64
nop_print(struct ftrace_printer * p, struct rbuf * rbuf, boolean header,
          boolean destructive, void * buf, u64 length, u64 offset)
{
    u64 written = 0;

    if (header) {
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

    /* flush the printer */
    written = printer_write_to_user_offset(
        p,
        buf,
        length,
        offset
    );

    return written;
}

closure_function(1, 0, void, rbuf_wake_all_fn,
                 struct rbuf *, rbuf)
{
    struct rbuf * rbuf = bound(rbuf);

    blockq_wake_one(rbuf->bq);
    rbuf->trace_timer = 0;
    closure_finish();
}

/*
 * There must be a better way than this .... 
 */
static inline void
rbuf_wake_all_deferred(struct rbuf * rbuf)
{
    if (!rbuf_has_waiters(rbuf) || rbuf->trace_timer != 0)
        return;

    rbuf->trace_timer = register_timer(
        0, closure(ftrace_heap, rbuf_wake_all_fn, rbuf)
    );
    assert(rbuf->trace_timer != 0);
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

    /* wake any waiters */
    rbuf_wake_all_deferred(&global_rbuf);

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
do_function_print_entry(struct ftrace_printer * p, struct rbuf_entry * entry)
{
    printer_write(p, " ");
    printer_print_right_adjusted(p, entry->name, TRACE_TASK_WIDTH);
    printer_write(p, "-%d", entry->tid);

    /* pad with spaces as needed */
    {
        int tid, blanks;

        for (tid = entry->tid, blanks = TRACE_PID_WIDTH;
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

static u64
function_print_nondestructive(struct ftrace_printer * p, struct rbuf * rbuf,
                              void * buf, u64 length, u64 offset)
{
    struct rbuf_entry * entry;
    unsigned long idx;
    u64 written, total;

    written = total = 0;

    for (idx  = rbuf->read_idx;
         idx != rbuf->write_idx;
         idx  = rbuf_next_idx(rbuf, idx))
    {
        entry   = &(rbuf->trace_array[idx]);
        written = printer_print_entry(p, entry,
            do_function_print_entry,
            buf + total,
            length - total,
            offset + total
        );

        total += written;
        if (total == length)
            break;
    }

    return total;
}

static u64
function_print_destructive(struct ftrace_printer * p, struct rbuf * rbuf,
                           void * buf, u64 length, u64 offset)
{
    struct rbuf_entry * entry;
    u64 written, total;

    written = total = 0;

    while (__rbuf_acquire_read_entry(rbuf, &entry)) {
        written = printer_print_entry(p, entry,
            do_function_print_entry,
            buf + total,
            length - total,
            offset + total
        );

        total += written;
        if (total == length)
            break;
    }

    return total;
}

static u64
function_print(struct ftrace_printer * p, struct rbuf * rbuf, boolean header,
               boolean destructive, void * buf, u64 length, u64 offset)

{
    u64 written;

    if (header) {
        printer_write(p, "# tracer: function\n");
        printer_write(p, "#\n");
        printer_write(p,
            "# entries-in-buffer/entries-written: %ld/%ld    #P:%d\n",
            global_rbuf.count, global_rbuf.total_written, 1
        );
        printer_write(p, "#\n");
        printer_write(p, "#           TASK-PID   CPU#     TIMESTAMP  FUNCTION\n");
        printer_write(p, "#              | |       |         |         |\n");
    }

    if (destructive)
        written = function_print_destructive(p, rbuf, buf, length, offset);
    else
        written = function_print_nondestructive(p, rbuf, buf, length, offset);

    /* if we've already written the length, we're done */
    assert(written <= length);
    if (written == length)
        return written;

    /* flush the printer */
    written += printer_write_to_user_offset(
        p,
        buf + written,
        length - written,
        offset + written
    );

    return written;
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

static u64
function_graph_print(struct ftrace_printer * p, struct rbuf * rbuf,
                     boolean header, boolean destructive, void * buf, u64 length,
                     u64 offset)
{
    if (header) {
        printer_write(p, "# tracer: function_graph\n");
        printer_write(p, "#\n");
        printer_write(p, "# CPU  DURATION                  FUNCTION CALLS\n");
        printer_write(p, "# |     |   |                     |   |   |   |\n");
    }

    /* TODO */

    return printer_write_to_user_offset(
        p, buf, length, offset
    );
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


/**** Start file operations ****/

/*
 * available_tracers callbacks
 */

/* write space-delimited list of tracer names */
sysreturn
FTRACE_FN(available_tracers, read)(file f, void * buf, u64 length, u64 offset)
{
    int i;
    u64 len;
    buffer b;

    b = allocate_buffer(ftrace_heap, 0);
    if (b == INVALID_ADDRESS)
        return -ENOMEM;

    for (i = 0; i < FTRACE_NR_TRACERS; i++) {
        struct ftrace_tracer * tracer = &(tracer_list[i]);

        if (i)
            bprintf(b , " ");
        bprintf(b, tracer->name);
    }

    bprintf(b, "\n");

    len = write_to_user_offset(b, buf, length, offset);
    deallocate_buffer(b);
    return len;
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

/* write name of current tracer */
sysreturn
FTRACE_FN(current_tracer, read)(file f, void * buf, u64 length, u64 offset)
{
    u64 len;
    buffer b;

    b = allocate_buffer(ftrace_heap, 0);
    if (b == INVALID_ADDRESS)
        return -ENOMEM;

    bprintf(b, "%s\n", current_tracer->name);

    len = write_to_user_offset(b, buf, length, offset);
    deallocate_buffer(b);
    return len;
}

sysreturn
FTRACE_FN(current_tracer, write)(file f, void * buf, u64 length, u64 offset)
{
    int i;
    char * str;

    /* write with an offset > 0 doesn't make much sense here */
    if (offset > 0)
        return 0;

    str = (char *)buf;

    for (i = 0; i < FTRACE_NR_TRACERS; i++) {
        struct ftrace_tracer * tracer = &(tracer_list[i]);
        int len = runtime_strlen(tracer->name);

        if ((length == len) &&
            (runtime_strcmp(tracer->name, str) == 0))
        {
            current_tracer = tracer;
            current_tracer->mcount_update();
            return length;
        }
    }

    return 0;
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

sysreturn
FTRACE_FN(trace, open)(file f)
{
    if (trace_is_open)
        return -EBUSY;

    trace_printer.b = allocate_buffer(ftrace_heap, TRACE_PRINTER_INIT_SIZE);
    if (trace_printer.b == INVALID_ADDRESS) {
        msg_err("failed to allocate ftrace buffer\n");
        return -ENOMEM;
    }

    rbuf_disable(&global_rbuf);
    trace_is_open = true;
    return 0;
}

sysreturn
FTRACE_FN(trace, close)(file f)
{
    assert(trace_is_open);
    trace_is_open = false;
    rbuf_enable(&global_rbuf);
    deallocate_buffer(trace_printer.b);
    return 0;
}

sysreturn
FTRACE_FN(trace, read)(file f, void * buf, u64 length, u64 offset)
{
    u64 len;

    /* trace reads are non-destructive, so we'll regenerate anything that
     * is still sitting in the printer */
    printer_reset(&trace_printer, 0);

    rbuf_lock(&global_rbuf);
    {
        len = current_tracer->print_fn(&trace_printer, &global_rbuf,
            true, false, buf, length, offset
        );
    }
    rbuf_unlock(&global_rbuf);

    return len;
}

sysreturn
FTRACE_FN(trace, write)(file f, void * buf, u64 length, u64 offset)
{
    printer_reset(&trace_printer, 0);

    /* writes clear the trace buffer */
    rbuf_lock(&global_rbuf);
    {
        rbuf_reset(&global_rbuf);
    }
    rbuf_unlock(&global_rbuf);

    return length;
}

u32
FTRACE_FN(trace, events)(file f)
{
    return EPOLLIN | EPOLLOUT;
}

/*
 * trace_clock callbacks
 */
sysreturn
FTRACE_FN(trace_clock, read)(file f, void * buf, u64 length, u64 offset)
{
    int len;
    buffer b;

    b = allocate_buffer(ftrace_heap, 0);
    if (b == INVALID_ADDRESS)
        return -ENOMEM;

    bprintf(b, "x86-tsc\n");

    len = write_to_user_offset(b, buf, length, offset);
    deallocate_buffer(b);

    return len;
}

sysreturn
FTRACE_FN(trace_clock, write)(file f, void * buf, u64 length, u64 offset)
{
    char * str;
    int len;

    /* write with an offset > 0 doesn't make much sense here */
    if (offset > 0)
        return 0;

    str = (char *)buf;
    len = runtime_strlen("x86-tsc");
    if ((len == length) &&
        (runtime_strcmp("x86-tsc", str) == 0))
    {
        return length;
    }

    return -EINVAL;
}

u32
FTRACE_FN(trace_clock, events)(file f)
{
    return EPOLLIN | EPOLLOUT;
}

/*
 * trace_pipe callbacks
 *
 * On Linux the differences between trace and trace_pipe are that reads on the
 * latter are destructive and do not disable tracing while the file is open
 */
static struct ftrace_printer trace_pipe_printer;
static boolean trace_pipe_is_open = false;

sysreturn
FTRACE_FN(trace_pipe, open)(file f)
{
    if (trace_pipe_is_open)
        return -EBUSY;

    trace_pipe_printer.b = allocate_buffer(ftrace_heap, TRACE_PRINTER_INIT_SIZE);
    if (trace_pipe_printer.b == INVALID_ADDRESS) {
        msg_err("failed to allocate ftrace buffer\n");
        return -ENOMEM;
    }

    printer_reset(&trace_pipe_printer, 0);
    trace_pipe_is_open = true;
    return 0;
}

sysreturn
FTRACE_FN(trace_pipe, close)(file f)
{
    assert(trace_pipe_is_open);
    trace_pipe_is_open = false;
    deallocate_buffer(trace_pipe_printer.b);
    return 0;
}

static sysreturn
do_trace_pipe_read(struct ftrace_printer * p, struct rbuf * rbuf, void * buf,
                   u64 length, u64 offset)
{
    u64 len;

    rbuf_lock(rbuf);
    {
        len = current_tracer->print_fn(p, rbuf,
            false, true, buf, length, offset
        );
    }
    rbuf_unlock(rbuf);

    return len;
}

closure_function(7, 2, sysreturn, trace_pipe_read_bh,
                 file, f, struct ftrace_printer *, p, struct rbuf *, rbuf,
                 void *, buf, u64, length, u64, offset, thread, t,
                 boolean, blocked, boolean, nullify)
{
    thread t = bound(t);
    file f = bound(f);
    struct rbuf * rbuf = bound(rbuf);
    sysreturn rv;

    rbuf_disable(rbuf);

    if (nullify) {
        rv = -EINTR;
        goto finish;
    }

    rv = do_trace_pipe_read(
        bound(p), rbuf, bound(buf), bound(length), bound(offset)
    );

    if (rv == 0) {
        if (!blocked)
            rbuf_wait(rbuf);
        rv = infinity;
        goto out;
    }

finish:
    if (blocked) {
        if (rv > 0) {
            f->offset += rv; /* XXX major hack, don't know how to do things like
                              * this without sleepable kernel contexts */
        }
        thread_wakeup(t);
        rbuf_release(rbuf);
    }
    closure_finish();
out:
    rbuf_enable(rbuf);
    return set_syscall_return(t, rv);
}

sysreturn
FTRACE_FN(trace_pipe, read)(file f, void * buf, u64 length, u64 offset)
{
    printer_reset(&trace_pipe_printer, offset);

    return blockq_check(
        global_rbuf.bq,
        current,
        closure(ftrace_heap, trace_pipe_read_bh,
            f, &trace_pipe_printer, &global_rbuf, buf, length, offset, current
        ),
        false
    );
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
sysreturn
FTRACE_FN(tracing_on, read)(file f, void * buf, u64 length, u64 offset)
{
    u64 len;
    buffer b;

    b = allocate_buffer(ftrace_heap, 0);
    if (b == INVALID_ADDRESS)
        return -ENOMEM;

    bprintf(b, "%d\n", (tracing_on) ? 1 : 0);

    len = write_to_user_offset(b, buf, length, offset);
    deallocate_buffer(b);
    return len;
}

sysreturn
FTRACE_FN(tracing_on, write)(file f, void * buf, u64 length, u64 offset)
{
    char * str;

    /* write with an offset > 0 doesn't make much sense here */
    if (offset > 0)
        return 0;

    if (length != 1)
        return -EINVAL;

    str = (char *)buf;
    if (str[0] == '0')
        tracing_on = false;
    else if (str[0]== '1')
        tracing_on = true;
    else
        return -EINVAL;

    return 1;
}

u32
FTRACE_FN(tracing_on, events)(file f)
{
    return EPOLLIN | EPOLLOUT;
}

int
ftrace_init(unix_heaps uh, filesystem fs)
{
    ftrace_heap = heap_general(&(uh->kh));
    rbuf_init(&global_rbuf, DEFAULT_TRACE_ARRAY_SIZE_KB);
    return 0;
}

void
ftrace_deinit(void)
{
}
