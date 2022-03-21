#include <kernel.h>
#include <http.h>
#include <net.h>

//#define TRACELOG_DEBUG
#ifdef TRACELOG_DEBUG
#define tracelog_debug rprintf
#else
#define tracelog_debug(x, ...)
#endif

#define TRACELOG_HTTP_PORT                 9090
#define TRACELOG_TRACE_URI                 "tracelog"
#define TRACELOG_DEFAULT_BUFFER_SIZE       (1 << 19)
#define TRACELOG_SPACE_COLLATE_THRESHOLD   ((TRACELOG_ENTRY_SIZE) * 8)
#define TRACELOG_HTTP_CHUNK_MAXSIZE        (64 << 10)
#define TRACELOG_HTTP_CHUNK_THRESHOLD      (TRACELOG_HTTP_CHUNK_MAXSIZE - \
                                            TRACELOG_ENTRY_SIZE)
#define TRACELOG_COLLATE_SPIN_TIMEOUT      (1ull << 27)
#define TRACELOG_MAX_FREE_BYTES            (TRACELOG_DEFAULT_BUFFER_SIZE * 16)

declare_closure_struct(2, 0, void, tracelog_send_http_chunk,
                       buffer_handler, out, buffer, relative_uri);

declare_closure_struct(0, 0, void, tracelog_collator);

struct tracelog {
    heap h;
    mutex m;
    struct list collated_entries;
    struct list free_tracelog_buffers;
    bytes n_free;
    bytes alloc_size;
    tuple trace_tags;
    closure_struct(tracelog_collator, collator);
    closure_struct(tracelog_send_http_chunk, send_http_chunk);
    http_listener http_listener;
    boolean collator_scheduled;
    boolean disabled;
} tracelog;

declare_closure_struct(1, 0, void, tracelog_buffer_free_locked,
                       struct tracelog_buffer *, tb);

typedef struct tracelog_buffer {
    struct buffer b;
    struct list l;
    struct refcount refcount;
    value lasttag;
    closure_struct(tracelog_buffer_free_locked, free);
} *tracelog_buffer;

#define TRACELOG_ENTRY_SIZE  256
#define TRACELOG_ENTRY_STRING_SIZE (TRACELOG_ENTRY_SIZE - 56)
#define TRACELOG_BUFFER_BUSY 1

typedef struct tracelog_entry {
    timestamp t;                /* 0 */
    symbol tag;                 /* 8 */
    value attrs;                /* 16 */
    u32 cpu;                    /* 24 */
    u32 str_len;
    struct list l;              /* 32 */
    tracelog_buffer tb;         /* 48 */
    char str[TRACELOG_ENTRY_STRING_SIZE]; /* 56 */
} *tracelog_entry;

build_assert(sizeof(struct tracelog_entry) == TRACELOG_ENTRY_SIZE);
build_assert((TRACELOG_ENTRY_SIZE & (TRACELOG_ENTRY_SIZE - 1)) == 0);

#define TRACELOG_HEADER_SIZE (TRACELOG_ENTRY_SIZE - TRACELOG_ENTRY_STRING_SIZE)
#define TRACELOG_OFFSET_MASK (TRACELOG_ENTRY_SIZE - 1)
#define TRACELOG_CAS_BUSY_SPIN_LIMIT 4

static inline void schedule_collator(void)
{
    if (!atomic_swap_boolean(&tracelog.collator_scheduled, true))
        enqueue_irqsafe(runqueue, &tracelog.collator);
}

static inline tracelog_buffer get_tracelog_buffer(cpuinfo ci)
{
    int n = TRACELOG_CAS_BUSY_SPIN_LIMIT;
    u64 w = u64_from_pointer(ci->tracelog_buffer);
    if (!w)
        return 0;
    if (w & TRACELOG_BUFFER_BUSY)
        return pointer_from_u64(w ^ TRACELOG_BUFFER_BUSY);
    while (!compare_and_swap_64((u64*)&ci->tracelog_buffer, w,
                                w | TRACELOG_BUFFER_BUSY)) {
        assert(n-- > 0);
        kern_pause();
        w = u64_from_pointer(ci->tracelog_buffer);
    }
    if (!w)
        ci->tracelog_buffer = 0;
    return pointer_from_u64(w);
}

static inline void put_tracelog_buffer(cpuinfo ci)
{
    u64 v = u64_from_pointer(ci->tracelog_buffer);
    assert(v & TRACELOG_BUFFER_BUSY);
    write_barrier();
    ci->tracelog_buffer = pointer_from_u64(v ^ TRACELOG_BUFFER_BUSY);
}

closure_function(2, 2, boolean, match_vec_attrs,
                 value, tv, boolean *, match,
                 value, a, value, v)
{
    /* TODO: revise with tag type updates, maybe compare method */
    if ((is_string(bound(tv)) && is_string(v)) &&
        buffer_compare((buffer)bound(tv), (buffer)v))
        *bound(match) = true;
    return true;
}

closure_function(1, 2, boolean, match_attrs,
                 tuple, attrs,
                 value, a, value, v)
{
    tuple attrs = bound(attrs);
    if (!attrs)
        return false;
    value tv = get(bound(attrs), a);
    if (!tv)
        return false;
    if (is_tuple(v)) {
        /* We support either a single value for this attribute or a set of
           acceptable values (as a tuple-encoded vector). */
        boolean match = false;
        iterate(v, stack_closure(match_vec_attrs, tv, &match));
        return match;
    }
    /* compares only string attributes, one level deep */
    if (!is_string(tv) || !is_string(v))
        return false;
    return buffer_compare((buffer)tv, (buffer)v);
}

static boolean match_tag_and_attrs(symbol tag, tuple attrs)
{
   if (!tracelog.trace_tags)
       return true;
   assert(is_symbol(tag));
   value v = get(tracelog.trace_tags, tag);
   if (!v)
       return false;
   if (!attrs)
       return true;
   if (is_tuple(v) && !iterate(v, stack_closure(match_attrs, attrs)))
       return false;
   return true;
}

static void close_trace_entry(cpuinfo ci, tracelog_buffer tb)
{
    buffer b = &tb->b;
    push_u8(b, '\0');
    tracelog_entry te = buffer_ref(b, buffer_length(b) & ~TRACELOG_OFFSET_MASK);
    u64 entry_len = buffer_length(b) & TRACELOG_OFFSET_MASK;
    te->str_len = entry_len - TRACELOG_HEADER_SIZE - 1;
    tracelog_debug("   finish: str_len %d entry_len %ld, produce %ld, string:\n%s\n",
                   te->str_len, entry_len, TRACELOG_ENTRY_SIZE - entry_len, te->str);
    buffer_produce(b, TRACELOG_ENTRY_SIZE - entry_len);
    if (!buffer_extend(b, TRACELOG_ENTRY_SIZE)) { /* for next */
        msg_err("failed to extend tracelog buffer; reduce collate threshold, reduce "
                "volume of traces or increase memory; disabling tracing\n");
        /* TODO consider eating up oldest entries to keep system alive through shutdown */
        tracelog.disabled = true;
    }
}

void vtprintf(symbol tag, tuple attrs, const char *format, vlist *ap)
{
    cpuinfo ci = current_cpu();
    if (tracelog.disabled || !match_tag_and_attrs(tag, attrs))
        return;
    if (!tracelog.m) {
        buffer b = little_stack_buffer(TRACELOG_ENTRY_STRING_SIZE);
        buffer f = alloca_wrap_buffer(format, runtime_strlen(format));
        bprintf(b, "[%T, %d, %v] ", now(CLOCK_ID_MONOTONIC), ci->id, tag);
        vbprintf(b, f, ap);
        buffer_print(b);
        return;
    }
    u64 saved_flags = irq_disable_save();
    tracelog_buffer tb = get_tracelog_buffer(ci);
    if (!tb)
        goto out_irq_restore;

    /* A trace print could occur for one tag while a line print for another is
       in progress. For now, just close out the interrupted line with a newline. */
    if (tb->lasttag && tb->lasttag != tag)
        close_trace_entry(ci, tb);
    tb->lasttag = tag;
    buffer b = &tb->b;
    u64 entry_start = buffer_length(b) & ~TRACELOG_OFFSET_MASK;
    u64 entry_offset = buffer_length(b) & TRACELOG_OFFSET_MASK;
    tracelog_debug("%s: buffer %p, tag %v, format \"%s\", buffer_length %ld,\n"
                   "entry start %ld\n", __func__, b, tag, format, buffer_length(b),
                   entry_start);
    tracelog_entry te = buffer_ref(b, entry_start);

    if (entry_offset == 0) {
        tracelog_debug("   new entry at start %ld\n", buffer_length(b));
        assert(buffer_space(b) >= sizeof(struct tracelog_entry));
        te->t = now(CLOCK_ID_MONOTONIC);
        te->tag = tag;
        te->attrs = attrs;
        te->cpu = ci->id;
        /* could avoid storing tb if we used fixed-sized, aligned buffers with headers */
        te->tb = tb;
        entry_offset = TRACELOG_HEADER_SIZE;
        buffer_produce(b, TRACELOG_HEADER_SIZE);
    }

    int remain = TRACELOG_ENTRY_SIZE - entry_offset - 1 /* terminator */;
    assert(remain > 0);

    /* writing to a wrapped buffer takes care of boundaries */
    void *p = buffer_ref(b, entry_start + entry_offset);
    tracelog_debug("   write at %p, remain %ld\n", p, remain);
    buffer teb = alloca_wrap_buffer(p, remain);
    buffer_clear(teb);
    vbprintf(teb, alloca_wrap_buffer(format, runtime_strlen(format)), ap);
    int written = buffer_length(teb);
    if (written == 0)
        goto out_irq_restore;
    buffer_produce(b, written);
    assert((buffer_length(b) & TRACELOG_OFFSET_MASK) != 0);
    if (*(u8*)(buffer_end(b) - 1) == '\n') {
        close_trace_entry(ci, tb);
        if (buffer_space(b) <= TRACELOG_SPACE_COLLATE_THRESHOLD)
            schedule_collator();
        put_tracelog_buffer(ci);
        tb->lasttag = 0;
    }
  out_irq_restore:
    irq_restore(saved_flags);
}

void tprintf(symbol tag, tuple attrs, const char *format, ...)
{
    vlist ap;
    vstart(ap, format);
    vtprintf(tag, attrs, format, &ap);
    vend(ap);
}

/* mutex held */
define_closure_function(1, 0, void, tracelog_buffer_free_locked,
                        tracelog_buffer, tb)
{
    tracelog_debug("%s: tb %p\n", __func__, bound(tb));
    tracelog_buffer tb = bound(tb);
    buffer_clear(&tb->b);
    if (tracelog.n_free < TRACELOG_MAX_FREE_BYTES) {
        list_insert_after(&tracelog.free_tracelog_buffers, &tb->l);
        tracelog.n_free += tb->b.length;
    } else {
        deallocate(tracelog.h, tb->b.contents, tb->b.length);
        deallocate(tracelog.h, tb, sizeof(*tb));
    }
}

/* mutex held */
static tracelog_buffer allocate_tracelog_buffer_locked(void)
{
    tracelog_debug("%s\n", __func__);
    tracelog_buffer tb;
    list l = list_get_next(&tracelog.free_tracelog_buffers);
    if (l) {
        tb = struct_from_list(l, tracelog_buffer, l);
        list_delete(l);
        assert(tracelog.n_free > 0);
        tracelog.n_free -= tb->b.length;
        refcount_set_count(&tb->refcount, 1);
    } else {
        tb = allocate(tracelog.h, sizeof(*tb));
        if (tb == INVALID_ADDRESS)
            return tb;
        void *contents = allocate(tracelog.h, tracelog.alloc_size);
        if (contents == INVALID_ADDRESS) {
            deallocate(tracelog.h, tb, sizeof(*tb));
            return INVALID_ADDRESS;
        }
        assert(contents != INVALID_ADDRESS);
        init_buffer(&tb->b, tracelog.alloc_size, false, tracelog.h, contents);
        list_init_member(&tb->l);
        init_refcount(&tb->refcount, 1,
                      init_closure(&tb->free, tracelog_buffer_free_locked, tb));
        tb->lasttag = 0;
    }
    return tb;
}

static void reserve_tracelog_buffer(tracelog_buffer tb)
{
    refcount_reserve(&tb->refcount);
}

/* must have mutex */
static void release_tracelog_buffer_locked(tracelog_buffer tb)
{
    refcount_release(&tb->refcount);
}

static boolean tracelog_entry_compare(void *za, void *zb)
{
    buffer ba = &((tracelog_buffer)za)->b;
    buffer bb = &((tracelog_buffer)zb)->b;
    assert(buffer_length(ba) > 0 && buffer_length(bb) > 0);

    /* lower time is the higher priority
       TODO suffers the same problem as elsewhere - need to have a static time
       reference and compare deltas instead of absolute timestamps */
    return ((tracelog_entry)buffer_ref(ba, 0))->t > ((tracelog_entry)buffer_ref(bb, 0))->t;
}

static void tracelog_collate(void)
{
    pqueue pq = allocate_pqueue(tracelog.h, tracelog_entry_compare);
    assert(pq != INVALID_ADDRESS);

    mutex_lock(tracelog.m);
    for (int i = 0; i < total_processors; i++) {
        cpuinfo ci = cpuinfo_from_id(i);
        tracelog_buffer nb = tracelog.disabled ? 0 : allocate_tracelog_buffer_locked();
        if (nb == INVALID_ADDRESS) {
            msg_err("failed to allocate tracelog buffer for cpu %d; disabling tracing\n", i);
            tracelog.disabled = true;
            nb = 0;
        }

        tracelog_buffer ob;
        u64 spins_remain = TRACELOG_COLLATE_SPIN_TIMEOUT;
        do {
            ob = ci->tracelog_buffer;
            while (u64_from_pointer(ob) & TRACELOG_BUFFER_BUSY) {
                if (spins_remain-- == 0)
                    goto timeout;
                kern_pause();
                ob = ci->tracelog_buffer;
            }
        } while (!compare_and_swap_64((u64*)&ci->tracelog_buffer, u64_from_pointer(ob),
                                      u64_from_pointer(nb)));

        if (ob) {
            if (buffer_length(&ob->b) > 0)
                pqueue_insert(pq, ob);
            else
                release_tracelog_buffer_locked(ob);
        }
        continue;
      timeout:
        msg_err("timeout while waiting for busy tracelog buffer on cpu %d\n", i);
    }

    tracelog_buffer tb;
    while ((tb = pqueue_pop(pq)) != INVALID_ADDRESS) {
        buffer b = &tb->b;
        assert(buffer_length(b) >= TRACELOG_ENTRY_SIZE);
        tracelog_entry te = buffer_ref(b, 0);
        buffer_consume(b, TRACELOG_ENTRY_SIZE);
        list_insert_before(&tracelog.collated_entries, &te->l);
        if (buffer_length(b) < TRACELOG_ENTRY_SIZE)
            continue;           /* done with buffer; skipped reserve counts as release */
        reserve_tracelog_buffer(tb);
        pqueue_insert(pq, tb);
    }
    mutex_unlock(tracelog.m);
    deallocate_pqueue(pq);
}

define_closure_function(0, 0, void, tracelog_collator)
{
    tracelog_debug("%s\n", __func__);
    tracelog.collator_scheduled = false;
    tracelog_collate();
}

#define catch_err(s) do {if (!is_ok(s)) msg_err("tracelog: failed to send HTTP response: %v\n", (s));} while(0)

static inline void tracelog_send_http_response(buffer_handler handler, buffer b)
{
    catch_err(send_http_response(handler, timm("ContentType", "text/html"), b));
}

static inline void tracelog_send_http_simple_result(buffer_handler handler, const char *result)
{
    buffer b = aprintf(tracelog.h, "<html><head><title>%s</title></head>"
                       "<body><h1>%s</h1></body></html>\r\n", result, result);
    tracelog_send_http_response(handler, b);
}

static inline void tracelog_send_http_chunked_response(buffer_handler handler)
{
    catch_err(send_http_chunked_response(handler, timm("ContentType", "text/html")));
}

static inline void tracelog_send_http_error(buffer_handler handler, const char *status, const char *msg)
{
    buffer b = aprintf(tracelog.h, "<html><head><title>%s %s</title></head>"
                       "<body><h1>%s</h1></body></html>\r\n", status, msg, msg);
    catch_err(send_http_response(handler, timm("status", "%s %s", status, msg), b));
}

static inline void tracelog_send_http_uri_not_found(buffer_handler handler)
{
    tracelog_send_http_error(handler, "404", "Not Found");
}

static inline void tracelog_send_http_no_method(buffer_handler handler)
{
    tracelog_send_http_error(handler, "501", "Not Implemented");
}

static void tracelog_clear(void)
{
    mutex_lock(tracelog.m);
    list_foreach(&tracelog.collated_entries, l) {
        tracelog_entry te = struct_from_list(l, tracelog_entry, l);
        list_delete(l);
        release_tracelog_buffer_locked(te->tb);
    }
    mutex_unlock(tracelog.m);
}

static boolean tracelog_do_http_get(buffer_handler out, buffer relative_uri)
{
    tracelog_debug("%s\n", __func__);
    buffer b = allocate_buffer(tracelog.h, TRACELOG_HTTP_CHUNK_MAXSIZE);
    mutex_lock(tracelog.m);
    list_foreach(&tracelog.collated_entries, l) {
        tracelog_entry te = struct_from_list(l, tracelog_entry, l);
        bprintf(b, "[%T, %d, %v", te->t, te->cpu, te->tag);
        if (te->attrs)
            bprintf(b, " %v", te->attrs);
        bprintf(b, "] %s", te->str);
        list_delete(l);
        release_tracelog_buffer_locked(te->tb);
        if (buffer_length(b) > TRACELOG_HTTP_CHUNK_THRESHOLD)
            break;
    }
    boolean more = !list_empty(&tracelog.collated_entries);
    mutex_unlock(tracelog.m);
    if (buffer_length(b) > 0)
        send_http_chunk(out, b); /* consumes and frees buffer */
    if (!more)
        send_http_chunk(out, 0);
    return more;
}

static inline void schedule_send_http_chunk(void)
{
    enqueue_irqsafe(runqueue, &tracelog.send_http_chunk);
}

define_closure_function(2, 0, void, tracelog_send_http_chunk,
                        buffer_handler, out, buffer, relative_uri)
{
    tracelog_debug("%s\n", __func__);
    if (tracelog_do_http_get(bound(out), bound(relative_uri)))
        schedule_send_http_chunk();
}

closure_function(0, 3, void, tracelog_http_request,
                 http_method, method, buffer_handler, handler, value, val)
{
    string relative_uri = get_string(val, sym(relative_uri));
    tracelog_debug("%s: method %d, handler %p, relative_uri %p\n", __func__,
                   method, handler, relative_uri);
    switch (method) {
    case HTTP_REQUEST_METHOD_GET:
        if (relative_uri) {
            if (buffer_compare_with_cstring(relative_uri, "enable")) {
                tracelog.disabled = false;
                tracelog_send_http_simple_result(handler, "tracelog enabled");
            } else if (buffer_compare_with_cstring(relative_uri, "disable")) {
                tracelog.disabled = true;
                tracelog_send_http_simple_result(handler, "tracelog disabled");
            } else if (buffer_compare_with_cstring(relative_uri, "clear")) {
                tracelog_collate();
                tracelog_clear();
                tracelog_send_http_simple_result(handler, "tracelog cleared");
            } else {
                tracelog_send_http_uri_not_found(handler);
            }
            break;
        }
        tracelog_collate();
        tracelog_send_http_chunked_response(handler);
        if (tracelog_do_http_get(handler, relative_uri)) {
            init_closure(&tracelog.send_http_chunk, tracelog_send_http_chunk, handler, relative_uri);
            schedule_send_http_chunk();
        }
        break;
    case HTTP_REQUEST_METHOD_PUT:
        /* not suported */
    default:
        tracelog_send_http_no_method(handler);
        break;
    }
}

static void init_tracelog_http_listener(void)
{
    tracelog.http_listener = allocate_http_listener(tracelog.h, TRACELOG_HTTP_PORT);
    assert(tracelog.http_listener != INVALID_ADDRESS);
    http_register_uri_handler(tracelog.http_listener,
                              TRACELOG_TRACE_URI,
                              closure(tracelog.h, tracelog_http_request));

    connection_handler ch = connection_handler_from_http_listener(tracelog.http_listener);
    status s = listen_port(tracelog.h, TRACELOG_HTTP_PORT, ch);
    if (is_ok(s)) {
        rprintf("started tracelog http listener on port %d\n", TRACELOG_HTTP_PORT);
    } else {
        msg_err("listen_port() (port %d) failed for tracelog HTTP listener\n",
                TRACELOG_HTTP_PORT);
        deallocate_http_listener(tracelog.h, tracelog.http_listener);
    }
}

void init_tracelog_config(tuple root)
{
    tuple tl = get(root, sym(tracelog));
    if (!tl)
        return;

    if (get(tl, sym(disable))) {
        /* don't trace on startup */
        tracelog.disabled = true;
        rprintf("tracelog disabled on start\n");
    }

    bytes alloc_size;
    if (get_u64(tl, sym(alloc_size), &alloc_size))
        tracelog.alloc_size = alloc_size;

    tracelog.trace_tags = get_tuple(tl, sym(trace_tags));
}

void init_tracelog(heap h)
{
    tracelog.h = h;
    tracelog.m = allocate_mutex(h, 0 /* no spinning */);
    assert(tracelog.m != INVALID_ADDRESS);
    list_init(&tracelog.collated_entries);
    list_init(&tracelog.free_tracelog_buffers);
    tracelog.n_free = 0;
    tracelog.alloc_size = TRACELOG_DEFAULT_BUFFER_SIZE;
    tracelog.trace_tags = 0;
    init_closure(&tracelog.collator, tracelog_collator);
    tracelog.collator_scheduled = false;
    tracelog.disabled = false;
    
    for (int i = 0; i < total_processors; i++) {
        tracelog_buffer b = allocate_tracelog_buffer_locked(); /* don't need lock here */
        assert(b != INVALID_ADDRESS);
        cpuinfo ci = cpuinfo_from_id(i);
        ci->tracelog_buffer = b;
    }
    init_tracelog_http_listener();
}
