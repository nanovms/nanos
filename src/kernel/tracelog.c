#include <kernel.h>
#include <http.h>
#include <net.h>
#include <pagecache.h>
#include <tfs.h>

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
#define TRACELOG_COLLATE_TIMER_PERIOD_SEC  1
#define TRACELOG_FILE_WRITE_THRESHOLD      PAGESIZE

declare_closure_struct(2, 0, void, tracelog_send_http_chunk,
                       http_responder, out, buffer, relative_uri);

struct tracelog {
    heap h;
    mutex m;
    struct list collated_entries;
    struct list free_tracelog_buffers;
    bytes n_free;
    bytes alloc_size;
    tuple trace_tags;
    closure_struct(thunk, collator);
    closure_struct(tracelog_send_http_chunk, send_http_chunk);
    http_listener http_listener;
    fsfile logfile;
    sg_io fs_write;
    bytes file_offset;
    struct timer collate_timer;
    closure_struct(timer_handler, collate_timer_func);
    boolean collator_scheduled;
    boolean disabled;
} tracelog;

typedef struct tracelog_buffer {
    struct buffer b;
    struct list l;
    struct refcount refcount;
    value lasttag;
    closure_struct(thunk, free);
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
        async_apply_bh((thunk)&tracelog.collator);
}

static inline void schedule_collator_timer(void)
{
    tracelog_debug("%s\n", func_ss);
    register_timer(kernel_timers, &tracelog.collate_timer, CLOCK_ID_MONOTONIC,
                   seconds(TRACELOG_COLLATE_TIMER_PERIOD_SEC), false, 0,
                   (timer_handler)&tracelog.collate_timer_func);
}

closure_func_basic(timer_handler, void, tracelog_collate_timer_func,
                   u64 expiry, u64 overruns)
{
    if (overruns != timer_disabled) {
        schedule_collator();
        schedule_collator_timer();
    }
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
    smp_write_barrier();
    ci->tracelog_buffer = pointer_from_u64(v ^ TRACELOG_BUFFER_BUSY);
}

closure_function(2, 2, boolean, match_vec_attrs,
                 value, tv, boolean *, match,
                 value a, value v)
{
    /* TODO: revise with tag type updates, maybe compare method */
    if ((is_string(bound(tv)) && is_string(v)) &&
        buffer_compare((buffer)bound(tv), (buffer)v))
        *bound(match) = true;
    return true;
}

closure_function(1, 2, boolean, match_attrs,
                 tuple, attrs,
                 value a, value v)
{
    tuple attrs = bound(attrs);
    if (!attrs)
        return false;
    value tv = get(bound(attrs), a);
    if (!tv)
        return false;
    if (is_composite(v)) {
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
                   te->str_len, entry_len, TRACELOG_ENTRY_SIZE - entry_len,
                   isstring(te->str, te->str_len));
    buffer_produce(b, TRACELOG_ENTRY_SIZE - entry_len);
    if (!buffer_extend(b, TRACELOG_ENTRY_SIZE)) { /* for next */
        msg_err("tracelog: failed to extend buffer; reduce collate threshold, reduce "
                "volume of traces or increase memory; disabling tracing");
        /* TODO consider eating up oldest entries to keep system alive through shutdown */
        tracelog.disabled = true;
    }
}

void vtprintf(symbol tag, tuple attrs, sstring format, vlist *ap)
{
    cpuinfo ci = current_cpu();
    if (tracelog.disabled || !match_tag_and_attrs(tag, attrs))
        return;
    if (!tracelog.m) {
        buffer b = little_stack_buffer(TRACELOG_ENTRY_STRING_SIZE);
        bprintf(b, "[%T, %d, %v] ", now(CLOCK_ID_MONOTONIC), ci->id, tag);
        vbprintf(b, format, ap);
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
                   "entry start %ld\n", func_ss, b, tag, format, buffer_length(b),
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
    vbprintf(teb, format, ap);
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

void tprintf(symbol tag, tuple attrs, sstring format, ...)
{
    vlist ap;
    vstart(ap, format);
    vtprintf(tag, attrs, format, &ap);
    vend(ap);
}

/* mutex held */
closure_func_basic(thunk, void, tracelog_buffer_free_locked)
{
    tracelog_buffer tb = struct_from_closure(tracelog_buffer, free);
    tracelog_debug("%s: tb %p\n", func_ss, tb);
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
    tracelog_debug("%s\n", func_ss);
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
                      init_closure_func(&tb->free, thunk, tracelog_buffer_free_locked));
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

closure_function(4, 1, void, tracelog_file_write_complete,
                 sg_list, sg, buffer, b, status_handler, complete, boolean, flushing,
                 status s)
{
    if (!is_ok(s))
        msg_err("tracelog: failed to %s log: %v", bound(flushing) ? ss("flush") : ss("write to"),
                s);
    if (bound(flushing)) {
        async_apply_status_handler(bound(complete), s);
        closure_finish();
        return;
    }
    deallocate_buffer(bound(b));
    deallocate_sg_list(bound(sg));
    if (bound(complete)) {
        bound(flushing) = true;
        fsfile_flush(tracelog.logfile, false, (status_handler)closure_self());
    } else {
        closure_finish();
    }
}

static void tracelog_buffer_fill_locked(buffer b, bytes threshold)
{
    list_foreach(&tracelog.collated_entries, l) {
        tracelog_entry te = struct_from_list(l, tracelog_entry, l);
        bprintf(b, "[%T, %d, %v", te->t, te->cpu, te->tag);
        if (te->attrs)
            bprintf(b, " %v", te->attrs);
        bprintf(b, "] %s", isstring(te->str, te->str_len));
        list_delete(l);
        release_tracelog_buffer_locked(te->tb);
        if (buffer_length(b) > threshold)
            break;
    }
}

/* mutex held */
static void tracelog_file_write(status_handler complete)
{
    tracelog_debug("%s\n", func_ss);
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS)
        goto fail;
    buffer b = allocate_buffer(tracelog.h, TRACELOG_FILE_WRITE_THRESHOLD);
    if (b == INVALID_ADDRESS)
        goto fail_dealloc_sg;
    tracelog_buffer_fill_locked(b, TRACELOG_FILE_WRITE_THRESHOLD);
    bytes size = buffer_length(b);
    sg_buf sgb = sg_list_tail_add(sg, size);
    if (sgb == INVALID_ADDRESS)
        goto fail_dealloc_buf;
    sgb->buf = buffer_ref(b, 0);
    sgb->size = size;
    sgb->offset = 0;
    sgb->refcount = 0;
    status_handler sh = closure(tracelog.h, tracelog_file_write_complete, sg, b, complete, false);
    if (sh == INVALID_ADDRESS)
        goto fail_dealloc_buf;

    /* advance file offset here in case next write starts before this completes */
    range r = irangel(tracelog.file_offset, size);
    fetch_and_add(&tracelog.file_offset, size);
    apply(tracelog.fs_write, sg, r, sh);
    return;
  fail_dealloc_buf:
    deallocate_buffer(b);
  fail_dealloc_sg:
    deallocate_sg_list(sg);
  fail:
    msg_err("%s: out of memory", func_ss);
    if (complete)
        async_apply_status_handler(complete, timm_oom);
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

static void tracelog_collate(status_handler complete)
{
    pqueue pq = allocate_pqueue(tracelog.h, tracelog_entry_compare);
    assert(pq != INVALID_ADDRESS);

    mutex_lock(tracelog.m);
    for (int i = 0; i < total_processors; i++) {
        cpuinfo ci = cpuinfo_from_id(i);
        tracelog_buffer nb = tracelog.disabled ? 0 : allocate_tracelog_buffer_locked();
        if (nb == INVALID_ADDRESS) {
            msg_err("%s: failed to allocate buffer for cpu %d; disabling tracing", func_ss, i);
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
        msg_err("%s: timeout while waiting for busy buffer on cpu %d", func_ss, i);
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
    if (tracelog.logfile)
        tracelog_file_write(complete);
    else if (complete)
        async_apply_status_handler(complete, STATUS_OK);
    mutex_unlock(tracelog.m);
    deallocate_pqueue(pq);
}

closure_func_basic(thunk, void, tracelog_collator)
{
    tracelog_debug("%s\n", func_ss);
    tracelog.collator_scheduled = false;
    tracelog_collate(0);
}

#define catch_err(s) do {if (!is_ok(s)) msg_err("tracelog: failed to send HTTP response: %v", (s));} while(0)

static inline void tracelog_send_http_response(http_responder handler, buffer b)
{
    catch_err(send_http_response(handler, timm("ContentType", "text/html"), b));
}

static inline void tracelog_send_http_simple_result(http_responder handler, sstring result)
{
    buffer b = aprintf(tracelog.h, "<html><head><title>%s</title></head>"
                       "<body><h1>%s</h1></body></html>\r\n", result, result);
    tracelog_send_http_response(handler, b);
}

static inline void tracelog_send_http_chunked_response(http_responder handler)
{
    catch_err(send_http_chunked_response(handler, timm("ContentType", "text/html")));
}

static inline void tracelog_send_http_error(http_responder handler, sstring status, sstring msg)
{
    buffer b = aprintf(tracelog.h, "<html><head><title>%s %s</title></head>"
                       "<body><h1>%s</h1></body></html>\r\n", status, msg, msg);
    catch_err(send_http_response(handler, timm("status", "%s %s", status, msg), b));
}

static inline void tracelog_send_http_uri_not_found(http_responder handler)
{
    tracelog_send_http_error(handler, ss("404"), ss("Not Found"));
}

static inline void tracelog_send_http_no_method(http_responder handler)
{
    tracelog_send_http_error(handler, ss("501"), ss("Not Implemented"));
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

static boolean tracelog_do_http_get(http_responder out, buffer relative_uri)
{
    tracelog_debug("%s\n", func_ss);
    buffer b = allocate_buffer(tracelog.h, TRACELOG_HTTP_CHUNK_MAXSIZE);
    mutex_lock(tracelog.m);
    tracelog_buffer_fill_locked(b, TRACELOG_HTTP_CHUNK_THRESHOLD);
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
    async_apply((thunk)&tracelog.send_http_chunk);
}

define_closure_function(2, 0, void, tracelog_send_http_chunk,
                        http_responder, out, buffer, relative_uri)
{
    tracelog_debug("%s\n", func_ss);
    if (tracelog_do_http_get(bound(out), bound(relative_uri)))
        schedule_send_http_chunk();
}

closure_func_basic(http_request_handler, void, tracelog_http_request,
                   http_method method, http_responder handler, value val)
{
    string relative_uri = get_string(val, sym(relative_uri));
    tracelog_debug("%s: method %d, handler %p, relative_uri %p\n", func_ss,
                   method, handler, relative_uri);
    switch (method) {
    case HTTP_REQUEST_METHOD_GET:
        if (relative_uri) {
            if (!buffer_strcmp(relative_uri, "enable")) {
                tracelog.disabled = false;
                tracelog_send_http_simple_result(handler, ss("tracelog enabled"));
            } else if (!buffer_strcmp(relative_uri, "disable")) {
                tracelog.disabled = true;
                tracelog_send_http_simple_result(handler, ss("tracelog disabled"));
            } else if (!buffer_strcmp(relative_uri, "clear")) {
                tracelog_collate(0);
                tracelog_clear();
                tracelog_send_http_simple_result(handler, ss("tracelog cleared"));
            } else {
                tracelog_send_http_uri_not_found(handler);
            }
            break;
        }
        tracelog_collate(0);
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
                              ss(TRACELOG_TRACE_URI),
                              closure_func(tracelog.h, http_request_handler,
                                           tracelog_http_request));

    connection_handler ch = connection_handler_from_http_listener(tracelog.http_listener);
    status s = listen_port(tracelog.h, TRACELOG_HTTP_PORT, ch);
    if (is_ok(s)) {
        msg_info("tracelog: started HTTP listener on port %d", TRACELOG_HTTP_PORT);
    } else {
        msg_err("tracelog HTTP: listen_port() (port %d) failed",
                TRACELOG_HTTP_PORT);
        deallocate_http_listener(tracelog.h, tracelog.http_listener);
    }
}

closure_func_basic(shutdown_handler, void, tracelog_shutdown_handler,
                   int status, merge m)
{
    tracelog_debug("%s\n", func_ss);
    tracelog_collate(apply_merge(m));
    closure_finish();
}

static void init_tracelog_file_writer(value v)
{
    tuple file;
    fsfile fsf;

    if (!is_string(v)) {
        msg_err("tracelog: invalid filename: %v", v);
        return;
    }
    filesystem fs = get_root_fs();
    tuple root = filesystem_getroot(fs);
    int s = filesystem_get_node(&fs, fs->get_inode(fs, root),
                                      buffer_to_sstring((buffer)v),
                                      true, true, false, false, &file, &fsf);
    if (s < 0) {
        msg_err("tracelog: failed to open file: %s", string_from_errno(-s));
        return;
    }
    filesystem_put_node(fs, file);
    tracelog.logfile = fsf;
    tracelog.fs_write = pagecache_node_get_writer(fsfile_get_cachenode(tracelog.logfile));
    tracelog.file_offset = fsfile_get_length(tracelog.logfile); /* append */
    add_shutdown_completion(closure_func(tracelog.h, shutdown_handler, tracelog_shutdown_handler));
    schedule_collator_timer();
    msg_info("tracelog file opened, offset %ld", tracelog.file_offset);
}

void init_tracelog_config(tuple root)
{
    tuple tl = get(root, sym(tracelog));
    if (!tl) {
        init_tracelog_http_listener();
        return;
    }

    if (get(tl, sym(disable))) {
        /* don't trace on startup */
        tracelog.disabled = true;
        msg_info("tracelog disabled on start");
    }

    bytes alloc_size;
    if (get_u64(tl, sym(alloc_size), &alloc_size))
        tracelog.alloc_size = alloc_size;

    tracelog.trace_tags = get_tuple(tl, sym(trace_tags));
    value v = get(tl, sym(file));
    if (v)
        init_tracelog_file_writer(v);
    else
        init_tracelog_http_listener();
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
    init_closure_func(&tracelog.collator, thunk, tracelog_collator);
    tracelog.collator_scheduled = false;
    tracelog.disabled = false;
    init_closure_func(&tracelog.collate_timer_func, timer_handler, tracelog_collate_timer_func);
    
    for (int i = 0; i < total_processors; i++) {
        tracelog_buffer b = allocate_tracelog_buffer_locked(); /* don't need lock here */
        assert(b != INVALID_ADDRESS);
        cpuinfo ci = cpuinfo_from_id(i);
        ci->tracelog_buffer = b;
    }
    tracelog.logfile = 0;
    tracelog.fs_write = 0;
    tracelog.file_offset = 0;
}
