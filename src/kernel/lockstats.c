#include <kernel.h>
#include <net.h>
#include <http.h>
#include <symtab.h>

#define LOCKSTATS_PORT               9090
#define LOCKSTATS_URI                "lockstat"
#define LOCKSTATS_HTTP_CHUNK_MAXSIZE (64*KB)
#define LOCKSTATS_PREALLOC           2048

static heap lockstats_heap;
static http_listener lockstats_hl;

boolean record_lock_stats = false;

static u64 hash_lock_block(lock_block b)
{
    u64 hash = 0xcbf29ce484222325;
    u64 fnv_prime = 1099511628211;
    for (int i = 0; i < MAX_TRACE_DEPTH; i++) {
        if (b->lock_trace[i] == 0)
            break;
        hash ^= b->lock_trace[i];
        hash *= fnv_prime;
    }
    return hash;
}

static inline void save_frame_trace(u64 *trace)
{
    int i;
    u64 *fp = get_current_fp();

    for (i = 0; i < MAX_TRACE_DEPTH; i++) {
        /* simple bounds check for performance and to avoid recursive pt locking */
        if (!is_kernel_memory(fp))
            break;
        u64 *rap = get_frame_ra_ptr(fp, &fp);
        if (rap == 0)
            break;
        trace[i] = *rap;
        if (*rap == 0)
            return;
    }
    if (i < MAX_TRACE_DEPTH)
        trace[i] = 0;
}

lock_stats get_lockstats_block(lockstats_lock l, boolean islocking)
{
    struct lock_block lookup;
    cpuinfo ci = current_cpu();

    if (ci->lock_stats_disable)
        return 0;
    ci->lock_stats_disable = true;

    u64 trace_hash = 0;
    lock_stats stats = 0;
    table t = ci->lock_stats_table;
    if (islocking) {
        lookup.lock_address = u64_from_pointer(l);
        save_frame_trace(lookup.lock_trace);
        trace_hash = hash_lock_block(&lookup);
        stats = table_find(t, (void *)trace_hash);
        if (stats)
            goto out;
        stats = allocate_zero(ci->lock_stats_heap, sizeof(struct lock_stats));
        assert(stats != INVALID_ADDRESS);
        runtime_memcpy(&stats->lock, &lookup, sizeof(struct lock_block));
        stats->lock.type = l->type;
        stats->lock.hash = trace_hash;
        stats->spins_min = -1u;
        stats->hold_time_min = -1u;
        table_set(t, (void *)trace_hash, stats);
    } else if (l->trace_hash) {
        stats = table_find(t, (void *)l->trace_hash);
    }
out:
    ci->lock_stats_disable = false;
    return stats;
}

boolean lockstats_print_u64_with_sym(buffer b, u64 n)
{
    sstring name;
    u64 offset, len;

    name = find_elf_sym(n, &offset, &len);
    boolean found = !sstring_is_null(name);
    if (!found) {
        name = sstring_empty();
        offset = 0;
    }
    bprintf(b, "%p [%s+0x%x]", n, name, offset);
    return found;
}

static boolean stat_sort_reverse(void *a, void *b)
{
    lock_stats sa = a;
    lock_stats sb = b;
    if (sa->cont > sb->cont)
        return false;
    return true;
}

static pqueue log_collate_and_sort(void)
{
    cpuinfo ci;
    pqueue pq = INVALID_ADDRESS;
    boolean record_state = record_lock_stats;
    record_lock_stats = 0;
    table collated = allocate_table(lockstats_heap, identity_key, pointer_equal);
    if (collated == INVALID_ADDRESS)
        goto out;
    vector_foreach(cpuinfos, ci) {
        table_foreach(ci->lock_stats_table, k, v) {
            lock_stats stats = table_find(collated, k);
            if (!stats) {
                stats = allocate_zero(lockstats_heap, sizeof(struct lock_stats));
                assert(stats != INVALID_ADDRESS);
                runtime_memcpy(stats, v, sizeof(struct lock_stats));
                table_set(collated, k, stats);
                continue;
            }
            lock_stats s = v;
            stats->acq += s->acq;
            stats->cont += s->cont;
            stats->tries += s->tries;
            stats->spins_total += s->spins_total;
            if (s->cont) {
                if (s->spins_max > stats->spins_max)
                    stats->spins_max = s->spins_max;
                if (s->spins_min < stats->spins_min)
                    stats->spins_min = s->spins_min;
            }
        }
    }
    pq = allocate_pqueue(lockstats_heap, stat_sort_reverse);
    if (pq == INVALID_ADDRESS)
        goto out;
    table_foreach(collated, k, v) {
        (void)k;
        /* Only print locks with contended acquisitions */
        if (((lock_stats)v)->cont == 0)
            continue;
        pqueue_insert(pq, v);
    }
    deallocate_table(collated);
out:
    record_lock_stats = record_state;
    return pq;
}

static boolean log_output(pqueue pq, buffer b)
{
    lock_stats s;
    buffer tb = little_stack_buffer(4*KB);

    if (pqueue_peek(pq) == INVALID_ADDRESS)
        return false;

    while ((s = pqueue_peek(pq)) != INVALID_ADDRESS) {
        buffer_clear(tb);
        bprintf(tb, "%p %s %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld ", s->lock.lock_address,
            s->lock.type == 0 ? ss("spin") : ss("mutex"), s->acq,
            s->cont, s->tries, s->spins_total,
            s->spins_min, s->spins_max, s->hold_time_total,
            s->hold_time_min, s->hold_time_max, s->sleep_time_total);
        for (int i = 0; i < MAX_TRACE_DEPTH; i++) {
            if (s->lock.lock_trace[i] == 0)
                break;
            if (!lockstats_print_u64_with_sym(tb, s->lock.lock_trace[i]))
                break;
            bprintf(tb, " ");
        }
        bprintf(tb, "\n");
        if (buffer_length(tb) > buffer_space(b))
            break;
        push_buffer(b, tb);
        s = pqueue_pop(pq);
        deallocate(lockstats_heap, s, sizeof(struct lock_stats));
    }
    return true;
}

#define catch_err(s) do {if (!is_ok(s)) msg_err("lockstats: failed to send HTTP response: %v", (s));} while(0)

static void
lockstats_send_http_response(http_responder handler, buffer b)
{
    catch_err(send_http_response(handler, timm("ContentType", "text/html"), b));
}

static inline void lockstats_send_http_chunked_response(http_responder handler)
{
    catch_err(send_http_chunked_response(handler, timm("ContentType", "text/html")));
}

static inline void lockstats_send_http_error(http_responder handler, sstring status, sstring msg)
{
    buffer b = aprintf(lockstats_heap, "<html><head><title>%s %s</title></head>"
                       "<body><h1>%s</h1></body></html>\r\n", status, msg, msg);
    catch_err(send_http_response(handler, timm("status", "%s %s", status, msg), b));
}

static void
lockstats_send_http_uri_not_found(http_responder handler)
{
    lockstats_send_http_error(handler, ss("404"), ss("Not Found"));
}

static void
lockstats_send_http_no_method(http_responder handler, http_method method)
{
    lockstats_send_http_error(handler, ss("501"), ss("Not Implemented"));
}

static void
lockstats_send_http_internal_error(http_responder handler, http_method method)
{
    lockstats_send_http_error(handler, ss("500"), ss("Internal Server Error"));
}

static void
lockstats_do_http_get_log_chunked(http_responder out)
{
    pqueue pq = log_collate_and_sort();
    if (pq == INVALID_ADDRESS) {
        lockstats_send_http_internal_error(out, 0);
        return;
    }
    while (true) {
        buffer b = allocate_buffer(lockstats_heap, LOCKSTATS_HTTP_CHUNK_MAXSIZE);
        assert(b != INVALID_ADDRESS);
        if (!log_output(pq, b)) {
            deallocate_buffer(b);
            break;
        }
        send_http_chunk(out, b);
    }
    deallocate_pqueue(pq);
    send_http_chunk(out, 0);
}

closure_func_basic(http_request_handler, void, lockstats_http_request,
                   http_method method, http_responder handler, value val)
{
    string relative_uri;
    relative_uri = get_string(val, sym(relative_uri));
    if (relative_uri == 0) {
        lockstats_send_http_internal_error(handler, method);
        return;
    }

    if (method != HTTP_REQUEST_METHOD_GET) {
        lockstats_send_http_no_method(handler, method);
        return;
    }
    if (!buffer_strcmp(relative_uri, "log")) {
        lockstats_send_http_chunked_response(handler);
        lockstats_do_http_get_log_chunked(handler);
    } else if (!buffer_strcmp(relative_uri, "enable")) {
        lockstats_send_http_response(handler,
               aprintf(lockstats_heap, "lock profiling enabled\n"));
        record_lock_stats = true;
    } else if (!buffer_strcmp(relative_uri, "disable")) {
        record_lock_stats = false;
        lockstats_send_http_response(handler,
               aprintf(lockstats_heap, "lock profiling disabled\n"));
    } else {
        lockstats_send_http_uri_not_found(handler);
    }
}

static int
init_http_listener(void)
{
    status s;

    lockstats_hl = allocate_http_listener(lockstats_heap, LOCKSTATS_PORT);
    if (lockstats_hl == INVALID_ADDRESS) {
        msg_err("lockstats: could not allocate HTTP listener");
        return -1;
    }

    http_register_uri_handler(
        lockstats_hl,
        ss(LOCKSTATS_URI),
        closure_func(lockstats_heap, http_request_handler, lockstats_http_request)
    );

    s = listen_port(lockstats_heap, LOCKSTATS_PORT,
        connection_handler_from_http_listener(lockstats_hl)
    );
    if (!is_ok(s)) {
        msg_err("lockstats: listen_port(port=%d) failed",
            LOCKSTATS_PORT
        );
        deallocate_http_listener(lockstats_heap, lockstats_hl);
        return -1;
    }

    msg_info("lockstats: started HTTP listener on port %d", LOCKSTATS_PORT);

    return 0;
}

void lockstats_init(kernel_heaps kh)
{
    heap h = heap_general(kh);
    heap backed = (heap)heap_page_backed(kh);
    lockstats_heap = h;
    cpuinfo ci;
    vector_foreach(cpuinfos, ci) {
        ci->lock_stats_table = allocate_table_preallocated(h, backed, identity_key, pointer_equal, LOCKSTATS_PREALLOC);
        ci->lock_stats_heap = (heap)allocate_objcache_preallocated(h, backed,
            sizeof(struct lock_stats), PAGESIZE, LOCKSTATS_PREALLOC, true);
    }
    int ret = init_http_listener();
    if (ret != 0)
        msg_err("lockstats: failed to start HTTP listener");
}
