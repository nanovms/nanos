#include <tfs_internal.h>

#ifdef BOOT // XXX move
#define TLOG_READ_ONLY
#endif

//#define TLOG_DEBUG
//#define TLOG_DEBUG_DUMP
#ifdef TLOG_DEBUG
#define tlog_debug(x, ...) do {rprintf("TLOG: " x, ##__VA_ARGS__);} while(0)
#else
#define tlog_debug(x, ...)
#endif

#define TFS_MAGIC_BYTES 6
static const char *tfs_magic = "NVMTFS";

#define END_OF_LOG 1
#define TUPLE_AVAILABLE 2
#define TUPLE_EXTENDED 3
#define END_OF_SEGMENT 4
#define LOG_EXTENSION_LINK 5

#define COMPLETION_QUEUE_SIZE 10

#define MAX_VARINT_SIZE 10 /* to encode 64 significant bits */

#define TFS_EXTENSION_HEADER_BYTES (TFS_MAGIC_BYTES + 2 * MAX_VARINT_SIZE)
#define TFS_EXTENSION_LINK_BYTES (1 + 2 * MAX_VARINT_SIZE)
#define TFS_LOG_RESERVED_BYTES (TFS_EXTENSION_HEADER_BYTES + TFS_EXTENSION_LINK_BYTES)

typedef struct log *log;
typedef struct log_ext *log_ext;

declare_closure_struct(1, 0, void, log_ext_free,
                       log_ext, ext);

struct log_ext {
    log tl;
    buffer staging;
    boolean open;

    pagecache_node cache_node;
    range sectors;
    sg_io read;
    sg_io write;
    struct refcount refcount;
    closure_struct(log_ext_free, free);
};

struct log {
    heap h;
    filesystem fs;
    table dictionary;
    log_ext current;
    buffer tuple_staging;
    vector encoding_lengths;
    u64 tuple_bytes_remain;

    boolean dirty;
    boolean flushing;
    timer flush_timer;
    vector flush_completions;
};

closure_function(0, 3, void, zero_fill,
                 sg_list, sg, range, q, status_handler, sh)
{
    tlog_debug("%s: zero-fill sg %p, q %R, sh %F\n", __func__, sg, q, sh);
    sg_zero_fill(sg, range_span(q));
    apply(sh, STATUS_OK);
}

closure_function(3, 3, void, log_storage_op,
                 filesystem, fs, u64, start_sector, block_io, op,
                 sg_list, sg, range, q, status_handler, sh)
{
    int order = bound(fs)->blocksize_order;
    assert((q.start & MASK(order)) == 0);
    assert((range_span(q) & MASK(order)) == 0);
    merge m = allocate_merge(bound(fs)->h, sh);
    status_handler k = apply_merge(m);
    range blocks = range_add(range_rshift(q, order), bound(start_sector));
    tlog_debug("%s: sg %p, q %R, blocks %R, sh %F, op %F\n", __func__,
               sg, q, blocks, sh, bound(op));
    filesystem_storage_op(bound(fs), sg, m, blocks, bound(op));
    apply(k, STATUS_OK);
}

define_closure_function(1, 0, void, log_ext_free,
                        log_ext, ext)
{
    log_ext ext = bound(ext);
    if (ext->staging)
        deallocate_buffer(ext->staging);
    pagecache_deallocate_node(ext->cache_node);
    deallocate(ext->tl->h, ext, sizeof(struct log_ext));
}

static log_ext open_log_extension(log tl, range sectors)
{
    u64 size_bytes = range_span(sectors) << tl->fs->blocksize_order;
    log_ext ext = allocate(tl->h, sizeof(struct log_ext));
    if (ext == INVALID_ADDRESS)
        return ext;
    ext->tl = tl;
    ext->staging = allocate_buffer(tl->h, size_bytes);
    if (ext->staging == INVALID_ADDRESS)
        goto fail_dealloc;
    ext->open = false;
    sg_io r_op = tl->fs->r ? closure(tl->h, log_storage_op, tl->fs, sectors.start, tl->fs->r) :
        closure(tl->h, zero_fill);  /* mkfs */
    sg_io w_op = closure(tl->h, log_storage_op, tl->fs, sectors.start, tl->fs->w);
    ext->cache_node = pagecache_allocate_node(tl->fs->pv, r_op, w_op);
    if (ext->cache_node == INVALID_ADDRESS)
        goto fail_dealloc_staging;

    pagecache_set_node_length(ext->cache_node, TFS_LOG_DEFAULT_EXTENSION_SIZE);
    ext->sectors = sectors;
    ext->read = pagecache_node_get_reader(ext->cache_node);
    ext->write = pagecache_node_get_writer(ext->cache_node);
    init_refcount(&ext->refcount, 1, init_closure(&ext->free, log_ext_free, ext));
    return ext;
  fail_dealloc_staging:
    deallocate_buffer(ext->staging);
  fail_dealloc:
    deallocate(tl->h, ext, sizeof(struct log_ext));
    return INVALID_ADDRESS;
}

static void close_log_extension(log_ext ext)
{
    refcount_release(&ext->refcount);
}

static void dump_staging(log_ext ext)
{
#ifdef TLOG_DEBUG_DUMP
    buffer b = ext->staging;
    u64 z = b->end;
    rprintf("staging contains:\n");
    for (int i = 0; i < 4; i++) {
        b->start = i * 256;
        b->end = b->start + 256;
        rprintf("%X\n", b);
    }
    b->start = 0;
    b->end = z;
#endif
}

#ifndef TLOG_READ_ONLY
closure_function(4, 1, void, flush_log_extension_complete,
                 sg_list, sg, log_ext, ext, boolean, release, status_handler, complete,
                 status, s)
{
    log_ext ext = bound(ext);
    tlog_debug("%s: status %v\n", __func__, s);

    if (bound(release))
        close_log_extension(ext);

    deallocate_sg_list(bound(sg));
    apply(bound(complete), s);
    closure_finish();
}

static void flush_log_extension(log_ext ext, boolean release, status_handler complete)
{
    filesystem fs = ext->tl->fs;
    buffer b = ext->staging;
    dump_staging(ext);
    push_u8(b, END_OF_LOG);
    assert(buffer_length(b) > 0); /* END_OF_LOG, at least */
    assert((b->start & MASK(fs->blocksize_order)) == 0);
    u64 write_bytes = pad(buffer_length(b), fs_blocksize(fs));
    assert(write_bytes <= bytes_from_sectors(fs, range_span(ext->sectors)));

    sg_list sg = allocate_sg_list();
    assert(sg != INVALID_ADDRESS);
    sg_buf sgb = sg_list_tail_add(sg, buffer_length(b));
    sgb->buf = buffer_ref(b, 0);
    sgb->size = write_bytes; /* staging is prealloced to extension size */
    sgb->offset = 0;
    sgb->refcount = 0;

    range r = irangel(b->start, write_bytes);
    tlog_debug("%s: writing r %R, buffer addr %p\n", __func__, r, sgb->buf);
    apply(ext->write, sg, r, closure(ext->tl->h, flush_log_extension_complete,
                                     sg, ext, release, complete));
    if (!release) {
        b->end -= 1;                /* next write removes END_OF_LOG */
        tlog_debug("log ext offset was %d (end %d)\n", b->start, b->end);
        b->start = b->end & ~MASK(fs->blocksize_order); /* next storage write starting here */
        tlog_debug("log ext offset now %d\n", b->start);
        assert(b->end >= b->start);
    }
}

static void log_extension_init(log_ext ext)
{
    assert(!ext->open);
    push_buffer(ext->staging, alloca_wrap_buffer(tfs_magic, TFS_MAGIC_BYTES));
    push_varint(ext->staging, TFS_VERSION);
    push_varint(ext->staging, range_span(ext->sectors));
}

/* complete linkage in (now disembodied - thus long arg list) previous extension */
closure_function(3, 1, void, log_extend_link,
                 log_ext, old_ext, range, sectors, status_handler, sh,
                 status, s)
{
    tlog_debug("linking old extension to new and flushing\n");

    /* add link to close out old extension and commit */
    buffer b = bound(old_ext)->staging;
    push_u8(b, LOG_EXTENSION_LINK);
    push_varint(b, bound(sectors).start);
    push_varint(b, range_span(bound(sectors)));

    /* flush and dispose */
    flush_log_extension(bound(old_ext), true, bound(sh));
}

log_ext log_extend(log tl, u64 size, status_handler sh) {
    tlog_debug("log_extend: tl %p, size 0x%lx\n", tl, size);

    /* allocate new log and write with end of log */
    size >>= tl->fs->blocksize_order;
    u64 offset = allocate_u64((heap)tl->fs->storage, size);
    if (offset == INVALID_PHYSICAL) {
        // TODO should initiate flush of current extension before failing
        return INVALID_ADDRESS;
    }

    /* new log extension */
    range r = irangel(offset, size);
    tlog_debug("new log extension sectors %R\n", r);
    log_ext new_ext = open_log_extension(tl, r);

    /* flush new extension and link on completion */
    log_ext old_ext = tl->current;
    log_extension_init(new_ext);
    tl->current = new_ext;
    flush_log_extension(new_ext, false, closure(tl->h, log_extend_link, old_ext, r, sh));
    return new_ext;
}

#define TUPLE_AVAILABLE_HEADER_SIZE (1 + 2 * MAX_VARINT_SIZE)
#define TUPLE_AVAILABLE_MIN_SIZE (TUPLE_AVAILABLE_HEADER_SIZE + 32 /* arbitrary */)

static inline u64 log_size(log_ext ext)
{
    return bytes_from_sectors(ext->tl->fs, range_span(ext->sectors));
}

static inline boolean log_write_internal(log tl, merge m)
{
    log_ext ext = tl->current;
    assert(ext);

    int n = vector_length(tl->encoding_lengths);
    for (int i = 0; i < n; i++) {
        u64 size;
        u64 written = 0;
        u64 remaining = (u64)vector_get(tl->encoding_lengths, i);
        assert(remaining > 0);
        do {
            assert(buffer_length(tl->tuple_staging) > 0);
            size = log_size(ext);
            u64 min = TFS_EXTENSION_LINK_BYTES + TUPLE_AVAILABLE_MIN_SIZE;
            if (ext->staging->end + min >= size) {
                ext = log_extend(tl, TFS_LOG_DEFAULT_EXTENSION_SIZE, apply_merge(m));
                if (ext == INVALID_ADDRESS)
                    return false;
                size = log_size(ext);
            }
            assert(ext->staging->end + min < size);
            u64 avail = size - (ext->staging->end + TFS_EXTENSION_LINK_BYTES + TUPLE_AVAILABLE_HEADER_SIZE);
            u64 length = MIN(avail, remaining);
            if (written == 0) {
                push_u8(ext->staging, TUPLE_AVAILABLE);
                push_varint(ext->staging, remaining);
            } else {
                push_u8(ext->staging, TUPLE_EXTENDED);
            }
            push_varint(ext->staging, length);
            buffer_write(ext->staging, buffer_ref(tl->tuple_staging, 0), length);
            buffer_consume(tl->tuple_staging, length);
            remaining -= length;
            written += length;
        } while (remaining > 0);
    }
    vector_clear(tl->encoding_lengths);
    return true;
}

closure_function(1, 1, void, log_flush_complete,
                 log, tl,
                 status, s)
{
    /* would need to move these to runqueue if a flush is ever invoked from a tfs op */
    bound(tl)->dirty = false;
    if (bound(tl)->flush_completions) {
        status_handler sh;
        vector_foreach(bound(tl)->flush_completions, sh)
            apply(sh, s);
        vector_clear(bound(tl)->flush_completions);
    }
    bound(tl)->flushing = false;
    closure_finish();
}

void log_flush(log tl, status_handler completion)
{
    tlog_debug("%s: log %p, completion %p, dirty %d\n", __func__, tl, completion, tl->dirty);
    if (!tl->dirty) {
        if (completion)
            apply(completion, STATUS_OK);
        return;
    }
    if (completion)
        vector_push(tl->flush_completions, completion);
    if (tl->flushing)
        return;
    if (tl->flush_timer) {
        remove_timer(tl->flush_timer, 0);
        tl->flush_timer = 0;
    }
    tl->flushing = true;
    merge m = allocate_merge(tl->h, closure(tl->h, log_flush_complete, tl));
    status_handler sh = apply_merge(m);
    if (!log_write_internal(tl, m)) {
        apply(sh, timm("result", "log_write_internal failed"));
        return;
    }
    flush_log_extension(tl->current, false, sh);
}

#ifdef STAGE3
closure_function(1, 1, void, log_flush_timer_expired,
                 log, tl,
                 u64, overruns /* ignored */)
{
    bound(tl)->flush_timer = 0;
    log_flush(bound(tl), 0);
    closure_finish();
}

static void log_set_dirty(log tl)
{
    if (tl->dirty)
        return;
    tl->dirty = true;
    assert(!tl->flush_timer);
    tl->flush_timer = register_timer(runloop_timers, CLOCK_ID_MONOTONIC,
                                     seconds(TFS_LOG_FLUSH_DELAY_SECONDS), false, 0,
                                     closure(tl->h, log_flush_timer_expired, tl));
}
#else
/* mkfs: flush on close */
static void log_set_dirty(log tl)
{
    tl->dirty = true;
}
#endif

void log_write_eav(log tl, tuple e, symbol a, value v)
{
    tlog_debug("log_write_eav: tl %p, e %p, a %b, v %p\n", tl, e, symbol_string(a), v);
    u64 len = buffer_length(tl->tuple_staging);
    encode_eav(tl->tuple_staging, tl->dictionary, e, a, v);
    len = buffer_length(tl->tuple_staging) - len;
    vector_push(tl->encoding_lengths, (void *)len);
    log_set_dirty(tl);
}

void log_write(log tl, tuple t)
{
    tlog_debug("log_write: tl %p, t %p\n", tl, t);
    u64 len = buffer_length(tl->tuple_staging);
    encode_tuple(tl->tuple_staging, tl->dictionary, t);
    len = buffer_length(tl->tuple_staging) - len;
    vector_push(tl->encoding_lengths, (void *)len);
    log_set_dirty(tl);
}

#endif /* !TLOG_READ_ONLY */

static boolean log_parse_tuple(log tl, buffer b)
{
    tuple dv = decode_value(tl->h, tl->dictionary, b);
    tlog_debug("   decoded %v\n", dv);
    if (tagof(dv) != tag_tuple)
        return false;

    fsfile f = 0;
    u64 filelength = infinity;
    tuple t = (tuple)dv;

    table_foreach(t, k, v) {
        if (k == sym(extents)) {
            tlog_debug("extents: %p\n", v);
            /* don't know why this needs to be in fs, it's really tlog-specific */
            if (!(f = table_find(tl->fs->extents, v))) {
                f = allocate_fsfile(tl->fs, t);
                table_set(tl->fs->extents, v, f);
                tlog_debug("   created fsfile %p\n", f);
            } else {
                tlog_debug("   found fsfile %p\n", f);
            }
        } else if (k == sym(filelength)) {
            assert(u64_from_value(v, &filelength));
        }
    }
        
    if (f && filelength != infinity) {
        tlog_debug("   update fsfile length to %ld\n", filelength);
        fsfile_set_length(f, filelength);
    }

    return true;
}

static inline void log_tuple_produce(log tl, buffer b, u64 length)
{
    buffer_write(tl->tuple_staging, buffer_ref(b, 0), length);
    buffer_consume(b, length);
    tl->tuple_bytes_remain -= length;
}

static void log_read(log tl, status_handler sh);

closure_function(4, 1, void, log_read_complete,
                 log_ext, ext, sg_list, sg, u64, length, status_handler, sh,
                 status, read_status)
{
    log_ext ext = bound(ext);
    log tl = ext->tl;
    status s = STATUS_OK;
    status_handler sh = bound(sh);
    u8 frame = 0;
    u64 sector, length, tuple_length;

    if (!is_ok(read_status)) {
        tlog_debug("log_read failure: %v\n", read_status);
        apply(sh, timm_up(read_status, "result", "read failed"));
        closure_finish();
        return;
    }

    /* staging is preallocated to size */
    buffer b = ext->staging;
    u64 n = sg_copy_to_buf_and_release(buffer_ref(b, 0), bound(sg), bound(length));
    buffer_produce(b, n);
    dump_staging(ext);
    tlog_debug("log_read_complete: buffer len %d, status %v\n", buffer_length(b), read_status);
    tlog_debug("-> new log extension, checking magic and version\n");
    if (!ext->open) {
        if (runtime_memcmp(buffer_ref(b, 0), tfs_magic, TFS_MAGIC_BYTES)) {
            s = timm("result", "tfs magic mismatch");
            goto out_apply_status;
        }
        buffer_consume(b, TFS_MAGIC_BYTES);
        u64 version = pop_varint(b);
        if (version != TFS_VERSION) {
            s = timm("result", "tfs version mismatch (read %ld, build %ld)", version, TFS_VERSION);
            goto out_apply_status;
        }
        /* XXX the length is really for validation...so hook it up */
        length = pop_varint(b);
        tlog_debug("%ld sectors\n", length);
        ext->open = true;
    }

    /* need to check bounds */
    while ((frame = pop_u8(b)) != END_OF_LOG) {
        switch (frame) {
        case END_OF_SEGMENT:
            tlog_debug("-> segment boundary\n");
            continue;
        case LOG_EXTENSION_LINK:
            tlog_debug("-> extend link\n");
            sector = pop_varint(b); /* XXX need to complete the error handling here */
            length = pop_varint(b);
            if (length == 0) {
                s = timm("result", "zero-length extension");
                goto out_apply_status;
            }
            range r = irangel(sector, length);
            close_log_extension(ext);
            ext = open_log_extension(tl, r);
            if (ext == INVALID_ADDRESS) {
                s = timm("result", "unable to open log extension");
                goto out_apply_status;
            }
            tl->current = ext;
#ifndef TLOG_READ_ONLY
            if (!filesystem_reserve_storage(tl->fs, r)) {
                s = timm("result", "failed to reserve sectors %R in log extension", r);
                goto out_apply_status;
            }
#endif
            /* chain to next log extension, carrying status handler to end */
            log_read(tl, sh);
            goto out;
        case TUPLE_AVAILABLE:
            tlog_debug("-> tuple available\n");
            if (tl->tuple_bytes_remain > 0) {
                s = timm("result", "TUPLE_AVAILABLE read while already parsing tuple (%ld remaining)",
                         tl->tuple_bytes_remain);
                goto out_apply_status;
            }
            tuple_length = pop_varint(b);
            length = pop_varint(b); /* of segment */
            tlog_debug("tuple total length %ld, available %ld\n", tuple_length, length);
            if (length > tuple_length || length + 1 > buffer_length(b)) {
                s = timm("result", "TUPLE_AVAILABLE read with invalid or short available "
                         "length (%ld, tuple_length: %ld, buffer length: %ld)",
                         length, tuple_length, buffer_length(b));
                goto out_apply_status;
            }
            if (length == tuple_length) {
                /* read at once from log staging */
                log_parse_tuple(tl, b);
            } else {
                /* this tuple is in installments */
                buffer_clear(tl->tuple_staging);
                tl->tuple_bytes_remain = tuple_length;
                log_tuple_produce(tl, b, length);
            }
            break;
        case TUPLE_EXTENDED:
            tlog_debug("-> tuple extended data\n");
            length = pop_varint(b);
            if (length > tl->tuple_bytes_remain) {
                s = timm("result", "TUPLE_EXTENDED read of length %ld, exceeding remainder %ld",
                         length, tl->tuple_bytes_remain);
                goto out_apply_status;
            }
            tlog_debug("need %ld, available %ld\n", tl->tuple_bytes_remain, length);
            log_tuple_produce(tl, b, length);
            if (tl->tuple_bytes_remain == 0) {
                log_parse_tuple(tl, tl->tuple_staging);
                buffer_clear(tl->tuple_staging);
            }
            break;
        default:
            tlog_debug("-> unknown encoding type %d, offset %ld\n", frame, b->start);
            s = timm("result", "unknown frame identifier 0x%x", frame);
            goto out_apply_status;
        }
    }

    assert(frame == END_OF_LOG);
    tlog_debug("-> end of log\n");

    /* the log must go on */
    *(u8*)(b->contents + b->start - 1) = END_OF_SEGMENT;

    /* mark end of log */
    b->end = b->start;
    b->start = 0;
    tlog_debug("   log parse finished, end now at %d\n", b->end);

    /* XXX this will only work for reading the log a single time
       through, but at present that's all we do */
    table_foreach(tl->fs->extents, t, f) {
        table_foreach(t, off, e) {
            tlog_debug("   tlog ingesting sym %p, val %p\n", symbol_string(off), e);
            ingest_extent((fsfile)f, off, e);
        }
    }

    // not sure we should be passing the root.. anyways, splat the
    // log root onto the given root
    table logroot = (table)table_find(tl->dictionary, pointer_from_u64(1));
    if (logroot) {
        // XXX prob better way
        table_foreach (logroot, k, v) {
            table_set(tl->fs->root, k, v);
        }
    }

    if (tl->fs->w) {
        /* Reverse pairs in dictionary so that we can use it for writing
           the next log segment. */
        table newdict = allocate_table(tl->h, identity_key, pointer_equal);
        table_foreach(tl->dictionary, k, v) {
            tlog_debug("   dict swap: k %p, v %p, type %d\n", k, v, tagof(v));
            if (tagof(v) == tag_tuple || tagof(v) == tag_symbol)
                table_set(newdict, v, k);
        }
        deallocate_table(tl->dictionary);
        tl->dictionary = newdict;
    }

  out_apply_status:
    tlog_debug("log_read_complete exit with status %v\n", s);
    buffer_clear(tl->tuple_staging);
    apply(sh, s);
  out:
    closure_finish();
}

static void log_read(log tl, status_handler sh)
{
    log_ext ext = tl->current;
    assert(ext);
    assert(!ext->open);
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        apply(sh, timm("result", "failed to allocate sg list"));
        return;
    }
    range r = irangel(0, bytes_from_sectors(tl->fs, range_span(ext->sectors)));
    status_handler tlc = closure(tl->h, log_read_complete, ext, sg, range_span(r), sh);
    tlog_debug("%s: issuing sg read, sg %p, r %R\n", __func__, sg, r);
    apply(ext->read, sg, r, tlc);
}

log log_create(heap h, filesystem fs, boolean initialize, status_handler sh)
{
    tlog_debug("log_create: heap %p, fs %p, sh %p\n", h, fs, sh);
    log tl = allocate(h, sizeof(struct log));
    if (tl == INVALID_ADDRESS)
        return tl;
    tl->h = h;
    tl->fs = fs;
    tl->dictionary = allocate_table(h, identity_key, pointer_equal);
    if (tl->dictionary == INVALID_ADDRESS)
        goto fail_dealloc_log;
    range sectors = irange(0, TFS_LOG_DEFAULT_EXTENSION_SIZE >> fs->blocksize_order);
    tl->current = open_log_extension(tl, sectors);
    if (tl->current == INVALID_ADDRESS)
        goto fail_dealloc_dict;
#ifndef TLOG_READ_ONLY
    if (!filesystem_reserve_storage(tl->fs, sectors)) {
        msg_err("failed to reserve sectors in allocation map");
        goto fail_dealloc_current;
    }
#endif
    tl->tuple_staging = allocate_buffer(h, PAGESIZE /* arbitrary */);
    if (tl->tuple_staging == INVALID_ADDRESS)
        goto fail_dealloc_current; /* should unreserve sectors */
    tl->encoding_lengths = allocate_vector(h, 512);
    if (tl->encoding_lengths == INVALID_ADDRESS)
        goto fail_dealloc_staging;
    tl->tuple_bytes_remain = 0;
    tl->dirty = false;
    tl->flushing = false;
    tl->flush_timer = 0;
    tl->flush_completions = allocate_vector(tl->h, COMPLETION_QUEUE_SIZE);
    if (tl->flush_completions == INVALID_ADDRESS)
        goto fail_dealloc_encoding_lengths;

    fs->tl = tl;
    if (initialize) {
#ifdef TLOG_READ_ONLY
        halt("no tlog write support\n");
#else
        log_extension_init(tl->current);
        apply(sh, STATUS_OK);
#endif
    } else {
        log_read(tl, sh);
    }
    return tl;
  fail_dealloc_encoding_lengths:
    deallocate_vector(tl->encoding_lengths);
  fail_dealloc_staging:
    deallocate_buffer(tl->tuple_staging);
  fail_dealloc_current:
    refcount_release(&tl->current->refcount);
  fail_dealloc_dict:
    deallocate_table(tl->dictionary);
  fail_dealloc_log:
    deallocate(h, tl, sizeof(struct log));
    return INVALID_ADDRESS;
}

void log_destroy(log tl)
{
    deallocate_vector(tl->flush_completions);
    deallocate_vector(tl->encoding_lengths);
    deallocate_buffer(tl->tuple_staging);
    close_log_extension(tl->current);
    deallocate_table(tl->dictionary);
    deallocate(tl->h, tl, sizeof(*tl));
}
