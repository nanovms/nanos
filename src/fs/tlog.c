#include <tfs_internal.h>

#ifdef BOOT // XXX move
#define TLOG_READ_ONLY
#endif

//#define TLOG_DEBUG
//#define TLOG_DEBUG_DUMP
#ifdef TLOG_DEBUG
#ifdef KERNEL
#define tlog_debug(x, ...) do {tprintf(sym(tlog), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define tlog_debug(x, ...) do {rprintf(" TLOG: " x, ##__VA_ARGS__);} while(0)
#endif
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
#define TFS_LOG_MAX_TUPLE_STAGING_BYTES (32 * MB)

typedef struct log *log;
typedef struct log_ext *log_ext;

#define tlog_lock(tl)       filesystem_lock(&(tl)->fs->fs)
#define tlog_unlock(tl)     filesystem_unlock(&(tl)->fs->fs)

#ifdef KERNEL

#define tlog_ext_lock_init(ext)    spin_lock_init(&(ext)->lock)
#define tlog_ext_lock(ext)         spin_lock(&(ext)->lock)
#define tlog_ext_unlock(ext)       spin_unlock(&(ext)->lock)

#else

#define tlog_ext_lock_init(ext)
#define tlog_ext_lock(ext)
#define tlog_ext_unlock(ext)

#endif

declare_closure_struct(3, 3, void, log_storage_op,
                       tfs, fs, u64, start_sector, boolean, write,
                       sg_list, sg, range, q, status_handler, sh)
declare_closure_struct(1, 0, void, log_ext_free,
                       log_ext, ext);

struct log_ext {
    log tl;
    struct buffer staging;
    boolean open;
    boolean old_encoding;

    range sectors;
    closure_struct(log_storage_op, read);
    closure_struct(log_storage_op, write);
#ifdef KERNEL
    struct spinlock lock;
#endif
    struct refcount refcount;
    closure_struct(log_ext_free, free);
};

declare_closure_struct(1, 0, void, log_free,
                       log, tl);

struct log {
    heap h;
    tfs fs;
    table dictionary;
    u64 total_entries, obsolete_entries;
    rangemap extensions;
    log_ext current;
    buffer tuple_staging;
    vector encoding_lengths;
    u64 tuple_bytes_remain;

    struct timer flush_timer;
    vector flush_completions;
    boolean dirty;
    boolean flushing;
    enum {
        TLOG_STATE_INIT,
        TLOG_STATE_LINKED,
        TLOG_STATE_COMPACTING,
        TLOG_STATE_FAILED,      /* unrecoverable log failure */
    } state;
    struct refcount refcount;
    closure_struct(log_free, free);
};

define_closure_function(3, 3, void, log_storage_op,
                        tfs, fs, u64, start_sector, boolean, write,
                        sg_list, sg, range, q, status_handler, sh)
{
    int order = bound(fs)->fs.blocksize_order;
    assert((q.start & MASK(order)) == 0);
    assert((range_span(q) & MASK(order)) == 0);
    range blocks = range_add(range_rshift(q, order), bound(start_sector));
    boolean write = bound(write);
    tlog_debug("%s: sg %p, q %R, blocks %R, sh %F, %s\n", func_ss,
               sg, q, blocks, sh, write ? ss("write") : ss("read"));
    filesystem_storage_op(bound(fs), sg, blocks, write, sh);
}

define_closure_function(1, 0, void, log_ext_free,
                        log_ext, ext)
{
    log_ext ext = bound(ext);
    log tl = ext->tl;
    deallocate(tl->fs->dma, ext->staging.contents, ext->staging.length);
    heap h = tl->h;
    deallocate(h, ext, sizeof(struct log_ext));
}

static log_ext open_log_extension(log tl, range sectors)
{
    u64 size_bytes = range_span(sectors) << tl->fs->fs.blocksize_order;
    log_ext ext = allocate(tl->h, sizeof(struct log_ext));
    if (ext == INVALID_ADDRESS)
        return ext;
    ext->tl = tl;
    tfs fs = tl->fs;
    heap dma = fs->dma;
    void *staging = allocate(dma, size_bytes);
    if (staging == INVALID_ADDRESS)
        goto fail_dealloc;
    init_buffer(&ext->staging, size_bytes, true, 0, staging);
    ext->open = false;
    ext->old_encoding = false;
    init_closure(&ext->read, log_storage_op, fs, sectors.start, false);
    init_closure(&ext->write, log_storage_op, fs, sectors.start, true);
    ext->sectors = sectors;
    init_refcount(&ext->refcount, 1, init_closure(&ext->free, log_ext_free, ext));
#ifndef TLOG_READ_ONLY
    tlog_ext_lock_init(ext);
    if (sectors.start != 0) {
        rmnode n = allocate(tl->h, sizeof(*n));
        if (n == INVALID_ADDRESS) {
            goto fail_dealloc_staging;
        }
        rmnode_init(n, sectors);
        rangemap_insert(tl->extensions, n);
    }
#endif
    return ext;
#ifndef TLOG_READ_ONLY
  fail_dealloc_staging:
    deallocate(dma, staging, size_bytes);
#endif
  fail_dealloc:
    deallocate(tl->h, ext, sizeof(struct log_ext));
    return INVALID_ADDRESS;
}

static void close_log_extension(log_ext ext)
{
    refcount_release(&ext->refcount);
}

#ifndef TLOG_READ_ONLY

closure_function(1, 1, boolean, log_dealloc_ext_node,
                 log, tl,
                 rmnode, n)
{
    deallocate(bound(tl)->h, n, sizeof(*n));
    return true;
}

define_closure_function(1, 0, void, log_free,
                        log, tl)
{
    tlog_debug("%s\n", func_ss);
    log_destroy(bound(tl));
}

#endif

static log log_new(heap h, tfs fs)
{
    tlog_debug("new log: heap %p, fs %p\n", h, fs);
    log tl = allocate(h, sizeof(struct log));
    if (tl == INVALID_ADDRESS)
        return tl;
    tl->h = h;
    tl->fs = fs;
    tl->dictionary = allocate_table(h, identity_key, pointer_equal);
    if (tl->dictionary == INVALID_ADDRESS)
        goto fail_dealloc_log;
    tl->tuple_staging = allocate_buffer(h, PAGESIZE /* arbitrary */);
    if (tl->tuple_staging == INVALID_ADDRESS)
        goto fail_dealloc_dict;
    tl->encoding_lengths = allocate_vector(h, 512);
    if (tl->encoding_lengths == INVALID_ADDRESS)
        goto fail_dealloc_staging;
    tl->tuple_bytes_remain = 0;
    tl->dirty = false;
    tl->flushing = false;
    init_timer(&tl->flush_timer);
    tl->flush_completions = allocate_vector(tl->h, COMPLETION_QUEUE_SIZE);
    if (tl->flush_completions == INVALID_ADDRESS)
        goto fail_dealloc_encoding_lengths;
    tl->total_entries = tl->obsolete_entries = 0;
#ifndef TLOG_READ_ONLY
    tl->extensions = allocate_rangemap(h);
    if (tl->extensions == INVALID_ADDRESS) {
        goto fail_dealloc_completions;
    }
    init_refcount(&tl->refcount, 1, init_closure(&tl->free, log_free, tl));
#endif
    range sectors = irange(0, TFS_LOG_INITIAL_SIZE >> fs->fs.blocksize_order);
    tl->current = open_log_extension(tl, sectors);
    if (tl->current == INVALID_ADDRESS) {
#ifndef TLOG_READ_ONLY
        deallocate_rangemap(tl->extensions, stack_closure(log_dealloc_ext_node, tl));
#endif
        goto fail_dealloc_completions;
    }
    return tl;
  fail_dealloc_completions:
    deallocate_vector(tl->flush_completions);
  fail_dealloc_encoding_lengths:
    deallocate_vector(tl->encoding_lengths);
  fail_dealloc_staging:
    deallocate_buffer(tl->tuple_staging);
  fail_dealloc_dict:
    deallocate_table(tl->dictionary);
  fail_dealloc_log:
    deallocate(h, tl, sizeof(struct log));
    return INVALID_ADDRESS;
}

static void dump_staging(log_ext ext)
{
#ifdef TLOG_DEBUG_DUMP
    buffer b = &ext->staging;
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
    tlog_debug("%s: status %v\n", func_ss, s);
    deallocate_sg_list(bound(sg));
    apply(bound(complete), s);
    refcount_release(&ext->refcount);
    if (bound(release))
        close_log_extension(ext);
    closure_finish();
}

static void flush_log_extension(log_ext ext, boolean release, status_handler complete)
{
    refcount_reserve(&ext->refcount);
    tfs fs = ext->tl->fs;
    buffer b = &ext->staging;
    tlog_ext_lock(ext);
    dump_staging(ext);
    push_u8(b, END_OF_LOG);
    assert(buffer_length(b) > 0); /* END_OF_LOG, at least */
    assert((b->start & MASK(fs->fs.blocksize_order)) == 0);
    u64 write_bytes = pad(buffer_length(b), fs_blocksize(&fs->fs));
    assert(write_bytes <= bytes_from_sectors(&fs->fs, range_span(ext->sectors)));

    sg_list sg = allocate_sg_list();
    assert(sg != INVALID_ADDRESS);
    sg_buf sgb = sg_list_tail_add(sg, buffer_length(b));
    assert(sgb != INVALID_ADDRESS);
    sgb->buf = buffer_ref(b, 0);
    sgb->size = write_bytes; /* staging is prealloced to extension size */
    sgb->offset = 0;
    sgb->refcount = 0;

    range r = irangel(b->start, write_bytes);
    tlog_debug("%s: writing r %R, buffer addr %p\n", func_ss, r, sgb->buf);
    apply((sg_io)&ext->write, sg, r, closure(ext->tl->h, flush_log_extension_complete,
                                             sg, ext, release, complete));
    if (!release) {
        b->end -= 1;                /* next write removes END_OF_LOG */
        tlog_debug("log ext offset was %d (end %d)\n", b->start, b->end);
        b->start = b->end & ~MASK(fs->fs.blocksize_order); /* next storage write starting here */
        tlog_debug("log ext offset now %d\n", b->start);
        assert(b->end >= b->start);
    }
    tlog_ext_unlock(ext);
}

static log_ext log_ext_new(log tl)
{
    tfs fs = tl->fs;
    u64 ext_size = filesystem_log_blocks(fs);
    u64 ext_offset;
    if (!filesystem_reserve_log_space(fs, &fs->next_new_log_offset, &ext_offset, ext_size))
        return INVALID_ADDRESS;
    range sectors = irangel(ext_offset, ext_size);
    tlog_debug("new extension at %R\n", sectors);
    return open_log_extension(tl, sectors);
}

static void log_extension_init(log_ext ext)
{
    assert(!ext->open);
    buffer staging = &ext->staging;
    assert(push_buffer(staging, alloca_wrap_buffer(tfs_magic, TFS_MAGIC_BYTES)));
    push_varint(staging, TFS_VERSION);
    push_varint(staging, range_span(ext->sectors));
    if (ext->sectors.start == 0) {
        assert(buffer_write(staging, ext->tl->fs->uuid, UUID_LEN));
        assert(buffer_write_sstring(staging, sstring_from_cstring(ext->tl->fs->label,
                                                                  VOLUME_LABEL_MAX_LEN)));
        push_u8(staging, '\0');   /* label string terminator */
    }
}

/* complete linkage in (now disembodied - thus long arg list) previous extension */
closure_function(3, 1, void, log_extend_link,
                 log_ext, old_ext, range, sectors, status_handler, sh,
                 status, s)
{
    status_handler sh = bound(sh);
    if (!is_ok(s)) {
        apply(sh, s);
        goto out;
    }

    tlog_debug("linking old extension to new and flushing\n");

    /* add link to close out old extension and commit */
    log_ext old_ext = bound(old_ext);
    buffer b = &old_ext->staging;
    push_u8(b, LOG_EXTENSION_LINK);
    push_varint(b, bound(sectors).start);
    push_varint(b, range_span(bound(sectors)));

    /* flush and dispose */
    flush_log_extension(bound(old_ext), true, sh);

  out:
    closure_finish();
}

log_ext log_extend(log tl, u64 size, status_handler sh) {
    tlog_debug("log_extend: tl %p, size 0x%lx\n", tl, size);

    /* allocate new log and write with end of log */
    size >>= tl->fs->fs.blocksize_order;
    u64 offset;
    if (!filesystem_reserve_log_space(tl->fs, &tl->fs->next_extend_log_offset, &offset, size)) {
        apply(sh, timm("result", "failed to extend log"));
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
    return bytes_from_sectors(&ext->tl->fs->fs, range_span(ext->sectors));
}

static inline boolean log_write_internal(log tl, merge m)
{
    log_ext ext = tl->current;
    assert(ext);

    int n = vector_length(tl->encoding_lengths);
    tlog_ext_lock(ext);
    for (int i = 0; i < n; i++) {
        u64 size;
        u64 written = 0;
        u64 remaining = (u64)vector_get(tl->encoding_lengths, i);
        assert(remaining > 0);
        do {
            assert(buffer_length(tl->tuple_staging) > 0);
            size = log_size(ext);
            buffer staging = &ext->staging;
            u64 min = TFS_EXTENSION_LINK_BYTES + TUPLE_AVAILABLE_MIN_SIZE;
            if (staging->end + min >= size || ext->old_encoding) {
                tlog_ext_unlock(ext);
                status_handler sh = apply_merge(m);
                ext = log_extend(tl, TFS_LOG_DEFAULT_EXTENSION_SIZE, sh);
                if (ext == INVALID_ADDRESS)
                    return false;
                size = log_size(ext);
                staging = &ext->staging;
                tlog_ext_lock(ext);
            }
            assert(staging->end + min < size);
            u64 avail = size - (staging->end + TFS_EXTENSION_LINK_BYTES + TUPLE_AVAILABLE_HEADER_SIZE);
            u64 length = MIN(avail, remaining);
            if (written == 0) {
                push_u8(staging, TUPLE_AVAILABLE);
                push_varint(staging, remaining);
            } else {
                push_u8(staging, TUPLE_EXTENDED);
            }
            push_varint(staging, length);

            /* No graceful way to recover from an alloc failure here, and
               flushing could leave the log extension in a corrupt state. */
            assert(buffer_write(staging, buffer_ref(tl->tuple_staging, 0), length));
            buffer_consume(tl->tuple_staging, length);
            remaining -= length;
            written += length;
        } while (remaining > 0);
    }
    tlog_ext_unlock(ext);
    vector_clear(tl->encoding_lengths);
    return true;
}

static void run_flush_completions(log tl, status s)
{
    if (tl->flush_completions) {
        status_handler sh;
        vector_foreach(tl->flush_completions, sh)
#ifdef KERNEL
            async_apply_status_handler(sh, s);
#else
            apply(sh, s);
#endif
        vector_clear(tl->flush_completions);
    }
}

closure_function(1, 1, void, log_flush_complete,
                 log, tl,
                 status, s)
{
    /* would need to move these to runqueue if a flush is ever invoked from a tfs op */
    tlog_lock(bound(tl));
    bound(tl)->dirty = false;
    run_flush_completions(bound(tl), s);
    bound(tl)->flushing = false;
    tlog_unlock(bound(tl));
    refcount_release(&bound(tl)->refcount);
    closure_finish();
}

closure_function(2, 1, void, log_switch_complete,
                 log, old_tl, log, new_tl,
                 status, s)
{
    tlog_debug("%s: status %v\n", func_ss, s);
    log old_tl = bound(old_tl);
    log new_tl = bound(new_tl);
    tfs fs = old_tl->fs;
    filesystem_lock(&fs->fs);
    log to_be_used, to_be_destroyed;
    if (is_ok(s)) {
        to_be_used = new_tl;
        to_be_destroyed = old_tl;
    } else {
        to_be_used = old_tl;
        to_be_destroyed = new_tl;
    }
    to_be_used->state = TLOG_STATE_LINKED;
    filesystem_log_rebuild_done(fs, to_be_used);
    if (is_ok(s))
        table_foreach(old_tl->dictionary, k, v) {
            (void)v;
            if (is_composite(k) && !table_find(new_tl->dictionary, k)) {
                tlog_debug("  destroying value %p\n", __func__, k);
                destruct_value(k, false);
            }
        }
    rangemap_foreach(to_be_destroyed->extensions, ext) {
        tlog_debug("  deallocating extension at %R\n", __func__, ext->r);
        if (!filesystem_free_storage(fs, ext->r))
            msg_err("failed to mark to_be_destroyed log at %R as free", ext->r);
    }

    run_flush_completions(old_tl, s);
    filesystem_unlock(&fs->fs);

    refcount_release(&to_be_destroyed->refcount);
    timm_dealloc(s);
    closure_finish();
}

void log_flush(log tl, status_handler completion)
{
    tlog_debug("%s: log %p, completion %p, dirty %d\n", func_ss, tl, completion, tl->dirty);
    if (!tl->dirty && (tl->state != TLOG_STATE_COMPACTING)) {
        if (completion)
#ifdef KERNEL
            async_apply_status_handler(completion, STATUS_OK);
#else
            apply(completion, STATUS_OK);
#endif
        return;
    }
    if (completion)
        vector_push(tl->flush_completions, completion);
    if (tl->flushing || (tl->state == TLOG_STATE_COMPACTING))
        return;
#ifdef KERNEL
    remove_timer(kernel_timers, &tl->flush_timer, 0);
#endif
    tl->flushing = true;
    refcount_reserve(&tl->refcount);
    merge m = allocate_merge(tl->h, closure(tl->h, log_flush_complete, tl));
    status_handler sh = apply_merge(m);

    /* If we're unable to commit the entire tuple_staging buffer, record an
       unrecoverable failure in the log, but flush the current extension. */
    if (!log_write_internal(tl, m))
        tl->state = TLOG_STATE_FAILED;

    /* completion merge will close out with the flush; compaction is independent */
    tlog_unlock(tl);    /* to allow flush completion to run synchronously */
    flush_log_extension(tl->current, false, sh);
    tlog_lock(tl);

    if ((tl->state == TLOG_STATE_LINKED) && (tl->obsolete_entries >= TFS_LOG_COMPACT_OBSOLETE) &&
        (tl->total_entries <= TFS_LOG_COMPACT_RATIO * tl->obsolete_entries)) {
        tlog_debug("%ld obsolete entries out of %ld, starting log compaction\n",
            tl->obsolete_entries, tl->total_entries);
        tfs fs = tl->fs;
        log new_tl = log_new(fs->fs.h, fs);
        if (new_tl == INVALID_ADDRESS)
            return;
        log_ext new_ext = log_ext_new(new_tl);
        if (new_ext == INVALID_ADDRESS)
            goto fail_log_destroy;
        status_handler switch_complete = closure(new_tl->h, log_switch_complete,
            tl, new_tl);
        if (switch_complete == INVALID_ADDRESS)
            goto fail_log_ext_close;
        status_handler rebuild_complete = closure(tl->h, log_extend_link,
            new_tl->current, new_ext->sectors, switch_complete);
        if (rebuild_complete == INVALID_ADDRESS)
            goto fail_log_dealloc_closure;
        log_extension_init(new_tl->current);
        log_extension_init(new_ext);
        new_tl->current = new_ext;
        tl->state = TLOG_STATE_COMPACTING;
        new_tl->state = TLOG_STATE_INIT;
        filesystem_log_rebuild(fs, new_tl, rebuild_complete);
        return;
  fail_log_dealloc_closure:
        deallocate_closure(switch_complete);
  fail_log_ext_close:
        close_log_extension(new_ext);
        if (!filesystem_free_storage(fs, new_ext->sectors))
            msg_err("failed to mark new_ext at %R as free", new_ext->sectors);
  fail_log_destroy:
        log_destroy(new_tl);
    }
}

#ifdef KERNEL
closure_function(1, 2, void, log_flush_timer_expired,
                 log, tl,
                 u64, expiry, u64, overruns)
{
    if (overruns != timer_disabled) {
        tlog_lock(bound(tl));
        log_flush(bound(tl), 0);
        tlog_unlock(bound(tl));
    }
    closure_finish();
}

static void log_set_dirty(log tl)
{
    if (tl->dirty) {
        if (buffer_length(tl->tuple_staging) >= bytes_from_sectors(&tl->fs->fs,
                range_span(tl->current->sectors)) / 2)
            log_flush(tl, 0);
        return;
    }
    tl->dirty = true;
    register_timer(kernel_timers, &tl->flush_timer, CLOCK_ID_MONOTONIC_RAW,
                   seconds(TFS_LOG_FLUSH_DELAY_SECONDS), false, 0,
                   closure(tl->h, log_flush_timer_expired, tl));
}
#else
/* mkfs: flush on close */
static void log_set_dirty(log tl)
{
    tl->dirty = true;
    if (buffer_length(tl->tuple_staging) >=
            bytes_from_sectors(&tl->fs->fs, range_span(tl->current->sectors))) {
        log_flush(tl, 0);
    }
}
#endif

boolean log_write_eav(log tl, tuple e, symbol a, value v)
{
    tlog_debug("log_write_eav: tl %p, e %p, a %b, v %p\n", tl, e, symbol_string(a), v);
    u64 len = buffer_length(tl->tuple_staging);
    if ((tl->state == TLOG_STATE_FAILED) || len >= TFS_LOG_MAX_TUPLE_STAGING_BYTES)
        return false;
    encode_eav(tl->tuple_staging, tl->dictionary, e, a, v, &tl->obsolete_entries);
    tl->total_entries++;
    len = buffer_length(tl->tuple_staging) - len;
    vector_push(tl->encoding_lengths, (void *)len);
    log_set_dirty(tl);
    return (tl->state != TLOG_STATE_FAILED);
}

boolean log_write(log tl, tuple t)
{
    tlog_debug("log_write: tl %p, t %p\n", tl, t);
    u64 len = buffer_length(tl->tuple_staging);
    if ((tl->state == TLOG_STATE_FAILED) || len >= TFS_LOG_MAX_TUPLE_STAGING_BYTES)
        return false;
    encode_tuple(tl->tuple_staging, tl->dictionary, t, &tl->total_entries);
    len = buffer_length(tl->tuple_staging) - len;
    vector_push(tl->encoding_lengths, (void *)len);
    log_set_dirty(tl);
    return (tl->state != TLOG_STATE_FAILED);
}

#endif /* !TLOG_READ_ONLY */

static boolean log_parse_tuple(log tl, buffer b, boolean old_encoding)
{
    tuple dv = decode_value(tl->h, tl->dictionary, b, &tl->total_entries,
                            &tl->obsolete_entries, old_encoding);
    if (!is_tuple(dv))
        return false;
    return true;
}

static inline void log_tuple_produce(log tl, buffer b, u64 length)
{
    assert(buffer_write(tl->tuple_staging, buffer_ref(b, 0), length));
    buffer_consume(b, length);
    tl->tuple_bytes_remain -= length;
}

static status log_hdr_parse(log_ext ext, buffer b, boolean first_ext,
                            u64 *length, u8 *uuid, char *label)
{
    if (runtime_memcmp(buffer_ref(b, 0), tfs_magic, TFS_MAGIC_BYTES))
        return timm("result", "tfs magic mismatch");
    buffer_consume(b, TFS_MAGIC_BYTES);
    u64 version = pop_varint(b);
    if (version == 0x4) {
#ifndef BOOT
        static boolean warn_once;
        if (!warn_once) {
            warn_once = true;
            rprintf("WARNING: old version of TFS found (4); please upgrade ops/mkfs\n");
        }
#endif
        if (ext)
            ext->old_encoding = true;
    } else if (version == TFS_VERSION) {
        if (ext)
            ext->old_encoding = false;
    } else {
        return timm("result", "tfs version mismatch (read %ld, build %ld)",
            version, TFS_VERSION);
    }
    *length = pop_varint(b);
    if (first_ext) {
        buffer_read(b, uuid, UUID_LEN);
        if (!read_cstring(b, label, VOLUME_LABEL_MAX_LEN))
            return timm("result", "invalid label");
    }
    return STATUS_OK;
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
    buffer b = &ext->staging;
    buffer_produce(b, bound(length));
    deallocate_sg_list(bound(sg));
    dump_staging(ext);
    tlog_debug("log_read_complete: buffer len %d, status %v\n", buffer_length(b), read_status);
    tlog_debug("-> new log extension, checking magic and version\n");
    if (!ext->open) {
        length = 0;
        s = log_hdr_parse(ext, b, ext->sectors.start == 0, &length, tl->fs->uuid,
            tl->fs->label);
        if (!is_ok(s))
            goto out_apply_status;
        /* XXX the length is really for validation...so hook it up */
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
                log_parse_tuple(tl, b, ext->old_encoding);
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
                log_parse_tuple(tl, tl->tuple_staging, ext->old_encoding);
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
    tlog_debug("-> end of log, %ld total entries (%ld obsolete)\n",
               tl->total_entries, tl->obsolete_entries);

    /* the log must go on */
    *(u8*)(b->contents + b->start - 1) = END_OF_SEGMENT;

    /* mark end of log */
    b->end = b->start;
    b->start = 0;
    tlog_debug("   log parse finished, end now at %d\n", b->end);

    tl->fs->fs.root = (tuple)table_find(tl->dictionary, pointer_from_u64(1));

    if (!tl->fs->fs.ro) {
        /* Reverse pairs in dictionary so that we can use it for writing
           the next log segment. */
        table newdict = allocate_table(tl->h, identity_key, pointer_equal);
        table_foreach(tl->dictionary, k, v) {
            tlog_debug("   dict swap: k %p, v %p, type %d\n", k, v, tagof(v));
            assert(is_composite(v) || is_symbol(v));
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
    range r = irangel(0, bytes_from_sectors(&tl->fs->fs, range_span(ext->sectors)));
    u64 length = range_span(r);
    sg_buf sgb = sg_list_tail_add(sg, length);
    sgb->buf = buffer_ref(&ext->staging, 0);
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = 0;
    status_handler tlc = closure(tl->h, log_read_complete, ext, sg, length, sh);
    tlog_debug("%s: issuing sg read, sg %p, r %R\n", func_ss, sg, r);
    apply((sg_io)&ext->read, sg, r, tlc);
}

status filesystem_probe(u8 *first_sector, u8 *uuid, char *label)
{
    u64 len;
    return log_hdr_parse(0, alloca_wrap_buffer(first_sector, SECTOR_SIZE), true, &len, uuid, label);
}

log log_create(heap h, tfs fs, boolean initialize, status_handler sh)
{
    tlog_debug("log_create: heap %p, fs %p, sh %p\n", h, fs, sh);
#ifndef TLOG_READ_ONLY
    range sectors = irange(0, TFS_LOG_INITIAL_SIZE >> fs->fs.blocksize_order);
    if (!filesystem_reserve_storage(fs, sectors)) {
        msg_err("failed to reserve sectors in allocation map");
        return INVALID_ADDRESS;
    }
#endif
    log tl = log_new(h, fs);
    if (tl == INVALID_ADDRESS)
        return tl;
    tl->state = TLOG_STATE_LINKED;
    fs->tl = tl;
    if (initialize) {
#ifdef TLOG_READ_ONLY
        halt("no tlog write support\n");
#else
        fs->fs.root = allocate_tuple();
        buffer uuid = alloca_wrap_buffer(fs->uuid, UUID_LEN);
        random_buffer(uuid);
        log_ext init_ext = tl->current;
        log_extension_init(init_ext);
        if (!filesystem_reserve_log_space(fs, &fs->next_new_log_offset, 0, 0))
            goto fail;
        if (!filesystem_reserve_log_space(fs, &fs->next_extend_log_offset, 0, 0))
            goto fail_alloc_extend_log;
        log_ext new_ext = log_ext_new(tl);
        if (!new_ext)
            goto fail_ext_new;
        log_extension_init(new_ext);
        tl->current = new_ext;
        apply(closure(tl->h, log_extend_link, init_ext, new_ext->sectors, sh),
              STATUS_OK);
#endif
    } else {
        log_read(tl, sh);
    }
    return tl;
#ifndef TLOG_READ_ONLY
  fail_ext_new:
    filesystem_free_storage(fs, irangel(fs->next_extend_log_offset, filesystem_log_blocks(fs)));
  fail_alloc_extend_log:
    filesystem_free_storage(fs, irangel(fs->next_new_log_offset, filesystem_log_blocks(fs)));
  fail:
    apply(sh, timm("result", "failed to allocate storage"));
    return INVALID_ADDRESS;
#endif
}

void log_destroy(log tl)
{
#ifdef KERNEL
    remove_timer(kernel_timers, &tl->flush_timer, 0);
#endif
    deallocate_vector(tl->flush_completions);
#ifndef TLOG_READ_ONLY
    deallocate_rangemap(tl->extensions, stack_closure(log_dealloc_ext_node,
        tl));
#endif
    deallocate_vector(tl->encoding_lengths);
    deallocate_buffer(tl->tuple_staging);
    close_log_extension(tl->current);
    deallocate_table(tl->dictionary);
    deallocate(tl->h, tl, sizeof(*tl));
}
