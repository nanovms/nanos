#include <tfs_internal.h>

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

typedef struct log {
    filesystem fs;
    vector completions;
    table dictionary;

    /* sector offset, length and staging buffer of current extension */
    range sectors;
    buffer staging;
    buffer tuple_staging;
    u64 tuple_bytes_remain;
    boolean extension_open;

    int dirty;              /* cas boolean */
    heap h;
} *log;

closure_function(3, 1, void, log_write_completion,
                 buffer, b,
                 vector, completions,
                 boolean, release,
                 status, s)
{
    // reclaim the buffer now and the vector...make it a whole thing
    vector v = bound(completions);
    status_handler sh;

    vector_foreach(v, sh)
        apply(sh, s);

    deallocate_vector(v);

    if (bound(release))
        deallocate_buffer(bound(b));
    closure_finish();
}

// xxx  currently we cant take writes during the flush

/* Avoid references to log, which may be in transition to a new extension. */
static void log_flush_internal(heap h, filesystem fs, buffer b, range log_range,
                               vector completions, boolean release)
{
    push_u8(b, END_OF_LOG);

#ifdef TLOG_DEBUG_DUMP
    u64 z = b->end;
    b->start = 0;
    b->end = 1024;
    rprintf("staging contains:\n%X\n", b);
    b->end = z;
#endif

    assert(buffer_length(b) > 0); /* END_OF_LOG, at least */
    assert((b->start & MASK(fs->blocksize_order)) == 0);
    u64 sector_start = log_range.start + sector_from_offset(fs, b->start);
    u64 sectors = sector_from_offset(fs, buffer_length(b) + (fs_blocksize(fs) - 1));
    range write_range = irange(sector_start, sector_start + sectors);
    assert(range_contains(log_range, write_range));

    void *p = buffer_ref(b, 0);
    tlog_debug("log_flush_internal: writing sectors %R, buffer addr %p\n", write_range, p);
    apply(fs->w, p, write_range, closure(h, log_write_completion, b, completions, release));
    if (!release) {
        b->end -= 1;                /* next write removes END_OF_LOG */
        tlog_debug("log ext offset was %d (end %d)\n", b->start, b->end);
        b->start = b->end & ~MASK(fs->blocksize_order); /* next storage write starting here */
        tlog_debug("log ext offset now %d\n", b->start);
        assert(b->end >= b->start);
    }
}

void log_flush(log tl)
{
    if (!tl->dirty)
        return;
    tl->dirty = false;

    tlog_debug("log_flush: log %p dirty\n", tl);
    vector c = tl->completions;
    tl->completions = allocate_vector(tl->h, COMPLETION_QUEUE_SIZE);
    log_flush_internal(tl->h, tl->fs, tl->staging, tl->sectors, c, false);
}

void log_flush_complete(log tl, status_handler completion)
{
    tlog_debug("log_flush_complete: log %p, completion %p, dirty %d\n",
               tl, completion, tl->dirty);
    if (!tl->dirty) {
        apply(completion, STATUS_OK);
        return;
    }
    vector_push(tl->completions, completion);
    log_flush(tl);
}

/* complete linkage in (now disembodied - thus long arg list) previous extension */
closure_function(7, 1, void, log_extend_link,
                 u64, offset,
                 u64, sectors,
                 heap, h,
                 filesystem, fs,
                 buffer, b,
                 range, r,
                 vector, c,
                 status, s)
{
    tlog_debug("linking old extension to new and flushing\n");

    /* add link to close out old extension and commit */
    buffer b = bound(b);
    push_u8(b, LOG_EXTENSION_LINK);
    push_varint(b, bound(offset));
    push_varint(b, bound(sectors));

    /* flush and dispose */
    log_flush_internal(bound(h), bound(fs), b, bound(r), bound(c), true);
}

static void init_log_extension(buffer b, u64 sectors)
{
    push_buffer(b, alloca_wrap_buffer(tfs_magic, TFS_MAGIC_BYTES));
    push_varint(b, TFS_VERSION);
    push_varint(b, sectors);
}

boolean log_extend(log tl, u64 size) {
    tlog_debug("log_extend: tl %p\n", tl);

    /* allocate new log and write with end of log */
    u64 offset = allocate_u64((heap)tl->fs->storage, size);
    if (offset == INVALID_PHYSICAL)
        return false;
    offset = sector_from_offset(tl->fs, offset);
    u64 sectors = sector_from_offset(tl->fs, size);
    range r = irange(offset, offset + sectors);
    buffer nb = allocate_buffer(tl->h, size);

    /* new log extension */
    tl->dirty = true;
    tlog_debug("new log extension sector range %R, sectors %d staging %p\n", r, sectors, nb);
    init_log_extension(nb, sectors);
    push_u8(nb, END_OF_LOG);
    assert(buffer_length(nb) < fs_blocksize(tl->fs));
    range wr = irange(offset, offset + 1);

    void *p = buffer_ref(nb, 0);
    tlog_debug("log_extend: writing new extension, sectors %R, buffer %p\n", wr, p);
    apply(tl->fs->w, p, wr,
          closure(tl->h, log_extend_link, offset, sectors, tl->h, tl->fs,
                  tl->staging, tl->sectors, tl->completions));
    nb->end -= 1;
    tl->staging = nb;
    tl->sectors = r;
    tl->completions = allocate_vector(tl->h, COMPLETION_QUEUE_SIZE);
    tl->dirty = false;
    return true;
}

#define TUPLE_AVAILABLE_HEADER_SIZE (1 + 2 * MAX_VARINT_SIZE)
#define TUPLE_AVAILABLE_MIN_SIZE (TUPLE_AVAILABLE_HEADER_SIZE + 32 /* arbitrary */)

static inline u64 log_size(log tl)
{
    return bytes_from_sectors(tl->fs, range_span(tl->sectors));
}

static inline void log_write_internal(log tl, status_handler sh)
{
    u64 remaining = buffer_length(tl->tuple_staging);
    u64 written = 0;
    u64 size;

    do {
        size = log_size(tl);
        u64 min = TFS_EXTENSION_LINK_BYTES + TUPLE_AVAILABLE_MIN_SIZE;
        if (tl->staging->end + min >= size) {
            if (!log_extend(tl, TFS_LOG_DEFAULT_EXTENSION_SIZE)) {
                apply(sh, timm("result", "log_write failed to extend log: out of storage"));
                return;
            }
            size = log_size(tl);
        }
        assert(tl->staging->end + min < size);
        u64 avail = size - (tl->staging->end + TFS_EXTENSION_LINK_BYTES + TUPLE_AVAILABLE_HEADER_SIZE);
        u64 length = MIN(avail, remaining);
        if (written == 0) {
            push_u8(tl->staging, TUPLE_AVAILABLE);
            push_varint(tl->staging, remaining);
        } else {
            push_u8(tl->staging, TUPLE_EXTENDED);
        }
        push_varint(tl->staging, length);
        buffer_write(tl->staging, buffer_ref(tl->tuple_staging, 0), length);
        buffer_consume(tl->tuple_staging, length);
        remaining -= length;
        written += length;
    } while (remaining > 0);

    /* assign completion to the last log extension flush */
    vector_push(tl->completions, sh);
    tl->dirty = true;
}

void log_write_eav(log tl, tuple e, symbol a, value v, status_handler sh)
{
    tlog_debug("log_write_eav: tl %p, e %p, a %p, v %p\n", tl, e, a, v);
    encode_eav(tl->tuple_staging, tl->dictionary, e, a, v);
    log_write_internal(tl, sh);
}

void log_write(log tl, tuple t, status_handler sh)
{
    tlog_debug("log_write: tl %p, t %p\n", tl, t);
    encode_tuple(tl->tuple_staging, tl->dictionary, t);
    log_write_internal(tl, sh);
}

static boolean log_parse_tuple(log tl, buffer b)
{
    tuple dv = decode_value(tl->h, tl->dictionary, b);
    tlog_debug("   decoded %p\n", dv);
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
                 log, tl, sg_list, sg, u64, length, status_handler, sh,
                 status, read_status)
{
    log tl = bound(tl);
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

    sg_copy_to_buf_and_release(buffer_ref(tl->staging, 0), bound(sg), bound(length));

    buffer b = tl->staging;
    tlog_debug("log_read_complete: buffer len %d, status %v\n", buffer_length(b), read_status);
    tlog_debug("-> new log extension, checking magic and version\n");
    if (!tl->extension_open) {
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
        tl->extension_open = true;
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
            range r = irange(sector, sector + length);

            /* XXX validate against device */
            assert(tl->staging);
            buffer_clear(tl->staging);
            extend_total(tl->staging, bytes_from_sectors(tl->fs, length));
            tl->sectors = r;
            tl->extension_open = false;

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
            tlog_debug("-> unknown encoding type %d\n", frame);
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

static boolean init_staging(log tl, status_handler sh)
{
    char *err;
    u64 size = log_size(tl);
    tl->staging = allocate_buffer(tl->h, size);
    if (tl->staging == INVALID_ADDRESS) {
        err = "failed to allocate staging buffer";
        goto fail;
    }
    tlog_debug("reading log extension, sectors %R, staging %p\n",
               tl->sectors, tl->staging);

    /* reserve sectors in map */
    if (!filesystem_reserve_storage(tl->fs, bytes_from_sectors(tl->fs, tl->sectors.start), size)) {
        err = "failed to reserve sectors in allocation map";
        goto fail;
    }
    return true;
  fail:
    tlog_debug("%s\n", err);
    apply(sh, timm("result", "%s", err));
    deallocate_buffer(tl->staging);
    tl->staging = 0;
    return false;
}

static void log_read(log tl, status_handler sh)
{
    assert(!tl->extension_open);
    if (!init_staging(tl, sh))
        return;
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        apply(sh, timm("result", "failed to allocate sg list"));
        return;
    }
    range r = range_lshift(tl->sectors, SECTOR_OFFSET);
    status_handler tlc = closure(tl->h, log_read_complete, tl, sg, range_span(r), sh);
    tlog_debug("%s: issuing sg read, sg %p, r %R, tlc %p\n", __func__, sg, r, tlc);
    apply(tl->fs->sg_r, sg, r, tlc);
}

log log_create(heap h, filesystem fs, boolean initialize, status_handler sh)
{
    tlog_debug("log_create: heap %p, fs %p, sh %p\n", h, fs, sh);
    log tl = allocate(h, sizeof(struct log));
    if (tl == INVALID_ADDRESS)
        return tl;
    tl->h = h;
    tl->sectors = irange(0, sector_from_offset(fs, TFS_LOG_DEFAULT_EXTENSION_SIZE));
    tl->fs = fs;
    tl->completions = allocate_vector(h, COMPLETION_QUEUE_SIZE);
    if (tl->completions == INVALID_ADDRESS)
        goto fail_dealloc_dict;
    tl->dictionary = allocate_table(h, identity_key, pointer_equal);
    if (tl->dictionary == INVALID_ADDRESS)
        goto fail_dealloc_tstage;
    tl->dirty = false;
    tl->staging = 0;
    tl->tuple_staging = allocate_buffer(h, PAGESIZE /* arbitrary */);
    tl->tuple_bytes_remain = 0;
    tl->extension_open = false;
    fs->tl = tl;
    if (initialize) {
        /* mkfs */
        if (!init_staging(tl, sh))
            goto fail_dealloc;
        init_log_extension(tl->staging, range_span(tl->sectors));
        apply(sh, STATUS_OK);
    } else {
        log_read(tl, sh);
    }
    return tl;
  fail_dealloc:
    deallocate_vector(tl->completions);
  fail_dealloc_dict:
    deallocate_table(tl->dictionary);
  fail_dealloc_tstage:
    deallocate_buffer(tl->tuple_staging);
    deallocate(h, tl, sizeof(struct log));
    return INVALID_ADDRESS;
}
