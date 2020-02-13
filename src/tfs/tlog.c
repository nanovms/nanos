/* TODO
   x fix completion vector - reset or delete / replace
   - add magic and version to each extension / remove special case for first
   - figure MAX_VARINT_SIZE
   - figure TFS_LOG_FILL_THRESHOLD
   - replace SECTOR_* with fs->block_size
   - store current log size in tl, don't assume default
 */

#include <tfs_internal.h>

//#define TLOG_DEBUG
//#define TLOG_DEBUG_DUMP
#ifdef TLOG_DEBUG
#define tlog_debug(x, ...) do {rprintf("TLOG: " x, ##__VA_ARGS__);} while(0)
#else
#define tlog_debug(x, ...)
#endif

#define END_OF_LOG 1
#define TUPLE_AVAILABLE 2
#define END_OF_SEGMENT 3
#define LOG_EXTENSION_LINK 4
#define LOG_EXTENSION_HEADER 5
#define TUPLE_EXTENDED 6

#define COMPLETION_QUEUE_SIZE 10

#define MAX_VARINT_SIZE 10 /* XXX figure this out */

/* This is arbitrary, because we can't really know how much space an
   encoded tuple or eav would require. We *might* be able to eliminate
   this by parameterizing the expand function on buffer allocation. */
#define TFS_LOG_FILL_THRESHOLD (TFS_LOG_DEFAULT_EXTENSION_SIZE - 128)

typedef struct log {
    filesystem fs;
    vector completions;
    table dictionary;

    /* sector offset, length and staging buffer of current extension */
    range sectors;
    buffer staging;
    buffer tuple_staging;
    u64 tuple_bytes_remain;

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
    assert((b->start & MASK(SECTOR_OFFSET)) == 0);
    u64 sector_start = log_range.start + (b->start >> SECTOR_OFFSET);
    u64 sectors = (buffer_length(b) + (SECTOR_SIZE - 1)) >> SECTOR_OFFSET;
    range write_range = irange(sector_start, sector_start + sectors);
    assert(range_contains(log_range, write_range));

    void *p = buffer_ref(b, 0);
    tlog_debug("log_flush_internal: writing sectors %R, buffer addr %p\n", write_range, p);
    apply(fs->w, p, write_range, closure(h, log_write_completion, b, completions, release));
    if (!release) {
        b->end -= 1;                /* next write removes END_OF_LOG */
        tlog_debug("log ext offset was %d (end %d)\n", b->start, b->end);
        b->start = b->end & ~MASK(SECTOR_OFFSET); /* next storage write starting here */
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

boolean log_extend(log tl, u64 size) {
    tlog_debug("log_extend: tl %p\n", tl);

    /* allocate new log and write with end of log */
    u64 offset = allocate_u64(tl->fs->storage, size);
    if (offset == INVALID_PHYSICAL)
        return false;
    offset >>= SECTOR_OFFSET;
    u64 sectors = size >> SECTOR_OFFSET;
    range r = irange(offset, offset + sectors);
    buffer nb = allocate_buffer(tl->h, size);

    /* new log extension */
    tl->dirty = true;
    tlog_debug("new log extension sector range %R, sectors %d staging %p\n", r, sectors, nb);
    push_u8(nb, LOG_EXTENSION_HEADER);
    push_varint(nb, sectors);
    push_u8(nb, END_OF_LOG);
    assert(buffer_length(nb) < SECTOR_SIZE);
    range wr = irange(offset, offset + 1);

    /* Somewhat dicey assumption that, as with other writes, this
       buffer is not touched after return... */
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

#define TUPLE_AVAILABLE_MAX_SIZE (1 + 2 * MAX_VARINT_SIZE)

static inline void log_write_internal(log tl, status_handler sh)
{
    u64 remaining = buffer_length(tl->tuple_staging);
    u64 written = 0;

    do {
        if (tl->staging->end >= TFS_LOG_FILL_THRESHOLD) {
            if (!log_extend(tl, TFS_LOG_DEFAULT_EXTENSION_SIZE)) {
                apply(sh, timm("result", "log_write failed to extend log: out of storage"));
                return;
            }
        }
        assert(tl->staging->end < TFS_LOG_FILL_THRESHOLD);
        // XXX really should get size from tl
        u64 avail = TFS_LOG_DEFAULT_EXTENSION_SIZE - tl->staging->end;
        assert(avail > TUPLE_AVAILABLE_MAX_SIZE);
        u64 length = MIN(avail - TUPLE_AVAILABLE_MAX_SIZE, remaining);
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

closure_function(2, 1, void, log_read_complete,
                 log, tl, status_handler, sh,
                 status, read_status)
{
    log tl = bound(tl);
    status s = STATUS_OK;
    status_handler sh = bound(sh);
    buffer b = tl->staging;
    u8 frame = 0;
    u64 sector, length, tuple_length;

    tlog_debug("log_read_complete: buffer len %d, status %v\n", buffer_length(b), read_status);
    if (!is_ok(read_status)) {
        tlog_debug("read failure\n");
        apply(sh, timm_up(read_status, "result", "read failed"));
        closure_finish();
        return;
    }

    /* need to check bounds */
    while ((frame = pop_u8(b)) != END_OF_LOG) {
        switch (frame) {
        case END_OF_SEGMENT:
            tlog_debug("-> segment boundary\n");
            continue;
        case LOG_EXTENSION_HEADER:
            tlog_debug("-> extend header\n");
            /* XXX the length is really for validation...so hook it up */
            length = pop_varint(b);
            tlog_debug("%ld sectors\n", length);
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
            extend_total(tl->staging, length << SECTOR_OFFSET);
            tl->sectors = r;

            /* chain to next log extension, carrying status handler to end */
            read_log(tl, sh);
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
        default:
            tlog_debug("-> unknown encoding type %d\n", frame);
            b->end = SECTOR_SIZE;
            tlog_debug("%X\n", b);
            s = timm("result", "unknown frame identifier 0x%x\n", frame);
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

#ifndef BOOT
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
#endif

  out_apply_status:
    buffer_clear(tl->tuple_staging);
    apply(sh, s);
  out:
    closure_finish();
}

void read_log(log tl, status_handler sh)
{
    u64 size = range_span(tl->sectors) << SECTOR_OFFSET;
    tl->staging = allocate_buffer(tl->h, size);
    tlog_debug("reading log extension, sectors %R, staging %p\n", tl->sectors, tl->staging);
    /* reserve sectors in map */
#ifndef BOOT
    if (!id_heap_set_area(tl->fs->storage, tl->sectors.start << SECTOR_OFFSET,
                          range_span(tl->sectors) << SECTOR_OFFSET, true, true)) {
        const char *err = "failed to reserve sectors in allocation map";
        tlog_debug("%s\n", err);
        apply(sh, timm("result", "%s", err));
        return;
    }
#endif
    status_handler tlc = closure(tl->h, log_read_complete, tl, sh);
    apply(tl->fs->r, tl->staging->contents, tl->sectors, tlc);
}

log log_create(heap h, filesystem fs, status_handler sh)
{
    tlog_debug("log_create: heap %p, fs %p, sh %p\n", h, fs, sh);
    log tl = allocate(h, sizeof(struct log));
    tl->h = h;
    tl->sectors = irange(0, TFS_LOG_DEFAULT_EXTENSION_SIZE >> SECTOR_OFFSET);
    tl->fs = fs;
    tl->completions = allocate_vector(h, COMPLETION_QUEUE_SIZE);
    tl->dictionary = allocate_table(h, identity_key, pointer_equal);
    tl->dirty = false;
    tl->staging = 0;
    tl->tuple_staging = allocate_buffer(h, PAGESIZE /* arbitrary */);
    fs->tl = tl;
    read_log(tl, sh);
    return tl;
}
