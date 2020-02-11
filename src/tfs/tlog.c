#include <tfs_internal.h>

//#define TLOG_DEBUG
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

#define COMPLETION_QUEUE_SIZE 10
typedef struct log {
    filesystem fs;
    vector completions;         /* XXX change to queue */
    table dictionary;

    /* sector offset, length and staging buffer of current extension */
    range sectors;
    buffer staging;

    int dirty;              /* cas boolean */
    heap h;
} *log;

closure_function(3, 1, void, log_write_completion,
                 buffer, b,
                 value, completions,
                 boolean, release,
                 status, s)
{
    // reclaim the buffer now and the vector...make it a whole thing
    status_handler i;
    vector v = bound(completions);
    int len = vector_length(v);
    for (int count = 0; count < len; count++) {
        i = vector_delete(v, 0);
        apply(i, s);
    }
    if (bound(release)) {
        deallocate_buffer(bound(b));
        deallocate_vector(v);
    }
    closure_finish();
}

// xxx  currently we cant take writes during the flush

/* Avoid references to log, which may be in transition to a new extension. */
static void log_flush_internal(heap h, filesystem fs, buffer b, range log_range,
                               vector completions, boolean release)
{
    push_u8(b, END_OF_LOG);

#ifdef TLOG_DEBUG
    u64 z = b->end;
    b->start = 0;
    b->end = 1024;
    rprintf("staging contains:\n%X\n", b);
    b->end = z;
#endif

    u64 sector_start = b->start;
    assert(sector_start < b->end); /* END_OF_LOG, at least */
    assert((sector_start & MASK(SECTOR_OFFSET)) == 0);
    sector_start = log_range.start + (sector_start >> SECTOR_OFFSET);
    u64 sectors = (buffer_length(b) + (SECTOR_SIZE - 1)) >> SECTOR_OFFSET;
    range write_range = irange(sector_start, sector_start + sectors);
    assert(range_contains(log_range, write_range));

    apply(fs->w, buffer_ref(b, 0), write_range,
          closure(h, log_write_completion, b, completions, release));
    if (!release) {
        b->end -= 1;                /* next write removes END_OF_LOG */
        tlog_debug("log ext offset was %d now %d\n", b->start, b->end);
        b->start += (sectors - 1) << SECTOR_OFFSET;        /* pick up next write here */
    }
}

void log_flush(log tl)
{
    if (!__sync_bool_compare_and_swap(&tl->dirty, 1, 0))
        return;

    tlog_debug("log_flush: log %p dirty\n", tl);
    log_flush_internal(tl->h, tl->fs, tl->staging, tl->sectors, tl->completions, false);
}

boolean log_flush_complete(log tl, status_handler completion)
{
    if (!tl->dirty) {
        return true;
    }
    vector_push(tl->completions, completion);
    log_flush(tl);
    return false;
}

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
    /* add link to close out old extension and commit */
    buffer b = bound(b);
    push_u8(b, LOG_EXTENSION_LINK);
    push_varint(b, bound(offset));
    push_varint(b, bound(sectors));

    /* flush and dispose */
    log_flush_internal(bound(h), bound(fs), b, bound(r), bound(c), true);
}

boolean log_extend(log tl) {
    tlog_debug("log_extend: tl %p\n", tl);

    /* allocate new log and write with end of log */
    u64 offset = allocate_u64(tl->fs->storage, INITIAL_LOG_SIZE);
    if (offset == INVALID_PHYSICAL)
        return false;
    offset >>= SECTOR_OFFSET;
    u64 sectors = INITIAL_LOG_SIZE >> SECTOR_OFFSET;
    range r = irange(offset, offset + sectors);
    buffer nb = allocate_buffer(tl->h, INITIAL_LOG_SIZE);

    /* new log extension */
    tlog_debug("new log extension sector range %R, sectors %d staging %p\n", r, sectors, nb);
    push_u8(nb, LOG_EXTENSION_HEADER);
    push_varint(nb, sectors);
    push_u8(nb, END_OF_LOG);
    assert(buffer_length(nb) < SECTOR_SIZE);
    range wr = irange(offset, offset + 1);

    /* Somewhat dicey assumption that, as with other writes, this
       buffer is not touched after return... */
    tlog_debug("link old extension to new and switch over\n");
    apply(tl->fs->w, buffer_ref(nb, 0), wr,
          closure(tl->h, log_extend_link, offset, sectors, tl->h, tl->fs,
                  tl->staging, tl->sectors, tl->completions));
    nb->end -= 1;
    tl->staging = nb;
    tl->sectors = r;
    tl->completions = allocate_vector(tl->h, COMPLETION_QUEUE_SIZE);
    tl->dirty = false;
    return true;
}

void log_write_eav(log tl, tuple e, symbol a, value v, status_handler sh)
{
    tlog_debug("log_write_eav: tl %p, e %p (%t), a \"%b\", v %v\n", tl, e, e, symbol_string(a), v);
    if (tl->staging->end > INITIAL_LOG_SIZE - 32) {
        if (!log_extend(tl)) {
            apply(sh, timm("result", "log_write_eav failed to extend log: out of storage"));
            return;
        }
    }
    push_u8(tl->staging, TUPLE_AVAILABLE);
    encode_eav(tl->staging, tl->dictionary, e, a, v);
    vector_push(tl->completions, sh);
    tl->dirty = true;
}

void log_write(log tl, tuple t, status_handler sh)
{
    tlog_debug("log_write: tl %p, t %p (%t)\n", tl, t, t);
    if (tl->staging->end > INITIAL_LOG_SIZE - 32) {
        if (!log_extend(tl)) {
            apply(sh, timm("result", "log_write failed to extend log: out of storage"));
            return;
        }
    }
    push_u8(tl->staging, TUPLE_AVAILABLE);
    // this should be incremental on root!
    encode_tuple(tl->staging, tl->dictionary, t);
    vector_push(tl->completions, sh);
    tl->dirty = true;
}

closure_function(2, 1, void, log_read_complete,
                 log, tl, status_handler, sh,
                 status, s)
{
    log tl = bound(tl);
    status_handler sh = bound(sh);
    buffer b = tl->staging;
    u8 frame = 0;
    u64 sector, length;

    tlog_debug("log_read_complete: buffer len %d, status %v\n", buffer_length(b), s);
    if (!is_ok(s)) {
        apply(sh, s);
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
                apply(sh, timm("result", "zero-length extension\n"));
                closure_finish();
                return;
            }
            range r = irange(sector, sector + length);

            /* XXX validate against device */
            assert(tl->staging);
            buffer_clear(tl->staging);
            extend_total(tl->staging, length << SECTOR_OFFSET);
            tl->sectors = r;

            /* chain to next log extension, carrying status handler to end */
            read_log(tl, sh);
            closure_finish();
            return;
        case TUPLE_AVAILABLE:
            break;
        default:
            apply(sh, timm("result", "unknown frame identifier 0x%x\n", frame));
            closure_finish();
            return;
        }
        tuple dv = decode_value(tl->h, tl->dictionary, b);
        tlog_debug("   decoded %p\n", dv);
        if (tagof(dv) != tag_tuple)
            continue;

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
    }

    /* the log must go on */
    if (frame == END_OF_LOG) {
        *(u8*)(b->contents + b->start - 1) = END_OF_SEGMENT;
    }

    /* mark end of log */
    b->end = b->start;
    b->start = 0;
    tlog_debug("   log parse finished, end now at %d\n", b->end);

    /* XXX this will only work for reading the log a single time
       through, but at present we're not using any incremental log updates */
    table_foreach(tl->fs->extents, t, f) {
        table_foreach(t, off, e) {
            tlog_debug("   tlog ingesting sym %b, val %p\n", symbol_string(off), e);
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

    apply(sh, 0);
    closure_finish();
}

void read_log(log tl, status_handler sh)
{
    u64 size = range_span(tl->sectors) << SECTOR_OFFSET;
    tl->staging = allocate_buffer(tl->h, size);
    tlog_debug("reading log extension, sectors %R, staging %p\n", tl->sectors, tl->staging);
    status_handler tlc = closure(tl->h, log_read_complete, tl, sh);
    apply(tl->fs->r, tl->staging->contents, tl->sectors, tlc);
}

log log_create(heap h, filesystem fs, status_handler sh)
{
    tlog_debug("log_create: heap %p, fs %p, sh %p\n", h, fs, sh);
    log tl = allocate(h, sizeof(struct log));
    tl->h = h;
    tl->sectors = irange(0, INITIAL_LOG_SIZE >> SECTOR_OFFSET);
    tl->fs = fs;
    tl->completions = allocate_vector(h, COMPLETION_QUEUE_SIZE);
    tl->dictionary = allocate_table(h, identity_key, pointer_equal);
    tl->dirty = false;
    tl->staging = 0;
    fs->tl = tl;
    read_log(tl, sh);
    return tl;
}
