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

typedef struct log {
    filesystem fs;
    u64 remainder;
    buffer staging;
    vector completions;
    table dictionary;
    u64 offset;
    int dirty;              /* cas boolean */
    heap h;
} *log;

closure_function(1, 1, void, log_write_completion,
                 vector, v,
                 status, s)
{
    // reclaim the buffer now and the vector...make it a whole thing
    status_handler i;
    int len = vector_length(bound(v));
    for (int count = 0; count < len; count++) {
        i = vector_delete(bound(v), 0);
        apply(i, s);
    }
    closure_finish();
}

// xxx  currently we cant take writes during the flush

/* XXX it's not right to just stick SECTOR_{SIZE,OFFSET} everywhere...
   and add block_log2 to fs */
range log_block_range(log tl, u64 length)
{
    return irange(tl->offset >> SECTOR_OFFSET,
                  (tl->offset + pad(length, tl->fs->blocksize)) >> SECTOR_OFFSET);
}

/* XXX we're just writing the whole log - instead write only from
   block of buffer start forward */
void log_flush(log tl)
{
    if (!__sync_bool_compare_and_swap(&tl->dirty, 1, 0))
        return;

    tlog_debug("log_flush: log %p dirty\n", tl);
    buffer b = tl->staging;
    push_u8(b, END_OF_LOG);
#ifdef TLOG_DEBUG
    u64 z = tl->staging->end;
    tl->staging->start = 0;
    tl->staging->end = 1024;
    rprintf("staging contains:\n%X\n", b);
    tl->staging->end = z;
#endif

    void * buf = b->contents;
    u64 length = b->end;
    range r = log_block_range(tl, length);
    apply(tl->fs->w, buf, r, closure(tl->h, log_write_completion, tl->completions));
    b->end -= 1;                /* next write removes END_OF_LOG */
//    rprintf("was %d now %d\n", b->start, b->end);
//    b->start = b->end;          /* pick up next write here */
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

void log_write_eav(log tl, tuple e, symbol a, value v, status_handler sh)
{
    tlog_debug("log_write_eav: tl %p, e %p (%t), a \"%b\", v %v\n", tl, e, e, symbol_string(a), v);
    /* XXX make log extendable */
    if (tl->staging->end > INITIAL_LOG_SIZE - 32)
        halt("log full\n");
    push_u8(tl->staging, TUPLE_AVAILABLE);
    encode_eav(tl->staging, tl->dictionary, e, a, v);
    vector_push(tl->completions, sh);
    tl->dirty = true;
}

void log_write(log tl, tuple t, status_handler sh)
{
    tlog_debug("log_write: tl %p, t %p (%t)\n", tl, t, t);
    if (tl->staging->end > INITIAL_LOG_SIZE - 32)
        halt("log full\n");
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

    tlog_debug("log_read_complete: buffer len %d, status %v\n", buffer_length(b), s);
    if (!is_ok(s)) {
        apply(sh, s);
        closure_finish();
        return;
    }

    /* this is crap, but just fix for now due to time */

    // log extension - length at the beginnin and pointer at the end
    for (; frame = pop_u8(b), frame == TUPLE_AVAILABLE || frame == END_OF_SEGMENT;) {
        if (frame == END_OF_SEGMENT) {
            tlog_debug("-> segment boundary\n");
            continue;
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

void read_log(log tl, u64 offset, u64 size, status_handler sh)
{
    tl->staging = allocate_buffer(tl->h, size);
    status_handler tlc = closure(tl->h, log_read_complete, tl, sh);
    range r = log_block_range(tl, tl->staging->length);
//    rprintf("blocks %R\n", r);
    apply(tl->fs->r, tl->staging->contents, r, tlc);
}

log log_create(heap h, filesystem fs, status_handler sh)
{
    tlog_debug("log_create: heap %p, fs %p, sh %p\n", h, fs, sh);
    log tl = allocate(h, sizeof(struct log));
    tl->h = h;
    tl->offset = 0;
    tl->fs = fs;
    tl->completions = allocate_vector(h, 10);
    tl->dictionary = allocate_table(h, identity_key, pointer_equal);
    tl->dirty = false;
    tl->staging = 0;
    fs->tl = tl;
    read_log(tl, 0, INITIAL_LOG_SIZE, sh);
    return tl;
}
