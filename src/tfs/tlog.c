#include <tfs_internal.h>

#define END_OF_LOG 1
#define TUPLE_AVAILABLE 2
#define END_OF_SEGMENT 3

#define TRAILER_SIZE 16

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

static CLOSURE_1_1(log_write_completion, void, vector, status);
static void log_write_completion(vector v, status nothing)
{
    // reclaim the buffer now and the vector...make it a whole thing
    thunk i;
    vector_foreach(v, i) apply(i);
}

// xxx  currently we cant take writes during the flush

/* XXX it's not right to just stick SECTOR_{SIZE,OFFSET} everywhere...
   and add block_log2 to fs */
range log_block_range(log tl, u64 length)
{
    return irange(tl->offset >> SECTOR_OFFSET,
                  (tl->offset + pad(length, tl->fs->blocksize)) >> SECTOR_OFFSET);
}

void log_flush(log tl)
{
    if (!__sync_bool_compare_and_swap(&tl->dirty, 1, 0))
        return;

    buffer b = tl->staging;
    push_u8(b, END_OF_LOG);
    u64 z = tl->staging->end;
    tl->staging->start = 0;
    tl->staging->end = 1024;
    rprintf("staging contains:\n%X\n", b);
    tl->staging->end = z;

    void * buf = b->contents;
    u64 length = b->end;
    range r = log_block_range(tl, length);
    rprintf("range %R, buf %p, length %d, start %d\n", r, buf, length, b->start);
    apply(tl->fs->w, buf, r, closure(tl->h, log_write_completion, tl->completions));
    b->end -= 1;                /* next write removes END_OF_LOG */
}

void log_write_eav(log tl, tuple e, symbol a, value v, thunk complete)
{
    // out of space
    push_u8(tl->staging, TUPLE_AVAILABLE);
    encode_eav(tl->staging, tl->dictionary, e, a, v);
    vector_push(tl->completions, complete);
    tl->dirty = true;
}

void log_write(log tl, tuple t, thunk complete)
{
    // out of space
    push_u8(tl->staging, TUPLE_AVAILABLE);
    // this should be incremental on root!
    encode_tuple(tl->staging, tl->dictionary, t);
    vector_push(tl->completions, complete);
    tl->dirty = true;
}

CLOSURE_2_1(log_read_complete, void, log, status_handler, status);
void log_read_complete(log tl, status_handler sh, status s)
{
    buffer b = tl->staging;
    u8 frame = 0;

    if (!is_ok(s)) {
        apply(sh, s);
        return;
    }

    /* this is crap, but just fix for now due to time */

    // log extension - length at the beginnin and pointer at the end
    for (; frame = pop_u8(b), frame == TUPLE_AVAILABLE || frame == END_OF_SEGMENT;) {
        if (frame == END_OF_SEGMENT) {
            // XXX debug
            continue;
        }
        tuple t = decode_value(tl->h, tl->dictionary, b);
        rprintf("decoded %t\n", t);
        fsfile f = 0;
        u64 filelength = infinity;
        // doesn't seem like all the incremental updates are handled here,
        // nor the recursive case

        /* right, so just pasting in random extents won't get picked up here... */
        table_foreach(t, k, v) {
            if (k == sym(extents)) {
                rprintf("ext %v\n", v);
                /* don't know why this needs to be in fs, it's really tlog-specific */
                if (!(f = table_find(tl->fs->extents, v))) {
                    f = allocate_fsfile(tl->fs, t);
                    rprintf("create f %p\n", f);
                    table_set(tl->fs->extents, v, f);
                } else {
                    rprintf("f match %p\n", f);
                }
            } else if (k == sym(filelength)) {
                filelength = u64_from_value(v);
                rprintf("len %d\n", filelength);
            } else {
                rprintf("other: %s = %v\n", symbol_string(k), v);
            }
        }
        
        if (f && filelength != infinity)
            fsfile_set_length(f, filelength);
    }

    if (frame == END_OF_LOG) {
        *(u8*)(b->contents + b->start - 1) = END_OF_SEGMENT;
    }
    /* mark end of log */
    b->end = b->start;
    b->start = 0;
    rprintf("log read, end 0x%P\n", b->end);

    /* XXX this will only work for reading the log a single time
       through, but at present we're not using any incremental log updates */
    table_foreach(tl->fs->extents, t, f) {
        table_foreach(t, off, e) {
            rprintf("ingesting sym %s, val %v\n", symbol_string(off), e);
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
    apply(sh, 0);
    // something really strange is going on with the value of frame
    //    if (frame != END_OF_LOG) halt("bad log tag %p\n", frame);    
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
