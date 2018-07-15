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

void log_flush(log tl)
{
    thunk i;
    buffer b = tl->staging;
    buffer_clear(tl->completions);
    push_u8(b, END_OF_LOG);
    apply(tl->fs->w,
          b,
          tl->offset + b->start, 
          closure(tl->h, log_write_completion, tl->completions));
    b->end -= 1;
}


void log_write_eav(log tl, tuple e, symbol a, value v, thunk complete)
{
    // out of space
    push_u8(tl->staging, TUPLE_AVAILABLE);
    encode_eav(tl->staging, tl->dictionary, e, a, v);
    vector_push(tl->completions, complete);
    // flush!
}

void log_write(log tl, tuple t, thunk complete)
{
    // out of space
    push_u8(tl->staging, TUPLE_AVAILABLE);
    // this should be incremental on root!
    encode_tuple(tl->staging, tl->dictionary, t);
    vector_push(tl->completions, complete);
    // flush
}


CLOSURE_1_1(log_read_complete, void, log, status);
void log_read_complete(log tl, status s)
{
    buffer b = tl->staging;
    u8 frame = 0;
    // log extension
    for (; frame = pop_u8(b), frame == TUPLE_AVAILABLE;) {
        tuple t = decode_value(tl->h, tl->dictionary, b);
        fsfile f;
        
        // doesn't seem like all the incremental updates are handled here,
        // nor the recursive case
        table_foreach(t, k, v) {
            if (k == sym(extents)) {
                if (!(f = table_find(tl->fs->extents, v))) {
                    f = allocate_fsfile(tl->fs, t);
                }
                table_set(tl->fs->extents, v, f);
            }
        }

        if ((f = table_find(tl->fs->extents, t))) 
            table_foreach(t, off, e) extent_update(f, off, e);
    }
    // something really strange is going on with the value of frame
    //    if (frame != END_OF_LOG) halt("bad log tag %p\n", frame);    
}


// deferring log extension -- should be a segment
// by convention, the first tuple (which always
// has a relative id 0) is the root
void read_log(log tl, u64 offset, u64 size)
{
    tl->staging = allocate_buffer(tl->h, size);
    status_handler tlc = closure(tl->h, log_read_complete, tl);
    apply(tl->fs->r, tl->staging->contents, 0, tl->staging->length, tlc);
}

log log_create(heap h, filesystem fs)
{
    log tl = allocate(h, sizeof(struct log));
    tl->h = h;
    tl->offset = 0;
    tl->fs = fs;
    tl->completions = allocate_vector(h, 10);
    tl->dictionary = allocate_table(h, identity_key, pointer_equal);
    read_log(tl, 0, INITIAL_LOG_SEGMENT);
    
    // not sure we should be passing the root.. anyways, splat the
    // log root onto the given root
    table logroot = (table)table_find(tl->dictionary, pointer_from_u64(1));
    if (logroot)
        table_foreach (logroot, k, v)
            table_set(fs->root, k, v);
    return tl;
}
