#include <tfs_internal.h>

#define END_OF_LOG 1
#define TUPLE_AVAILABLE 2
#define END_OF_SEGMENT 3

#define TRAILER_SIZE 16

typedef struct tlog {
    filesystem fs;
    u64 remainder;
    buffer staging;
    vector completions;
    table dictionary;
    u64 offset;
    heap h;
} *tlog;

static CLOSURE_1_0(log_write_completion, void, vector);
static void log_write_completion(vector v)
{
    // reclaim the buffer now and the vector...make it a whole thing
    thunk i;
    vector_foreach(i, v) apply(i);
}

// xxx  currently we cant take writes during the flush

static void tlog_flush(tlog tl)
{
    thunk i;
    buffer b = tl->staging;
    buffer_clear(tl->completions);
    *(u8 *)buffer_ref(b, 0) = TUPLE_AVAILABLE;
    apply(tl->fs->write,
          buffer_ref(b, 0),
          tl->offset + b->start, buffer_length(b),
          closure(tl->h, log_write_completion, tl->completions));
    tl->offset += buffer_length(b)  -1;
    b->start+= buffer_length(b)  -1;
    push_u8 (b, 0);
}


void tlog_write(tlog tl, tuple t, thunk complete)
{
    vector_push(tl->completions, complete);
    serialize_tuple(tl->dictionary, tl->staging, t);
    /* and clear the we need to set the previous byte */
}


CLOSURE_1_0(log_read_complete, void, tlog);
void log_read_complete(tlog t)
{
    buffer b = t->staging;
    table d = allocate_table(t->h, identity_key, pointer_equal);
    u8 frame;
    do {
        frame = pop_u8(b);
        if (frame == TUPLE_AVAILABLE) {
            tuple t = deserialize_tuple(t->h, d, b);
            // if this is an extent, mark it out in the freemap
            // if this is a reference to a file number, max it 
        }
    } while(frame != END_OF_LOG);
    push_u8(b, 0);    
}

// deferring log extension -- should be a segment
void read_log(tlog tl, u64 offset, u64 size)
{
    tl->staging = allocate_buffer(tl->h, size);
    apply(tl->fs->read, tl->staging->contents, 0, tl->staging->length,
          closure(tl->h, log_read_complete, tl));
}

tlog tlog_create(heap h, filesystem fs)
{
    tlog tl = allocate(h, sizeof(struct tlog));
    tl->h = h;
    tl->offset = 0;
    read_log(tl, 0, 1024*1024);
    return tl;
}
