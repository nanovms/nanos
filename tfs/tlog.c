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
    vector_foreach(i, v) apply(i);
}

// xxx  currently we cant take writes during the flush

static void log_flush(log tl)
{
    thunk i;
    buffer b = tl->staging;
    buffer_clear(tl->completions);
    *(u8 *)buffer_ref(b, 0) = TUPLE_AVAILABLE;
    apply(tl->fs->w,
          b,
          tl->offset + b->start, 
          closure(tl->h, log_write_completion, tl->completions));
    tl->offset += buffer_length(b)  -1;
    b->start+= buffer_length(b)  -1;
    push_u8 (b, 0);
}


void log_write_eav(log tl, tuple e, symbol a, value v, thunk complete)
{
    vector_push(tl->completions, complete);
}

void log_write(log tl, tuple t, thunk complete)
{
    /* and clear the we need to set the previous byte */
}


CLOSURE_1_1(log_read_complete, void, log, status);
void log_read_complete(log t, status s)
{
    buffer b = t->staging;
    table d = allocate_table(t->h, identity_key, pointer_equal);
    u8 frame;
    do {
        frame = pop_u8(b);
        if (frame == TUPLE_AVAILABLE) {
            tuple t = deserialize_tuple(t->h, d, b);
            // insert files as inode
            // if this is an extent, mark it out in the freemap
            // if this is a reference to a file number, map it 
        }
    } while(frame != END_OF_LOG);
    push_u8(b, 0);    
}

// deferring log extension -- should be a segment
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
    read_log(tl, 0, 1024*1024);
    return tl;
}
