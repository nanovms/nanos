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
    // out of space
    encode_eav(tl->staging, tl->dictionary, e, a, v);
    vector_push(tl->completions, complete);
    // flush!
}

void log_write(log tl, tuple t, thunk complete)
{
    // out of space
    encode_tuple(tl->staging, tl->dictionary, t);
    vector_push(tl->completions, complete);
    // flush
}


static void extent_update(filesystem fs, tuple t, symbol a, tuple value)
{
    rtrie e = table_find(fs->extents, t);
    buffer lengtht = table_find(value, sym(length));
    buffer offsett = table_find(value, sym(offset));
    u64 length, foffset, boffset;
    parse_int(symbol_string(a), 10, &foffset);
    parse_int(lengtht, 10, &length);
    parse_int(offsett, 10, &boffset);
    rtrie_insert(e, foffset, length, pointer_from_u64(boffset));
    rtrie_remove(fs->free, boffset, length);
    // update freemap
}


CLOSURE_1_1(log_read_complete, void, log, status);
void log_read_complete(log tl, status s)
{
    buffer b = tl->staging;
    u8 frame;
    do {
        frame = pop_u8(b);
        if (frame == TUPLE_AVAILABLE) {
            tuple t = decode_value(t->h, tl->dictionary, b);

            table_foreach(t, k, v) {
                if (k == sym(extents)) {
                    fsfile f;                     
                    if (!(f = table_find(tl->fs->extents, v))) {
                        f = allocate_fsfile(tl->fs, t);
                    }
                    table_set(tl->fs->extents, v, f);
                }
            }
            // insert files as inode
            // if this is an extent, mark it out in the freemap
            // if this is a reference to a file number, map it 
        }
    } while(frame != END_OF_LOG);
    push_u8(b, 0);    
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
    // allocate the dictionary
    table_set(tl->dictionary, pointer_from_u64(0), fs->root);
    read_log(tl, 0, 1024*1024);
    return tl;
}
