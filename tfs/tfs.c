#include <tfs_internal.h>

// should operate directly on tuples in some future version

typedef struct extent {
    u64 file_start;
    u64 block_start;
    u64 length;
} *extent;
    
struct fsfile {
    rtrie extents;
    filesystem fs;
    signature s; // cant really update this 
    u64 oid;
};

CLOSURE_2_0(merge, void, thunk, u64 *);
void merge(thunk c, u64 *count)
{
    u64 n = fetch_and_add(count, -1ull);
    if (n == 1) apply(c);
}

// last is in file byte offset            
static CLOSURE_5_2(fs_read_extent, void,
                   filesystem, buffer, thunk, u64 *, u64 *, 
                   u64, u64);
static void fs_read_extent(filesystem fs, buffer target, thunk completion, u64 *last, u64 *count,
                           u64 start, u64 length)
{
    (*count)++;
    if (*last != 0) zero(buffer_ref(target, *last), target->start - *last);
    apply(fs->read, target, start, length, completion);
}

// for this kind of a stuff we should have a freelist of pages
void fs_read(fsfile f, void *target, u64 offset, u64 length, thunk completion)
{
    heap h = f->fs->h;
    u64 *last = allocate_zero(f->fs->h, sizeof(u64));
    buffer b = alloca_wrap_buffer(target, length);
    u64 *opcount = allocate_zero(h, sizeof(u64));
    (*opcount)++; // to avoid closing out the join before everyone is posted
    thunk j = closure(h, merge, completion, opcount);
    rtrie_range_lookup(f->extents, offset, length, closure(h, fs_read_extent, f->fs, b, j, last, opcount));
    apply(j);
}



static CLOSURE_3_2(fs_write_extent, void,
                   filesystem, buffer, thunk, 
                   u64, u64);
static void fs_write_extent(filesystem fs, buffer target, thunk completion, u64 offset, u64 length)
{
    apply(fs->write, target, offset, length, completion);
}

// consider not overwritint the old version and fixing up the metadata
void fs_write(fsfile f, void *target, u64 offset, u64 length, thunk completion)
{
    heap h = f->fs->h;
    u64 *last = allocate(h, sizeof(u64));
    *last = offset;
    buffer b = alloca_wrap_buffer(target, length);
    u64 *opcount = allocate_zero(h, sizeof(u64));
    (*opcount)++; // to avoid closing out the join before everyone is posted
    thunk j = closure(h, merge, completion, opcount);    
    rtrie_range_lookup(f->extents, offset, length, closure(h, fs_write_extent, f->fs, b, j));
    // extend for last segment    
    if (*last < length) {
        u64 base = allocate_u64(f->fs->storage, length);
        // out of space
        // we can compact here
        rtrie_insert(f->extents, base, length, 0);
    }
}


u64 file_length(fsfile f)
{
    u64 min, max;
    rtrie_extent(f->extents, &min, &max);
    return max;
}

fsfile create(filesystem fs)
{
    fsfile f = allocate(fs->h, sizeof(struct fsfile));
    f->extents = rtrie_create(fs->h);
    f->oid = fs->inode_count++;
    return f;
}


filesystem create_filesystem(heap h, u64 alignment, u64 size, fio read, fio write)
{
    filesystem fs = allocate(h, sizeof(struct filesystem));
    //    create_id_heap();
    return fs;
}

