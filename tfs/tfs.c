#include <tfs_internal.h>

struct fsfile {
    rtrie extents;
    filesystem fs;
    tuple md;
};


// last is in file byte offset            
static CLOSURE_4_2(fs_read_extent, void,
                   filesystem, buffer, u64 *, merge, 
                   u64, u64);
static void fs_read_extent(filesystem fs,
                           buffer target,
                           u64 *last,
                           merge m,
                           u64 start,
                           u64 length)
{
    status_handler f = apply(m);
    if (*last != 0) zero(buffer_ref(target, *last), target->start - *last);
    apply(fs->r, target, start, length, f);
}

// actually need to return the length read?
void filesystem_read(filesystem fs, tuple t, void *dest, u64 offset, u64 length, status_handler completion)
{
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        tuple e = timm("result", "no such file %t", t);
        apply(completion, e);
        return;
    }
    // for temporary stuff we should have a freelist of pages and a trajectory
    // policy
    // cache
    heap h = fs->h;
    u64 min, max;
    
    u64 *last = allocate_zero(f->fs->h, sizeof(u64));
    // b here is permanent - cache?
    buffer b = wrap_buffer(h, dest, length);
    merge m = allocate_merge(h, completion);
    // wrap this in another ref so we dont vaccuously exit?
    rtrie_range_lookup(f->extents, offset, length, closure(h, fs_read_extent, f->fs, b, last, m));
}

static CLOSURE_3_2(fs_write_extent, void,
                   filesystem, buffer, merge, 
                   u64, u64);
static void fs_write_extent(filesystem fs, buffer target, merge m, u64 offset, u64 length)
{
    buffer segment = target; // not really
    // if this doesn't lie on an alignment bonudary we may need to do a read-modify-write
    status_handler sh = apply(m);
    apply(fs->w, segment, offset, sh);
}

// wrap in an interface
static tuple soft_create(filesystem fs, tuple t, symbol a)
{
    tuple v;
    if (!(v = table_find(t, a))) {
        v = allocate_tuple();
        table_set(t, a, v);
        log_write_eav(fs->tl, t, a, v, ignore); // not really ignore, this should carry a merge
    }
    return v;
}

static u64 extend(fsfile f, u64 foffset, u64 length)
{
    tuple e = allocate_tuple();
    // timm!
    table_set(e, sym(length), aprintf(f->fs->h, "%d", length));
    
    u64 storage = allocate_u64(f->fs->storage, length);
    if (storage == u64_from_pointer(INVALID_ADDRESS)) {
        halt("out of storage");
    }
    //    buffer off = allocate_buffer(f->fs->h, sizeof(u64));    
    //    buffer_write_le64(off, storage);
    //   we can(?) encode this as an immediate bitstring?
    string off = aprintf(f->fs->h, "%d", storage);
    table_set(e, sym(offset), off);

    tuple exts = soft_create(f->fs, f->md, sym(extents));
    symbol offs = intern_u64(foffset);
    table_set(exts, offs, e);
    log_write_eav(f->fs->tl, exts, offs, e, ignore); // merge
    rtrie_insert(f->extents, foffset, length, pointer_from_u64(storage));
    return storage;
}

                   
// consider not overwritint the old version and fixing up the metadata
void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, status_handler completion)
{
    heap h = fs->h;
    u64 len = buffer_length(b);
    u64 *last = allocate(h, sizeof(u64));
    *last = offset;
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        apply(completion, timm("no such file"));
        return;
    }
    merge m = allocate_merge(fs->h, completion);
    rtrie_range_lookup(f->extents, offset, len, closure(h, fs_write_extent, f->fs, b, m));
    // extend for last segment    .. this isn't enough, we may be filling in a hole
    if (*last < (offset + len)) {
        u64 elen = (offset + len) - *last;
        // out of space status
        // presumably it would be possible to extend into multiple fragments
        u64 eoff = extend(f, *last, len);
        if (eoff != u64_from_pointer(INVALID_ADDRESS))
            fs_write_extent(fs, b, m, eoff, elen);
    }
}

// need to provide better/more symmetric access to metadata, but ...
// status?
void filesystem_write_tuple(filesystem fs, tuple t)
{
    log_write(fs->tl, t, ignore);
}

void filesystem_write_eav(filesystem fs, tuple t, symbol a, value v)
{
    log_write_eav(fs->tl, t, a, v, ignore);
}


u64 file_length(fsfile f)
{
    u64 min, max;
    rtrie_extent(f->extents, &min, &max);
    return max;
}

fsfile allocate_fsfile(filesystem fs, tuple md)
{
    fsfile f = allocate(fs->h, sizeof(struct fsfile));
    f->extents = rtrie_create(fs->h);
    f->fs = fs;
    f->md = md;
    table_set(fs->files, f->md, f);
    return f;
}

void link(tuple dir, fsfile f, buffer name)
{
    // this has to log the soft create too.
    log_write_eav(f->fs->tl, soft_create(f->fs, dir, sym(children)), intern(name), f->md, ignore);
}

static CLOSURE_2_1(read_entire_complete, void, buffer_handler, buffer, status);
static void read_entire_complete(buffer_handler bh, buffer b, status s)
{
    apply(bh, b);
}


void extent_update(filesystem fs, tuple t, symbol a, tuple value)
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
}


void filesystem_read_entire(filesystem fs, tuple t, heap h, buffer_handler c)
{
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        apply(c, 0);
        return;
    }
    // cache goes on top
    buffer b = allocate(h, file_length(f));
    // that means a partial read, right?
    u64 *last = allocate_zero(f->fs->h, sizeof(u64));
    merge m = allocate_merge(h, closure(h, read_entire_complete, c, b));
    status_handler k = apply(m); // hold a reference until we're sure we've issued everything
    rtrie_range_lookup(f->extents, 0, file_length(f), closure(h, fs_read_extent, fs, b, last, m));
    apply(k, STATUS_OK);
}

void flush(filesystem fs, status_handler s)
{
    log_flush(fs->tl);
}

filesystem create_filesystem(heap h,
                             u64 alignment,
                             u64 size,
                             block_read read,
                             block_write write,
                             tuple root)
{
    filesystem fs = allocate(h, sizeof(struct filesystem));
    fs->files = allocate_table(h, identity_key, pointer_equal);
    fs->extents = allocate_table(h, identity_key, pointer_equal);    
    fs->r = read;
    fs->h = h;
    fs->w = write;
    fs->root = root;    
    fs->free = rtrie_create(h);
    rtrie_insert(fs->free, 0, size, 0);
    rtrie_remove(fs->free, 0, INITIAL_LOG_SIZE);
    fs->storage = rtrie_allocator(h, fs->free);
    fs->tl = log_create(h, fs);
    return fs;
}

