#include <tfs_internal.h>

struct fsfile {
    rtrie extents;
    filesystem fs;
    u64 length;
    tuple md;
};

u64 fsfile_get_length(fsfile f)
{
    return f->length;
}

void fsfile_set_length(fsfile f, u64 length)
{
    f->length = length;
}

static CLOSURE_5_1(copyout, void, filesystem, void *, void *, u64, status_handler, status);
void copyout(filesystem fs, void *target, void *source, u64 length, status_handler sh, status s)
{
    if (s) {
        apply(sh, s);
    } else {
        runtime_memcpy(target, source, length);
        apply(sh, s);
    }
    deallocate(fs->h, source, fs->blocksize);
}

static CLOSURE_4_2(fs_read_extent, void,
                   filesystem, buffer, merge, range,
                   range, void *);
static void fs_read_extent(filesystem fs,
                           buffer target,
                           merge m,
                           range q,
                           range ex,
                           void *val)
{
    range i = range_intersection(q, ex);
    // offset within a block - these are just the extents, so might be a sub
    u64 xfer = range_span(i);
    assert(xfer != 0);
    u64 block_start = u64_from_pointer(val);
    u64 tail = range_span(q) & (fs->blocksize - 1);
    u64 target_offset = i.start - q.start;
    void *target_start = buffer_ref(target, target_offset);

    // handle unaligned tail without clobbering extra memory
    if (tail && (ex.end > q.end)) {
        void *temp = allocate(fs->h, fs->blocksize);
        status_handler f = apply(m);
        xfer -= tail;
        status_handler copy = closure(fs->h, copyout, fs, target_start + xfer, temp, tail, f);
        fetch_and_add(&target->end, tail);
        apply(fs->r, temp, fs->blocksize, block_start + xfer, copy);
    }

    if (xfer) {
        status_handler f = apply(m);
        fetch_and_add(&target->end, xfer);
        apply(fs->r, target_start, xfer, block_start, f);
    }
}

static CLOSURE_2_1(filesystem_read_complete, void, io_status_handler, buffer, status);
static void filesystem_read_complete(io_status_handler c, buffer b, status s)
{
    apply(c, s, buffer_length(b));
}

void filesystem_read(filesystem fs, tuple t, void *dest, u64 length, u64 offset, io_status_handler completion)
{
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        tuple e = timm("result", "no such file %t", t);
        apply(completion, e, 0);
        return;
    }

    heap h = fs->h;
    u64 min, max;
    // b here is permanent - cache?
    buffer b = wrap_buffer(h, dest, length);
    /* b->end will accumulate the read extent lengths; enclose b so
       that filesystem_read_complete can hand the total read length to
       the completion. */
    b->end = b->start;
    merge m = allocate_merge(h, closure(h, filesystem_read_complete, completion, b));
    range total = irange(offset, offset+length);
    rtrie_range_lookup(f->extents, total, closure(h, fs_read_extent, f->fs, b, m, total));
}

// extend here
static CLOSURE_4_2(fs_write_extent, void,
                   filesystem, buffer, merge, u64 *, 
                   range, void *);
static void fs_write_extent(filesystem fs, buffer source, merge m, u64 *last, range x, void *val)
{
    buffer segment = source; // not really
    // if this doesn't lie on an alignment bonudary we may need to do a read-modify-write
    status_handler sh = apply(m);
    apply(fs->w, segment, x.start, sh);
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
    tuple e = timm("length", "%d", length);
    
    u64 storage = allocate_u64(f->fs->storage, pad(length, f->fs->alignment));
    if (storage == u64_from_pointer(INVALID_ADDRESS)) {
        halt("out of storage");
    }
    //  we should(?) encode this as an immediate bitstring?
    string off = aprintf(f->fs->h, "%d", storage);
    table_set(e, sym(offset), off);

    tuple exts = soft_create(f->fs, f->md, sym(extents));
    symbol offs = intern_u64(foffset);
    table_set(exts, offs, e);
    log_write_eav(f->fs->tl, exts, offs, e, ignore); 
    rtrie_insert(f->extents, foffset, length, pointer_from_u64(storage));
    return storage;
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
    rtrie_range_lookup(f->extents, irange(offset, offset+len), closure(h, fs_write_extent, f->fs, b, m, last));
    
    if (*last < (offset + len)) {
        u64 elen = (offset + len) - *last;
        u64 eoff = extend(f, *last, len);
        if (eoff != u64_from_pointer(INVALID_ADDRESS)) {
            status_handler sh = apply(m);
            apply(fs->w, wrap_buffer(transient, buffer_ref(b, *last), b->end - *last), eoff, sh);
        }
    }

    /* XXX Technically, we should wait until all extent writes have
       succeeded before extending the length. */
    u64 end = buffer_length(b) + offset;
    if (fsfile_get_length(f) < end) {
	/* XXX bother updating resident filelength tuple? */
	fsfile_set_length(f, end);
	filesystem_write_eav(fs, t, sym(filelength), value_from_u64(fs->h, end));
    }
}

fsfile allocate_fsfile(filesystem fs, tuple md)
{
    fsfile f = allocate(fs->h, sizeof(struct fsfile));
    f->extents = rtrie_create(fs->h);
    f->fs = fs;
    f->md = md;
    f->length = 0;
    table_set(fs->files, f->md, f);
    return f;
}

void link(tuple dir, fsfile f, buffer name)
{
    // this has to log the soft create too.
    log_write_eav(f->fs->tl, soft_create(f->fs, dir, sym(children)), intern(name), f->md, ignore);
}

int filesystem_mkdir(filesystem fs, char *fp)
{
    heap h = fs->h;
    tuple dir = allocate_tuple();
    tuple folder = table_find(fs->root, sym(children));
    symbol basename_sym;
    char *token, *rest = fp, *basename;

    /* 'make it a folder' by attaching a children node to the tuple */
    table_set(dir, sym(children), allocate_tuple());

    /* find the folder we need to mkdir in */
    while ((token = runtime_strtok_r(rest, "/", &rest))) {
        tuple prev_folder = folder;
        boolean final = *rest == '\0';
        folder = table_find(folder, sym_this(token));
        if (!folder) {
            if (final) {
                basename = token;
                folder = prev_folder;
                break;
            } else {
                msg_debug("a path component (\"%s\") is missing\n");
                return -1;
            }
        } else {
            if (final) {
                msg_debug("final path component (\"%s\") already exists\n");
                return -1;
            }
        }
    }

    basename_sym = sym_this(basename);
    table_set(folder, basename_sym, dir);
    log_write_eav(fs->tl, folder, basename_sym, dir, ignore);
    //log_flush(fs->tl);
    rprintf("mkdir: written!\n");

    return 0;
}

// should be passing status to the client
static CLOSURE_2_1(read_entire_complete, void, buffer_handler, buffer, status);
static void read_entire_complete(buffer_handler bh, buffer b, status s)
{
    apply(bh, b);
}


// translate symbolic to range trie
void extent_update(fsfile f, symbol foff, tuple value)
{
    u64 length, foffset, boffset;
    parse_int(alloca_wrap(symbol_string(foff)), 10, &foffset);
    parse_int(alloca_wrap(table_find(value, sym(length))), 10, &length);
    parse_int(alloca_wrap(table_find(value, sym(offset))), 10, &boffset);
    rtrie_insert(f->extents, foffset, length, pointer_from_u64(boffset));
    // xxx - fix before write
    //    rtrie_remove(f->fs->free, boffset, length);
}

fsfile fsfile_from_node(filesystem fs, tuple n)
{
    return table_find(fs->files, n);
}

// cache goes on top
void filesystem_read_entire(filesystem fs, tuple t, heap h, buffer_handler c, status_handler e)
{
    fsfile f;
    if ((f = table_find(fs->files, t))) {
        // block read is aligning to the next sector
        u64 len = pad(fsfile_get_length(f), fs->blocksize);
        buffer b = allocate_buffer(h, len + 1024);
        
        // that means a partial read, right?
        status_handler c1 = closure(f->fs->h, read_entire_complete, c, b);
        merge m = allocate_merge(f->fs->h, c1);
        status_handler k = apply(m); // hold a reference until we're sure we've issued everything
        rtrie_range_lookup(f->extents, irange(0, len), closure(h, fs_read_extent, fs, b, m, irange(0, len)));
        apply(k, STATUS_OK);
    } else {
        apply(e, timm("status", "no such file %v\n", t));
    }
}

void flush(filesystem fs, status_handler s)
{
    log_flush(fs->tl);
}

static CLOSURE_2_1(log_complete, void, filesystem_complete, filesystem, status);
static void log_complete(filesystem_complete fc, filesystem fs, status s)
{
    apply(fc, fs, s);
}

void create_filesystem(heap h,
                       u64 alignment,
                       u64 size,
                       block_read read,
                       block_write write,
                       tuple root,
                       filesystem_complete complete)
{
    filesystem fs = allocate(h, sizeof(struct filesystem));
    fs->files = allocate_table(h, identity_key, pointer_equal);
    fs->extents = allocate_table(h, identity_key, pointer_equal);    
    fs->r = read;
    fs->h = h;
    fs->w = write;
    fs->root = root;
    fs->alignment = alignment;
    fs->blocksize = SECTOR_SIZE;
    fs->free = rtrie_create(h);
    rtrie_insert(fs->free, 0, size, (void *)true); 
    rtrie_remove(fs->free, 0, INITIAL_LOG_SIZE);
    fs->storage = rtrie_allocator(h, fs->free);
    fs->tl = log_create(h, fs, closure(h, log_complete, complete, fs));
}

