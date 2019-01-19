//#define ENABLE_MSG_DEBUG
#include <tfs_internal.h>

#if defined(TFS_DEBUG)
#define tfs_debug(x, ...) do {rprintf("TFS: " x, ##__VA_ARGS__);} while(0)
#else
#define tfs_debug(x, ...)
#endif

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
    tfs_debug("copyout: target %p, length %P: %v\n", target, length, s);
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
    u64 xfer = range_span(i);
    assert(xfer != 0);
    u64 block_start = u64_from_pointer(val);

    // target_offset is required for the cases when q.start < ex.start
    // (q spans more than one extent) but this does not happen now
    // because rtrie_lookup() is used to find an extent (q.start is always >= ex.start)
    u64 target_offset = i.start - q.start;
    void *target_start = buffer_ref(target, target_offset);

    // make i absolute
    i.start += block_start;
    i.end += block_start;

    tfs_debug("fs_read_extent: q %R, ex %R, block_start %P, i %R, xfer %P, target_offset %P, target_start %p, blocksize %d\n",
        q, ex, block_start, i, xfer, target_offset, target_start, fs->blocksize);

    /*
     * +       i.start--+        +--start_padded      i.end--+      +--end_padded
     * |                |        |                           |      |
     * |                v        v                           v      v
     * v                 <-head->                    <-tail->
     * |---------|------[========|=======....=======|========]------|
     *            <--blocksize-->                    <--blocksize-->
     */

    // handle unaligned head without clobbering extra memory
    u64 start_padded = pad(i.start, fs->blocksize);
    if (i.start > 0 && i.start < start_padded) {
        // unaligned start
        u64 head = MIN(start_padded - i.start, xfer);

        void *temp = allocate(fs->h, fs->blocksize);
        status_handler f = apply(m);
        xfer -= head;
        status_handler copy = closure(fs->h, copyout, fs, target_start, temp + (fs->blocksize - head), head, f);
        fetch_and_add(&target->end, head);
        u64 read_start = start_padded - fs->blocksize;
        tfs_debug("fs_read_extent: unaligned head(%P, %P): reading block at %P (%P)\n",
            i.start, start_padded, read_start, head);
        apply(fs->r, temp, fs->blocksize, read_start, copy);

        i.start += head;
        target_start += head;
    }

    // handle unaligned tail without clobbering extra memory
    u64 end_padded = pad(i.end, fs->blocksize);
    if (xfer > 0 && i.end < end_padded) {
        // unaligned end
        u64 tail = i.end + fs->blocksize - end_padded;

        void *temp = allocate(fs->h, fs->blocksize);
        status_handler f = apply(m);
        assert(xfer >= tail);
        xfer -= tail;
        status_handler copy = closure(fs->h, copyout, fs, target_start + xfer, temp, tail, f);
        fetch_and_add(&target->end, tail);
        u64 read_start = end_padded - fs->blocksize;
        tfs_debug("fs_read_extent: unaligned tail(%P, %P): reading block at %P (%P)\n",
            i.end, end_padded, read_start, tail);
        apply(fs->r, temp, fs->blocksize, read_start, copy);
    }

    if (xfer > 0) {
        status_handler f = apply(m);
        fetch_and_add(&target->end, xfer);
        assert(i.start == 0 || pad(i.start, fs->blocksize) == i.start);
        tfs_debug("fs_read_extent: reading blocks at %P (%P)\n",
            i.start, xfer);
        apply(fs->r, target_start, xfer, i.start, f);
    }
}

io_status_handler ignore_io_status;

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

static u64 allocate_extend(fsfile f, u64 foffset, u64 length)
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

static CLOSURE_3_1(fsfile_write_cleanup, void, filesystem, buffer, status_handler, status);
void fsfile_write_cleanup(filesystem fs, buffer b, status_handler sh, status s)
{
    deallocate_buffer(b);
    msg_debug("%d: status %v (%s)\n", __LINE__,
            s, is_ok(s) ? "OK" : "NOTOK");

    apply(sh, s);
}

static CLOSURE_4_1(fsfile_write, void,
                   filesystem, buffer, u64, status_handler, 
                   status)
static void fsfile_write(filesystem fs, buffer b, u64 block_start, status_handler sh, status s)
{
    msg_debug("%d: writing to %d for %d\n", __LINE__, block_start, buffer_length(b));
    status_handler cleanup = closure(fs->h, fsfile_write_cleanup, fs, b, sh);
    apply(fs->w, b, block_start, cleanup);
}

static CLOSURE_6_1(fsfile_modify_read, void, filesystem, buffer, buffer, u64, u64, status_handler, status);
void fsfile_modify_read(filesystem fs, buffer target, buffer source, u64 block_start, u64 offset_in_block, status_handler sh, status s)
{
    if (s) {
        deallocate(fs->h, target, fs->blocksize);
        apply(sh, s);
    } else {
        u64 length = MIN(fs->blocksize, buffer_length(source));
        runtime_memcpy(buffer_ref(target,offset_in_block), buffer_ref(source,0), length);
        buffer_consume(source, length);
        status_handler do_write = closure(fs->h, fsfile_write, fs, target, block_start, sh);
        apply(do_write, s);
    }
}

static CLOSURE_6_2(fsfile_update, void,
                   fsfile, tuple, buffer, merge, u64 *, tuple, 
                   range, void *);
static void fsfile_update(fsfile f, tuple t, buffer source, merge m, u64 *last, tuple write_state, range block_range, void *val)
{
    filesystem fs = f->fs;
    u64 file_offset = *last;
    u64 offset_in_block = file_offset ? (file_offset % fs->blocksize) : 0;
    u64 block_len = block_range.end - block_range.start;
    u64 source_len = MIN(buffer_length(source), fs->blocksize);
    u64 block_start = u64_from_pointer(val);

    status_handler sh = apply(m);
    
    u64 xfer = ((source_len + offset_in_block) > fs->blocksize) ? source_len - offset_in_block : source_len;

    u64 new_block_len = MAX(block_len, xfer + offset_in_block);
    boolean need_rmw = ((block_len != new_block_len) && (xfer != fs->blocksize)) ? true : false;

    buffer wrapped_source = sub_buffer(fs->h, source, 0, xfer);
    buffer_consume(source, xfer);

    table_set(write_state, intern_u64(block_range.start), pointer_from_u64(new_block_len));
    *last += xfer;
    block_range.end = new_block_len;

    // if this doesn't lie on an alignment bonudary we NEED to do a read-modify-write
    if (need_rmw) {
        buffer rmw_buffer = allocate_buffer(fs->h, fs->blocksize);
        buffer_produce(rmw_buffer,fs->blocksize);
        status_handler copy = closure(fs->h, fsfile_modify_read, fs, rmw_buffer, wrapped_source, block_start, offset_in_block, sh);
        apply(fs->r, buffer_ref(rmw_buffer,0), fs->blocksize, block_start, copy);
    } else {
        apply(fs->w, wrapped_source, block_start, sh);
    }
}


static CLOSURE_6_1(filesystem_write_complete, void, fsfile, tuple, u64, io_status_handler, u64 *, tuple, status);
static void filesystem_write_complete(fsfile f, tuple t, u64 length, io_status_handler completion, u64 *last, tuple write_state,  status s)
{
    filesystem fs = f->fs;
    u64 end = *last;

    deallocate(fs->h, last, sizeof(u64));

    if (fsfile_get_length(f) < end) {
        /* XXX bother updating resident filelength tuple? */
        fsfile_set_length(f, end);
        filesystem_write_eav(fs, t, sym(filelength), value_from_u64(fs->h, end));
    }

    /* Reset the extent rtrie and update the extent cache */
    f->extents = rtrie_create(fs->h);
    tuple extents = table_find(t, sym(extents));
    table_foreach(extents, off, e) {
        u64 efoffset;
        parse_int(alloca_wrap(symbol_string(off)), 10, &efoffset);
        u64 updated_length = u64_from_pointer(table_find(write_state, intern_u64(efoffset)));
        extent_update(f, off, e, updated_length);
    }
    table_set(fs->files, t, f);
    tuple e = STATUS_OK;
    apply(completion, e, length);
}

static CLOSURE_7_1(fsfile_extend, void, fsfile, tuple, buffer, u64, io_status_handler, u64 *, tuple, status);
static void fsfile_extend(fsfile f, tuple t, buffer b, u64 length, io_status_handler completion, u64 *last, tuple write_state,  status s)
{
    u64 offset = *last;
    filesystem fs = f->fs;

    merge m = allocate_merge(fs->h, closure(fs->h, filesystem_write_complete,
                f, t, length, completion, last, write_state));

    status_handler sh = apply(m); // Prevent race to filesystem_write_complete until we complete loop 
    while (buffer_length(b)) {
#ifndef HOST_BUILD
        u64 elen = MIN(fs->blocksize, buffer_length(b));
#else
        u64 elen = buffer_length(b);
#endif
        u64 eoff = allocate_extend(f, offset, elen);
        if (eoff != u64_from_pointer(INVALID_ADDRESS)) {
            status_handler sh = apply(m);
            buffer bf = wrap_buffer(transient, buffer_ref(b, 0), elen);
            offset += elen;
            apply(fs->w, bf, eoff, sh);
            buffer_consume(b, elen);
        }
    }
    *last = offset;
    apply(sh, s);
}

// consider not overwritint the old version and fixing up the metadata
void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, io_status_handler completion)
{
    fsfile f;
    
    if (!(f = table_find(fs->files, t))) {
        apply(completion, timm("no such file"), 0);
        return;
    }

    u64 len = buffer_length(b);
    u64 *last = allocate(fs->h, sizeof(u64));
    *last = offset;
    tuple write_state = allocate_tuple();

    u64 aligned_offset = (offset/fs->blocksize) * fs->blocksize;
    u64 end_offset = offset+len;
    u64 aligned_end_offset = pad(end_offset, fs->alignment);

    merge m = allocate_merge(fs->h, closure(fs->h, fsfile_extend,
                f, t, b, buffer_length(b), completion, last, write_state));

    status_handler sh = apply(m); // Prevent race to fsfile_extend, until we are sure rtrie_range_lookup is scheduled
    range total = irange(aligned_offset, aligned_end_offset);
    rtrie_range_lookup(f->extents, total, closure(fs->h, fsfile_update, f, t, b, m, last, write_state));
    apply(sh, 0);
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

fs_status filesystem_mkentry(filesystem fs, tuple root, char *fp, tuple entry)
{
    tuple children = (root ? root : table_find(fs->root, sym(children)));
    symbol basename_sym;
    char *token, *rest = fp, *basename = (char *)0;

    /* find the folder we need to mkentry in */
    while ((token = runtime_strtok_r(rest, "/", &rest))) {
        boolean final = *rest == '\0';
        tuple t = table_find(children, sym_this(token));
        if (!t) {
            if (!final) {
                msg_debug("a path component (\"%s\") is missing\n", token);
                return FS_STATUS_NOENT;
            }

            basename = token;
            break;
        } else {
            if (final) {
                msg_debug("final path component (\"%s\") already exists\n", token);
                return FS_STATUS_EXIST;
            }

            children = table_find(t, sym(children));
            if (!children) {
                msg_debug("a path component (\"%s\") is not a folder\n", token);
                return FS_STATUS_NOTDIR;
            }
        }
    }

    basename_sym = sym_this(basename);
    table_set(children, basename_sym, entry);
    log_write_eav(fs->tl, children, basename_sym, entry, ignore);
    //log_flush(fs->tl);
    msg_debug("written!\n");
    return FS_STATUS_OK;
}

fs_status filesystem_mkdir(filesystem fs, tuple root, char *fp)
{
    tuple dir = allocate_tuple();
    /* 'make it a folder' by attaching a children node to the tuple */
    table_set(dir, sym(children), allocate_tuple());

    return filesystem_mkentry(fs, root, fp, dir);
}

fs_status filesystem_creat(filesystem fs, tuple root, char *fp)
{
    tuple dir = allocate_tuple();
    static buffer off = 0;

    if (!off)
        off = wrap_buffer_cstring(fs->h, "0");

    /* 'make it a file' by adding an empty extents list */
    table_set(dir, sym(extents), allocate_tuple());
    table_set(dir, sym(filelength), off);

    fsfile f = allocate_fsfile(fs, dir);
    fsfile_set_length(f, 0);

    return filesystem_mkentry(fs, root, fp, dir);
}

// should be passing status to the client
static CLOSURE_2_1(read_entire_complete, void, buffer_handler, buffer, status);
static void read_entire_complete(buffer_handler bh, buffer b, status s)
{
    apply(bh, b);
}


// translate symbolic to range trie
void extent_update(fsfile f, symbol foff, tuple value, u64 realsize)
{
    u64 length, foffset, boffset;
    parse_int(alloca_wrap(symbol_string(foff)), 10, &foffset);
    if (!realsize)
        parse_int(alloca_wrap(table_find(value, sym(length))), 10, &length);
    else
        length = realsize;

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

/* XXX: cbm stuff is temporary */

void __cbm_set(struct cbm *c, u64 bit, boolean val)
{
    if (val)
        c->buffer[bit / 8] |= 1 << (bit % 8);
    else
        c->buffer[bit / 8] &= ~(1 << (bit % 8));
}

void cbm_set(struct cbm *c, u64 start, u64 len)
{
    u64 i;
    for (i = 0; i < len; i ++)
        __cbm_set(c, start + i, true);
}

void cbm_unset(struct cbm *c, u64 start, u64 len)
{
    u64 i;
    for (i = 0; i < len; i ++)
        __cbm_set(c, start + i, false);
}

boolean cbm_test(struct cbm *c, u64 i)
{
    return (c->buffer[i / 8] & (1 << (i % 8))) != 0;
}

boolean cbm_contains(struct cbm *c, u64 start, u64 cnt, boolean val)
{
    u64 i;

    for (i = 0; i < cnt; i ++)
        if (cbm_test(c, start + i) == val)
            return true;

    return false;
}

u64 cbm_scan(struct cbm *c, u64 start, u64 cnt, boolean val)
{
    u64 last = c->capacity_in_bits - start;
    u64 i;
    for (i = start; i <= last; i ++)
        if (!cbm_contains(c, i, cnt, !val))
            return i;

    return INVALID_PHYSICAL;
}

struct cbmalloc {
    struct heap h;
    struct cbm *c;
};

u64 cbm_allocator_alloc(heap h, bytes len)
{
    struct cbmalloc *c = (struct cbmalloc *) h;
    len >>= 9;
    if (len > c->c->capacity_in_bits) {
        return INVALID_PHYSICAL;
    }
    u64 ret = cbm_scan(c->c, 0, len, false);
    if (ret != INVALID_PHYSICAL) {
        cbm_set(c->c, ret, len);
        return ret << 9;
    }

    return ret;
}

heap cbm_allocator(heap h, struct cbm *c)
{
    struct cbmalloc *a = allocate(h, sizeof(*a));
    a->h.alloc = cbm_allocator_alloc;
    a->c = c;
    return &a->h;
}

struct cbm *cbm_create(heap h, u64 capacity)
{
    struct cbm *c = allocate(h, sizeof(*c));
    u8 *buffer = allocate(h, (capacity >> 3) + 1);
    c->buffer = buffer;
    c->capacity_in_bits = capacity;
    return c;
}

void enumerate_files(filesystem fs, tuple root)
{
    if (root) {
        table_foreach(root, k, v) {
            tuple extents = table_find(v, sym(extents));
            if (extents) {
                table_foreach(extents, k1, v1) {
                    u64 offset, length, block_offset, block_length;
                    parse_int(alloca_wrap(table_find(v1, sym(length))), 10, &length);
                    parse_int(alloca_wrap(table_find(v1, sym(offset))), 10, &offset);
                    block_offset = offset >> 9;
                    block_length = length >> 9;
                    cbm_set(fs->free, block_offset, block_length + 1);
                }
            }
        }
    }
}

static CLOSURE_2_1(log_complete, void, filesystem_complete, filesystem, status);
static void log_complete(filesystem_complete fc, filesystem fs, status s)
{
    tuple fsroot = children(fs->root);
    enumerate_files(fs, fsroot);
    apply(fc, fs, s);
}

static CLOSURE_0_2(ignore_io_body, void, status, bytes);
static void ignore_io_body(status s, bytes length){}

void create_filesystem(heap h,
                       u64 alignment,
                       u64 size,
                       block_read read,
                       block_write write,
                       tuple root,
                       filesystem_complete complete)
{
    filesystem fs = allocate(h, sizeof(struct filesystem));
    ignore_io_status = closure(h, ignore_io_body);
    fs->files = allocate_table(h, identity_key, pointer_equal);
    fs->extents = allocate_table(h, identity_key, pointer_equal);    
    fs->r = read;
    fs->h = h;
    fs->w = write;
    fs->root = root;
    fs->alignment = alignment;
    fs->blocksize = SECTOR_SIZE;
    fs->free = cbm_create(h, size >> 9);
    cbm_unset(fs->free, 0, size >> 9);
    cbm_set(fs->free, 0, INITIAL_LOG_SIZE >> 9);
    fs->storage = cbm_allocator(h, fs->free);
    fs->tl = log_create(h, fs, closure(h, log_complete, complete, fs));
}

tuple filesystem_getroot(filesystem fs)
{
    return fs->root;
}
