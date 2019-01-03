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

// extend here
// This function is terribly broken. *last is never updated, but it should be.
// Leave it as it is for now, but get back to this asap. -lkurusa
static CLOSURE_4_2(fs_write_extent, void,
                   filesystem, buffer, merge, u64 *, 
                   range, void *);
static void fs_write_extent(filesystem fs, buffer source, merge m, u64 *last, range x, void *val)
{
    u64 target_len = x.end - x.start, source_len = buffer_length(source);
    // if this doesn't lie on an alignment bonudary we may need to do a read-modify-write

    /* Will this extent be reallocated? */
    if (source_len > target_len)
        return;

    /* XXX: is this correct? */
    status_handler sh = apply(m);
    apply(fs->w, source, x.start, sh);
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

static CLOSURE_4_1(filesystem_write_complete, void, fsfile, tuple, u64, io_status_handler, status);
static void filesystem_write_complete(fsfile f, tuple t, u64 end, io_status_handler completion, status s)
{
    filesystem fs = f->fs;

    if (fsfile_get_length(f) < end) {
        /* XXX bother updating resident filelength tuple? */
        fsfile_set_length(f, end);
        filesystem_write_eav(fs, t, sym(filelength), value_from_u64(fs->h, end));
    }

    /* Reset the extent rtrie and update the extent cache */
    f->extents = rtrie_create(fs->h);
    tuple extents = table_find(t, sym(extents));
    table_foreach(extents, off, e)
        extent_update(f, off, e);
    table_set(fs->files, t, f);

    /* TODO(lkurusa): Write the final root tuple to the disk */

    tuple e = STATUS_OK;
    apply(completion, e, end);
}

// consider not overwritint the old version and fixing up the metadata
void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, io_status_handler completion)
{
    heap h = fs->h;
    u64 len = buffer_length(b);
    u64 *last = allocate(h, sizeof(u64));
    *last = offset;
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        apply(completion, timm("no such file"), 0);
        return;
    }

    merge m = allocate_merge(fs->h, closure(fs->h, filesystem_write_complete,
                f, t, buffer_length(b) + offset, completion));
    rtrie_range_lookup(f->extents, irange(offset, offset+len), closure(h, fs_write_extent, f->fs, b, m, last));
    
    if (*last < (offset + len)) {
        u64 elen = (offset + len) - *last;
        u64 eoff = extend(f, *last, elen);
        if (eoff != u64_from_pointer(INVALID_ADDRESS)) {
            status_handler sh = apply(m);

            /* XXX: this should only pop up when writing to virtio,
               check for HOST_BUILD is just a lazy kludge */
#ifndef HOST_BUILD
            if (b->end - *last > SECTOR_SIZE)
                rprintf("trying to write more than what's supported: %d > %d\n",
                        b->end - *last, SECTOR_SIZE);
#endif

            buffer bf = wrap_buffer(transient, buffer_ref(b, *last), b->end - *last);
            apply(fs->w, bf, eoff, sh);
        }
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

fs_status filesystem_mkentry(filesystem fs, char *fp, tuple entry)
{
    tuple children = table_find(fs->root, sym(children));
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

fs_status filesystem_mkdir(filesystem fs, char *fp)
{
    tuple dir = allocate_tuple();
    /* 'make it a folder' by attaching a children node to the tuple */
    table_set(dir, sym(children), allocate_tuple());

    return filesystem_mkentry(fs, fp, dir);
}

fs_status filesystem_creat(filesystem fs, char *fp)
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

    return filesystem_mkentry(fs, fp, dir);
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

