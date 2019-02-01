#include <tfs_internal.h>

#if defined(TFS_DEBUG)
#define tfs_debug(x, ...) do {rprintf("TFS: " x, ##__VA_ARGS__);} while(0)
#else
#define tfs_debug(x, ...)
#endif

struct fsfile {
    rangemap extentmap;
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

static CLOSURE_6_1(copyout, void, filesystem, void *, void *, u64, u64, status_handler, status);
void copyout(filesystem fs, void *target, void *source, u64 offset, u64 length, status_handler sh, status s)
{
    tfs_debug("copyout: source %p, offset %d, target %p, length %P: %v\n", source, offset, target, length, s);
    if (s) {
        apply(sh, s);
    } else {
        runtime_memcpy(target, (char *) source + offset, length);
        apply(sh, s);
    }
    deallocate(fs->h, source, fs->blocksize);
}

/* range_from_rmnode for file extent range */
typedef struct extent {
    struct rmnode node;
    u64 block_start;
    u64 allocated;
} *extent;

static inline extent allocate_extent(heap h, range init_range, u64 block_start, u64 allocated)
{
    extent e = allocate(h, sizeof(struct extent));
    if (e == INVALID_ADDRESS)
        return e;
    rmnode_init(&e->node, init_range);
    e->block_start = block_start;
    e->allocated = allocated;
    return e;
}

static CLOSURE_4_1(fs_read_extent, void,
                   filesystem, buffer, merge, range,
                   rmnode);
static void fs_read_extent(filesystem fs,
                           buffer target,
                           merge m,
                           range q,
                           rmnode node)
{
    extent e = (extent)node;
    range i = range_intersection(q, node->r);
    u64 block_start = e->block_start;

    // target_offset is required for the cases when q.start < ex.start
    // (q spans more than one extent) but this does not happen now
    // because rtrie_lookup() is used to find an extent (q.start is always >= ex.start)
    u64 target_offset = i.start - q.start;
    void *target_start = buffer_ref(target, target_offset);
    bytes target_length = target->length;

    // make i absolute
    i.start += block_start;
    i.end += block_start;

    tfs_debug("fs_read_extent: q %R, ex %R, block_start %P, i %R, target_offset %d, target_start %p, target length %d, blocksize %d\n",
        q, node->r, block_start, i, target_offset, target_start, target_length, fs->blocksize);

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
        u64 head = MIN(start_padded - i.start, range_span(i));

        void *temp = allocate(fs->h, fs->blocksize);
        assert(temp != INVALID_ADDRESS);
        status_handler f = apply(m);
        status_handler copy = closure(fs->h, copyout, fs, target_start, temp, fs->blocksize - (start_padded - i.start), head, f);
        fetch_and_add(&target->end, head);
        u64 read_start = start_padded - fs->blocksize;
        tfs_debug("fs_read_extent: unaligned head (%P, %P): reading block at %P (%P) to %p\n",
            i.start, start_padded, read_start, head, temp);
        apply(fs->r, temp, fs->blocksize, read_start, copy);

        i.start += head;
        target_start += head;
        target_length -= head;
    }

    // handle unaligned tail without clobbering extra memory
    u64 end_padded = pad(i.end, fs->blocksize);
    if (range_span(i) > 0 && i.end < end_padded && end_padded - i.start > target_length) {
        // unaligned end
        u64 tail = i.end + fs->blocksize - end_padded;

        void *temp = allocate(fs->h, fs->blocksize);
        assert(temp != INVALID_ADDRESS);
        status_handler f = apply(m);
        assert(range_span(i) >= tail);
        status_handler copy = closure(fs->h, copyout, fs, target_start + range_span(i) - tail, temp, 0, tail, f);
        fetch_and_add(&target->end, tail);
        u64 read_start = end_padded - fs->blocksize;
        tfs_debug("fs_read_extent: unaligned tail (%P, %P): reading block at %P (%P) to %p\n",
            i.end, end_padded, read_start, tail, temp);
        apply(fs->r, temp, fs->blocksize, read_start, copy);

        i.end -= tail;
        target_length -= tail;
    }

#ifdef BOOT
    if (range_span(i) > 0) {
        u64 xfer = range_span(i);
        u64 xfer_padded = pad(xfer, fs->blocksize);

        status_handler f = apply(m);
        fetch_and_add(&target->end, xfer);
        assert(i.start == 0 || pad(i.start, fs->blocksize) == i.start);
        assert(xfer <= target_length);
        tfs_debug("fs_read_extent: reading blocks at %P (xfer %P), target %p\n",
                  i.start, xfer_padded, target_start);
        apply(fs->r, target_start, xfer_padded, i.start, f);
    }
#else
    // general heap max_order is 20
    u64 max_read_chunk = U64_FROM_BIT(20);
    while (range_span(i) > 0) {
        u64 xfer = MIN(range_span(i), max_read_chunk);
        assert(xfer);
        u64 xfer_padded = pad(xfer, fs->blocksize);

        void *temp = allocate(fs->h, xfer_padded);
        assert(temp != INVALID_ADDRESS);
        status_handler f = apply(m);
        assert(xfer <= target_length);
        status_handler copy = closure(fs->h, copyout, fs, target_start, temp, 0, xfer, f);
        fetch_and_add(&target->end, xfer);
        assert(i.start == 0 || pad(i.start, fs->blocksize) == i.start);
        tfs_debug("fs_read_extent: chunk %R (%P): reading blocks at %P (%P) to %p\n",
            i, xfer_padded, i.start, xfer, temp);
        apply(fs->r, temp, xfer_padded, i.start, copy);

        i.start += xfer;
        target_start += xfer;
        target_length -= xfer;
    }
#endif
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
    rangemap_range_lookup(f->extentmap, total, closure(h, fs_read_extent, f->fs, b, m, total));
}

// extend here
// This function is terribly broken. *last is never updated, but it should be.
// Leave it as it is for now, but get back to this asap. -lkurusa
static CLOSURE_4_1(fs_write_extent, void, filesystem, buffer, merge, u64 *, rmnode);
static void fs_write_extent(filesystem fs, buffer source, merge m, u64 *last, rmnode node)
{
    range x = node->r;
    u64 target_len = x.end - x.start, source_len = buffer_length(source);
    // u64 block_start = u64_from_pointer(node->val);
    // if this doesn't lie on an alignment bonudary we may need to do a read-modify-write

    /* Will this extent be reallocated? */
    if (source_len > target_len)
        return;

    /* XXX: is this correct? no, it's all fucked */
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

/* create a new extent in the filesystem

   The life an extent depends on a particular allocation of contiguous
   storage space. The extent is tied to this allocated area (nominally
   page size). Only the extent data length may be updated; the file
   offset, block start and allocation size are immutable. As an
   optimization, adjacent extents on the disk could be joined into
   larger extents with only a meta update.

*/
#define MIN_EXTENT_SIZE PAGESIZE

static extent create_extent(fsfile f, range r)
{
    heap h = f->fs->h;
    u64 length = range_span(r);
    u64 alignment = f->fs->alignment;
    u64 alloc_order = find_order(pad(length, alignment));
    u64 alloc_bytes = MAX(1 << alloc_order, MIN_EXTENT_SIZE);

#ifdef BOOT
    /* No writes from the bootloader, please. */
    return INVALID_ADDRESS;
#endif

    tfs_debug("create_extent: length %d, align %d, length %d, alloc_order %d, alloc_bytes %d\n",
              length, alignment, length, alloc_order, alloc_bytes);

    u64 block_start = allocate_u64(f->fs->storage, alloc_bytes);
    if (block_start == u64_from_pointer(INVALID_ADDRESS)) {
        msg_err("out of storage");
        return INVALID_ADDRESS;
    }
    tfs_debug("   block_start 0x%P\n", block_start);

    /* XXX this extend / alloc stuff is getting redone */
    extent ex = allocate_extent(h, r, block_start, alloc_bytes);
    if (ex == INVALID_ADDRESS)
        halt("out of memory\n");
    assert(rangemap_insert(f->extentmap, &ex->node));

    // XXX encode this as an immediate bitstring
    tuple e = timm("length", "%d", length);
    string offset = aprintf(h, "%d", block_start);
    table_set(e, sym(offset), offset);
    string allocated = aprintf(h, "%d", alloc_bytes);
    table_set(e, sym(allocated), allocated);
    symbol offs = intern_u64(r.start);

    tuple extents = soft_create(f->fs, f->md, sym(extents));
    table_set(extents, offs, e);
    log_write_eav(f->fs->tl, extents, offs, e, ignore);
    return ex;
}

void ingest_extent(fsfile f, symbol off, tuple value)
{
    tfs_debug("ingest_extent: f %p, off %b, value %v\n", f, symbol_string(off), value);
    u64 length, file_offset, block_start, allocated;
    parse_int(alloca_wrap(symbol_string(off)), 10, &file_offset);
    parse_int(alloca_wrap(table_find(value, sym(length))), 10, &length);
    parse_int(alloca_wrap(table_find(value, sym(offset))), 10, &block_start);
    parse_int(alloca_wrap(table_find(value, sym(allocated))), 10, &allocated);
    tfs_debug("   file offset %d, length %d, block_start 0x%P, allocated %d\n",
              file_offset, length, block_start, allocated);
#ifndef BOOT
    if (!id_heap_reserve(f->fs->storage, block_start, allocated)) {
        /* soft error... */
        msg_err("unable to reserve storage at start 0x%P, len 0x%P\n",
                block_start, allocated);
    }
#endif
    range r = irange(file_offset, file_offset + length);
    extent ex = allocate_extent(f->fs->h, r, block_start, allocated);
    if (ex == INVALID_ADDRESS)
        halt("out of memory\n");
    assert(rangemap_insert(f->extentmap, &ex->node));
}

boolean set_extent_length(fsfile f, extent ex, u64 length)
{
    tfs_debug("set_extent_length: range %R, allocated %d, new length %d\n",
              ex->node.r, ex->allocated, length);
    if (length > ex->allocated) {
        tfs_debug("failed: new length %d > ex->allocated %d\n",
                  length, ex->allocated);
        return false;
    }

    range r = ex->node.r;
    r.end = ex->node.r.start + length;

    if (rangemap_range_lookup(f->extentmap, r, 0)) {
        tfs_debug("failed: collides with existing extent\n");
        return false;
    }

    tuple extents = table_find(f->md, sym(extents));
    if (!extents) {
        tfs_debug("failed: can't find extents in f->md\n");
        return false;
    }

    symbol offs = intern_u64(r.start);
    tuple extent_tuple = table_find(extents, offs);
    if (!extent_tuple) {
        tfs_debug("failed: can't find extent tuple\n");
        return false;
    }

    /* re-insert in rangemap */
    rangemap_remove_node(f->extentmap, &ex->node);

    if (!rangemap_insert(f->extentmap, &ex->node)) {
        tfs_debug("failed: rangemap_insert failed\n");
        return false;
    }

    /* update length in tuple and log */
    string v = aprintf(f->fs->h, "%d", length);
    table_set(extent_tuple, sym(length), v);
    log_write_eav(f->fs->tl, extents, offs, extent_tuple, ignore);
    log_flush(f->fs->tl);       /* XXX flush each time for now */
    return true;
}

#if 0
/* use more of an extent's allocated area */
static u64 inflate_extent(extent e, u64 n)
{

}

static void truncate_extent(extent e, u64 n)
{

}

static boolean delete_extent(extent e)
{

}
#endif

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

/* Holes over the query range will be filled with extents before later
   being filled with content. However, there are at least two
   differing ways that we can do this function:

   1) Use only single page-sized extents when writing. The reasons are
      two-fold: With our storage allocator, larger, non power-of-2
      sizes will lead to more wasted allocated space, and larger,
      varied allocations leads to more fragmentation of storage space.

      This comes at the cost of meta for every page worth of file
      data. However, extent meta for contiguous areas can be
      aggregated. This is aided by the storage allocator issuing
      allocations in-order when possible. (Note that we can add a
      "release" function to the id heap to complement reserve. This
      would allow us to arbitrarily deallocate blocks - and not
      necessarily in allocation alignments (as with reserve).)

   2) An alternative approach is to break large extent requests into
      allocation sizes that can be filled completely, descending in
      order. This would address the wasted allocated space issue but
      not the fragmentation issue.

   In any case, the attempt is to isolate the logic for mapping a
   write to a series of extents to this function alone. So any
   implementation of the above methods merely takes place in the logic
   below.
*/
/* static */
boolean fill_extents(fsfile f, range q)
{
    u64 curr = q.start;
    rmnode node = rangemap_lookup_at_or_next(f->extentmap, q.start);

    do {
        u64 limit = node ? node->r.start : q.end;
        if (curr < limit) {
            range hole = irange(curr, limit);
            range fill = range_intersection(q, hole);

            /* just doing min-sized extents for now */
            s64 remain = range_span(fill);
            u64 curr = fill.start;

            do {
                /* create_extent will allocate a minimum of pagesize */
                u64 length = MIN(MIN_EXTENT_SIZE, remain);
                range r = irange(curr, length);
                extent ex = create_extent(f, r);
                if (ex == INVALID_ADDRESS) {
                    msg_err("failed to create extent\n");
                    return false;
                }
                curr += length;
                remain -= length;
            } while (remain > 0);
        }

        /* advance past existing extent */
        if (node)
            curr = node->r.end;
        node = rangemap_next_node(f->extentmap, node);
    } while(curr < q.end);

    return true;
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
    /* XXX dealloc rangemap, don't bother cause this gets nuked */
    f->extentmap = allocate_rangemap(fs->h);
#if 0
    tuple extents = table_find(t, sym(extents));
    table_foreach(extents, off, e)
        extent_update(f, off, e);
#endif
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
    rangemap_range_lookup(f->extentmap, irange(offset, offset+len), closure(h, fs_write_extent, f->fs, b, m, last));

    if (*last < (offset + len)) {
        u64 elen = (offset + len) - *last;
        extent ex = create_extent(f, irange(*last, *last + elen)); /* XXX nuke anyway */
        if (ex == INVALID_ADDRESS) {
            msg_err("unable to create extent\n");
            /* XXX do completion with error */
            return;
        }

        status_handler sh = apply(m);
        /* XXX: this should only pop up when writing to virtio,
           check for HOST_BUILD is just a lazy kludge */
#ifndef HOST_BUILD
        if (b->end - *last > SECTOR_SIZE)
            rprintf("trying to write more than what's supported: %d > %d\n",
                    b->end - *last, SECTOR_SIZE);
#endif
        buffer bf = wrap_buffer(transient, buffer_ref(b, *last), b->end - *last);
        apply(fs->w, bf, ex->block_start, sh);
    }
}

fsfile allocate_fsfile(filesystem fs, tuple md)
{
    fsfile f = allocate(fs->h, sizeof(struct fsfile));
    f->extentmap = allocate_rangemap(fs->h);
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
        rangemap_range_lookup(f->extentmap, irange(0, len), closure(h, fs_read_extent, fs, b, m, irange(0, len)));
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
#ifndef BOOT
    fs->storage = create_id_heap(h, 0, infinity, SECTOR_SIZE);
    assert(fs->storage != INVALID_ADDRESS);
    assert(id_heap_reserve(fs->storage, 0, INITIAL_LOG_SIZE));
#endif
    fs->tl = log_create(h, fs, closure(h, log_complete, complete, fs));
}

tuple filesystem_getroot(filesystem fs)
{
    return fs->root;
}
