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

/* extent op

   - determine range of on which to perform operation
   - allocate pages for the operation from backed heap and/or freelist
   - if a write operation
     - and an unaligned start is detected, read the first sector into the buffer
     - same with unaligned end (using the same merge)

   merge completion / direct call if aligned:

   - if a write operation, copy the content of the user buffer into
     the dma buffer, overwriting any read data within the query range
     but leaving data outside the range untouched
   - begin the i/o operation as a one-shot request to block device

   i/o completion:

   - if a read operation, copy data from the dma buffer to the user buffer
   - release dma buffer
   - apply status handler

   It might be more efficient to allow the aligned portion of an
   unaligned request, if any, to proceed without blocking for
   unaligned block reads.
*/


/* I imagine this evolving into a more general page / buffer chace
   interface. We should be able to maintain and recycle dma buffers
   for anything in the system, or at least virtio. These should be
   kept in free lists, and also get passed down to virtqueue so it
   isn't calling physical_from_virtual() with each enqueue.
*/
typedef struct fs_dma_buf {
    void * buf;
    //u64 bus;           /* bus address would go here */
    u64 alloc_size;
    range blocks;        /* in sectors, not bytes */
    u64 block_offset;    /* offset of query start within first block */
    u64 data_length;
} *fs_dma_buf;

static fs_dma_buf fs_allocate_dma_buffer(filesystem fs, extent e, range i)
{
    fs_dma_buf db = allocate(fs->h, sizeof(struct fs_dma_buf));
    if (db == INVALID_ADDRESS)
        return db;
    bytes absolute = e->block_start + i.start - e->node.r.start;
    db->data_length = range_span(i);
    bytes blocksize = fs->blocksize;
    bytes padlength = pad(db->data_length, blocksize);
    u64 start_block = absolute / blocksize; /* XXX need to stash blocksize log2 */
    u64 nblocks = padlength / blocksize;
    db->blocks = irange(start_block, start_block + nblocks);
    db->block_offset = absolute & (blocksize - 1);

    /* determine power-of-2 allocation size */
    u64 alloc_order = find_order(pad(padlength, fs->dma->pagesize));
    db->alloc_size = 1ull << alloc_order;
#ifndef BOOT
    db->buf = allocate(fs->dma, db->alloc_size);
    if (db->buf == INVALID_ADDRESS) {
        msg_err("failed to allocate dma buffer of size %d\n", db->alloc_size);
        deallocate(fs->h, db, sizeof(struct fs_dma_buf));
        return INVALID_ADDRESS;
    }
#else
    db->buf = 0;                /* fixed up by caller for stage2 */
#endif
    return db;
}

static void fs_deallocate_dma_buffer(filesystem fs, fs_dma_buf db)
{
#ifndef BOOT
    deallocate(fs->dma, db->buf, db->alloc_size);
#endif
    deallocate(fs->h, db, sizeof(struct fs_dma_buf));
}

static CLOSURE_4_1(fs_read_extent_complete, void, filesystem, fs_dma_buf, void *, status_handler, status);
static void fs_read_extent_complete(filesystem fs, fs_dma_buf db, void * target, status_handler sh, status s)
{
    tfs_debug("fs_read_extent_complete: status %v\n", s);
    if (s) {
        apply(sh, s);
        return;
    }
#ifndef BOOT
    runtime_memcpy(target, db->buf + db->block_offset, db->data_length);
#endif
    fs_deallocate_dma_buffer(fs, db);
    apply(sh, s);
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
    /*
     * +       i.start--+        +--start_padded      i.end--+      +--end_padded
     * |                |        |                           |      |
     * |                v        v                           v      v
     * v                 <-head->                    <-tail->
     * |---------|------[========|=======....=======|========]------|
     *            <--blocksize-->                    <--blocksize-->
     */

    /* target (user) buffer */
    range i = range_intersection(q, node->r);
    u64 target_offset = i.start - q.start;
    void *target_start = buffer_ref(target, target_offset);

    /* get and init dma buf */
    extent e = (extent)node;
    fs_dma_buf db = fs_allocate_dma_buffer(fs, e, i);
#ifdef BOOT
    /* XXX To skip the copy in stage2, we're banking on the kernel
       being loaded in its entirety, with no partial-block reads
       (except the end, but that's fine). */
    assert(i.start == node->r.start);
    db->buf = target_start;
#endif

    tfs_debug("fs_read_extent: q %R, ex %R, blocks %R, block_offset %d, i %R, "
              "target_offset %d, target_start %p, length %d, blocksize %d\n",
              q, node->r, db->blocks, db->block_offset, i,
              target_offset, target_start, db->data_length, (u64)fs->blocksize);

    status_handler f = apply(m);
    fetch_and_add(&target->end, db->data_length);
    status_handler copy = closure(fs->h, fs_read_extent_complete, fs, db, target_start, f);
    apply(fs->r, db->buf, db->blocks, copy);

    /* XXX hole zero */
}

io_status_handler ignore_io_status;

static CLOSURE_3_1(filesystem_read_complete, void, heap, io_status_handler, buffer, status);
static void filesystem_read_complete(heap h, io_status_handler c, buffer b, status s)
{
    tfs_debug("filesystem_read_complete: status %v, length %d\n", s, buffer_length(b));
    apply(c, s, buffer_length(b));
    unwrap_buffer(h, b);
}

void filesystem_read(filesystem fs, tuple t, void *dest, u64 length, u64 offset, io_status_handler completion)
{
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        tuple e = timm("result", "no such file %t", t);
        apply(completion, e, 0);
        return;
    }

    assert(fs == f->fs);
    heap h = fs->h;
    // b here is permanent - cache?
    buffer b = wrap_buffer(h, dest, length);
    /* b->end will accumulate the read extent lengths; enclose b so
       that filesystem_read_complete can hand the total read length to
       the completion. */
    b->end = b->start;
    merge m = allocate_merge(h, closure(h, filesystem_read_complete, h, completion, b));
    status_handler k = apply(m); // hold a reference until we're sure we've issued everything
    range total = irange(offset, offset+length);
    rangemap_range_lookup(f->extentmap, total, closure(h, fs_read_extent, fs, b, m, total));
    apply(k, STATUS_OK);
}

// should be passing status to the client
static CLOSURE_2_1(read_entire_complete, void, buffer_handler, buffer, status);
static void read_entire_complete(buffer_handler bh, buffer b, status s)
{
    tfs_debug("read_entire_complete: status %v, addr %p, length %d\n",
              s, buffer_ref(b, 0), buffer_length(b));
    apply(bh, b);
}

// cache goes on top
void filesystem_read_entire(filesystem fs, tuple t, heap h, buffer_handler c, status_handler e)
{
    fsfile f;
    if ((f = table_find(fs->files, t))) {
        assert(fs == f->fs);
        // block read is aligning to the next sector
        u64 len = pad(fsfile_get_length(f), fs->blocksize);
        buffer b = allocate_buffer(h, len + 1024);

        // that means a partial read, right?
        status_handler c1 = closure(f->fs->h, read_entire_complete, c, b);
        merge m = allocate_merge(f->fs->h, c1);
        status_handler k = apply(m); // hold a reference until we're sure we've issued everything
        range total = irange(0, len);
        rangemap_range_lookup(f->extentmap, total, closure(h, fs_read_extent, fs, b, m, total));
        apply(k, STATUS_OK);
    } else {
        apply(e, timm("status", "no such file %v\n", t));
    }
}

static void fs_write_extent(filesystem fs, buffer source, merge m, range q, rmnode node)
{
    range i = range_intersection(q, node->r);
    u64 source_offset = i.start - q.start;
    u64 length = range_span(i);
    void * buf = buffer_ref(source, source_offset);
    tfs_debug("fs_write_extent: buf %p, buf len %d, q %R, node %R, i %R, i len %d, start 0x%P\n",
              buf, buffer_length(source), q, node->r, i, length, ((extent)node)->block_start);

    /* XXX This is temporary crap, and we're leaking. Unfinished,
       don't look here. Actually just redo the virtio write as it
       doesn't need to use a buffer and is probably fucked anyway.

       And yes, partial block writes aren't done.
    */
    status_handler sh = apply(m);
    /* XXX wrong, fix next */
    u64 block_start = ((extent)node)->block_start / fs->blocksize;
    range r = irange(block_start, block_start + (pad(length, fs->blocksize) / fs->blocksize));
    tfs_debug("   write from 0x%p to block range %R\n", buf, r);
    apply(fs->w, buf, r, sh);
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

    tfs_debug("create_extent: align %d, offset %d, length %d, alloc_order %d, alloc_bytes %d\n",
              alignment, r.start, length, alloc_order, alloc_bytes);

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

static inline boolean ingest_parse_int(tuple value, symbol s, u64 * i)
{
    buffer b = table_find(value, s);
    /* bark, because these shouldn't really happen */
    if (!b) {
        msg_err("value missing %b\n", symbol_string(s));
        return false;
    }

    /* XXX gross, but we're having issues with too many allocas in stage2 */
    bytes start = b->start;
    parse_int(b, 10, i);
    b->start = start;
    return true;
}

void ingest_extent(fsfile f, symbol off, tuple value)
{
    tfs_debug("ingest_extent: f %p, off %b, value %v\n", f, symbol_string(off), value);
    u64 length, file_offset, block_start, allocated;
    assert(off);
    parse_int(alloca_wrap(symbol_string(off)), 10, &file_offset);
    if (!ingest_parse_int(value, sym(length), &length)) return;
    if (!ingest_parse_int(value, sym(offset), &block_start)) return;
    if (!ingest_parse_int(value, sym(allocated), &allocated)) return;
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

static CLOSURE_4_1(filesystem_write_complete, void, fsfile, tuple, range, io_status_handler, status);
static void filesystem_write_complete(fsfile f, tuple t, range q, io_status_handler completion, status s)
{
    filesystem fs = f->fs;

    if (fsfile_get_length(f) < q.end) {
        /* XXX bother updating resident filelength tuple? */
        fsfile_set_length(f, q.end);
        filesystem_write_eav(fs, t, sym(filelength), value_from_u64(fs->h, q.end));
    }

    apply(completion, s, is_ok(s) ? range_span(q) : 0);
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

void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, io_status_handler completion)
{
    u64 len = buffer_length(b);
    range q = irange(offset, offset + len);
    u64 curr = offset;

    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        apply(completion, timm("no such file"), 0);
        return;
    }

    tfs_debug("filesystem_write: tuple %p, buffer %p, q %R\n", t, b, q);

    rmnode node = rangemap_lookup_at_or_next(f->extentmap, q.start);
    merge m = allocate_merge(fs->h, closure(fs->h, filesystem_write_complete,
                f, t, q, completion));
    status_handler sh = apply(m);

    do {
        /* detect and fill any hole before extent (or to end) */
        u64 limit = node != INVALID_ADDRESS ? node->r.start : q.end;
        if (curr < limit) {
            range hole = irange(curr, limit);
            range fill = range_intersection(q, hole);

            /* XXX optimization: check for a preceding extent and
               inflate if possible */

            /* just doing min-sized extents for now */
            s64 remain = range_span(fill);

            do {
                /* create_extent will allocate a minimum of pagesize */
                u64 length = MIN(MAX_EXTENT_SIZE, remain);
                range r = irange(curr, curr + length);
                extent ex = create_extent(f, r);
                if (ex == INVALID_ADDRESS) {
                    msg_err("failed to create extent\n");
                    goto fail;
                }
                tfs_debug("   writing new extent at %R\n", r);
                fs_write_extent(f->fs, b, m, q, &ex->node);
                curr += length;
                remain -= length;
            } while (remain > 0);

            /* should be at boundary of next extent or end */
            assert(curr == limit);
        }

        if (node != INVALID_ADDRESS) {
            /* overwrite any overlap with extent */
            range i = range_intersection(q, node->r);
            if (range_span(i)) {
                tfs_debug("   updating extent at %R (intersection %R)\n", node->r, i);
                fs_write_extent(f->fs, b, m, q, node);
            }
            curr = i.end;
            node = rangemap_next_node(f->extentmap, node);
        }

    } while(curr < q.end);

    /* apply merge success */
    apply(sh, STATUS_OK);
    return;

  fail:
    /* apply merge fail */
    apply(sh, timm("write failed"));
    return;
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

    if (!children) {
        msg_err("failed for \"%s\": no children found in root tuple\n", fp);
        return FS_STATUS_NOENT;
    }

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

fsfile fsfile_from_node(filesystem fs, tuple n)
{
    return table_find(fs->files, n);
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
                       heap dma,
                       block_read read,
                       block_write write,
                       tuple root,
                       filesystem_complete complete)
{
    tfs_debug("create_filesystem: ...\n");
    filesystem fs = allocate(h, sizeof(struct filesystem));
    ignore_io_status = closure(h, ignore_io_body);
    fs->files = allocate_table(h, identity_key, pointer_equal);
    fs->extents = allocate_table(h, identity_key, pointer_equal);
    fs->dma = dma;
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
