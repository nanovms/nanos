#include <tfs_internal.h>

//#define TFS_DEBUG
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

static void filesystem_flush_log(filesystem fs)
{
    log_flush(fs->tl);
}

/* XXX don't ignore status
       set fs dirty bit and flush at end of fs operation
*/
void filesystem_write_tuple(filesystem fs, tuple t, status_handler sh)
{
    log_write(fs->tl, t, sh);
}

void filesystem_write_eav(filesystem fs, tuple t, symbol a, value v, status_handler sh)
{
    log_write_eav(fs->tl, t, a, v, sh);
}

/* This can evolve into / be replaced by a more general page / buffer
   chace interface. We should be able to maintain and recycle dma
   buffers for anything in the system, or at least virtio. These
   could be kept in free lists, and also get passed down to virtqueue
   so it isn't calling physical_from_virtual() with each enqueue.
*/
typedef struct fs_dma_buf {
    void * buf;
    //u64 bus;           /* bus address would go here */
    u64 alloc_size;
    range blocks;        /* in sectors, not bytes */
    u64 start_offset;    /* offset of query start within first block */
    u64 data_length;
} *fs_dma_buf;

static fs_dma_buf fs_allocate_dma_buffer(filesystem fs, extent e, range i)
{
    fs_dma_buf db = allocate(fs->h, sizeof(struct fs_dma_buf));
    if (db == INVALID_ADDRESS)
        return db;
    bytes blocksize = fs->blocksize;
    bytes absolute = e->block_start + i.start - e->node.r.start;
    db->start_offset = absolute & (blocksize - 1);
    db->data_length = range_span(i);
    bytes padlength = pad(db->start_offset + db->data_length, blocksize);
    u64 start_block = absolute / blocksize; /* XXX need to stash blocksize log2 */
    u64 nblocks = padlength / blocksize;
    db->blocks = irange(start_block, start_block + nblocks);

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
    tfs_debug("fs_read_extent_complete: dma buf 0x%p, start_offset %d, length %d, target 0x%p, status %v\n",
              db->buf, db->start_offset, db->data_length, target, s);
#ifndef BOOT
    if (is_ok(s))
        runtime_memcpy(target, db->buf + db->start_offset, db->data_length);
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
    range i = range_intersection(q, node->r);
    u64 target_offset = i.start - q.start;
    void *target_start = buffer_ref(target, target_offset);

    /* get and init dma buf */
    extent e = (extent)node;
    fs_dma_buf db = fs_allocate_dma_buffer(fs, e, i);
    if (db == INVALID_ADDRESS) {
        msg_err("failed; unable to allocate dma buffer, i span %d bytes\n", range_span(i));
        return;
    }
#ifdef BOOT
    /* XXX To skip the copy in stage2, we're banking on the kernel
       being loaded in its entirety, with no partial-block reads
       (except the end, but that's fine). */
    assert(i.start == node->r.start);
    db->buf = target_start;
#endif

    tfs_debug("fs_read_extent: q %R, ex %R, blocks %R, start_offset %d, i %R, "
              "target_offset %d, target_start %p, length %d, blocksize %d\n",
              q, node->r, db->blocks, db->start_offset, i,
              target_offset, target_start, db->data_length, (u64)fs->blocksize);

    status_handler f = apply(m);
    fetch_and_add(&target->end, db->data_length);
    status_handler copy = closure(fs->h, fs_read_extent_complete, fs, db, target_start, f);
    apply(fs->r, db->buf, db->blocks, copy);
}

static CLOSURE_3_1(fs_zero_hole, void, filesystem, buffer, range, range);
void fs_zero_hole(filesystem fs, buffer target, range q, range z)
{
    range i = range_intersection(q, z);
    u64 target_offset = i.start - q.start;
    void * target_start = buffer_ref(target, target_offset);
    u64 length = range_span(i);
    tfs_debug("fs_zero_hole: i %R, target_start %p, length %d\n", i, target_start, length);
    runtime_memset(target_start, 0, length);
    fetch_and_add(&target->end, length);
}

io_status_handler ignore_io_status;

static CLOSURE_3_1(filesystem_read_complete, void, heap, io_status_handler, buffer, status);
static void filesystem_read_complete(heap h, io_status_handler c, buffer b, status s)
{
    tfs_debug("filesystem_read_complete: status %v, length %d\n", s, buffer_length(b));
    apply(c, s, is_ok(s) ? buffer_length(b) : 0);
    unwrap_buffer(h, b);
}

static void filesystem_read_internal(filesystem fs, fsfile f, buffer b, u64 length, u64 offset,
                                     status_handler sh)
{
    merge m = allocate_merge(fs->h, sh);
    status_handler k = apply(m); // hold a reference until we're sure we've issued everything
    u64 file_length = fsfile_get_length(f);
    u64 actual_length = MIN(length, file_length - offset);
    if (offset >= file_length || actual_length == 0) { /* XXX check */
        apply(k, STATUS_OK);
        return;
    }
    range total = irange(offset, offset + actual_length);

    /* read extent data */
    rangemap_range_lookup(f->extentmap, total, closure(fs->h, fs_read_extent, fs, b, m, total));

    /* zero areas corresponding to file holes */
    rangemap_range_find_gaps(f->extentmap, total, closure(fs->h, fs_zero_hole, fs, b, total));

    apply(k, STATUS_OK);
}

void filesystem_read(filesystem fs, tuple t, void *dest, u64 length, u64 offset,
                     io_status_handler io_complete)
{
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        tuple e = timm("result", "no such file %t", t);
        apply(io_complete, e, 0);
        return;
    }

    /* b->end will accumulate the read extent and hole lengths, thus
       effectively handing a read length to the completion. */
    buffer b = wrap_buffer(fs->h, dest, length);
    b->end = b->start;
    status_handler sh = closure(fs->h, filesystem_read_complete, fs->h, io_complete, b);
    filesystem_read_internal(fs, f, b, length, offset, sh);
}

static CLOSURE_3_1(read_entire_complete, void, buffer_handler, buffer, status_handler, status);
static void read_entire_complete(buffer_handler bh, buffer b, status_handler sh, status s)
{
    tfs_debug("read_entire_complete: status %v, addr %p, length %d\n",
              s, buffer_ref(b, 0), buffer_length(b));
    if (is_ok(s)) {
        apply(bh, b);
    } else {
        deallocate_buffer(b);
        apply(sh, s);
    }
}

void filesystem_read_entire(filesystem fs, tuple t, heap bufheap, buffer_handler c, status_handler sh)
{
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        tuple e = timm("result", "no such file %t", t);
        apply(sh, e);
        return;
    }

    u64 length = pad(fsfile_get_length(f), fs->blocksize);
    buffer b = allocate_buffer(bufheap, pad(length, bufheap->pagesize));
    filesystem_read_internal(fs, f, b, length, 0, closure(fs->h, read_entire_complete, c, b, sh));
}

/*
 * +       i.start--+        +--start_padded      i.end--+      +--end_padded
 * |                |        |                           |      |
 * |                v        v                           v      v
 * v                 <-head->                    <-tail->
 * |---------|------[========|=======....=======|========]------|
 *            <--blocksize-->                    <--blocksize-->
 */

static CLOSURE_3_1(fs_write_extent_complete, void, filesystem, fs_dma_buf, status_handler, status);
static void fs_write_extent_complete(filesystem fs, fs_dma_buf db, status_handler sh, status s)
{
    tfs_debug("fs_write_extent_complete: status %v\n", s);
    fs_deallocate_dma_buffer(fs, db);
    apply(sh, s);
}

/* In theory these writes could be split up, allowing the aligned
   write to commence without waiting for head/tail reads. Not clear if
   it matters. */
static CLOSURE_4_1(fs_write_extent_aligned, void, filesystem, fs_dma_buf, void *, status_handler, status);
static void fs_write_extent_aligned(filesystem fs, fs_dma_buf db, void * source, status_handler sh, status s)
{
    if (!is_ok(s)) {
        msg_err("read failed: %v\n", s);
        apply(sh, s);
        return;
    }
    void * dest = db->buf + db->start_offset;
    tfs_debug("fs_write_extent_complete: copy from 0x%p to 0x%p, len %d\n", source, dest, db->data_length);
    runtime_memcpy(dest, source, db->data_length);
    tfs_debug("   write from 0x%p to block range %R\n", db->buf, db->blocks);
    status_handler complete = closure(fs->h, fs_write_extent_complete, fs, db, sh);
    apply(fs->w, db->buf, db->blocks, complete);
}

static void fs_write_extent_read_block(filesystem fs, fs_dma_buf db, u64 offset_block, status_handler sh)
{
    u64 absolute_block = db->blocks.start + offset_block;
    void * buf = db->buf + (offset_block * fs->blocksize);
    range r = irange(absolute_block, absolute_block + 1);
    tfs_debug("fs_write_extent_read_block: sector range %R, buf %p\n", r, buf);
    apply(fs->r, buf, r, sh);
}

static void fs_write_extent(filesystem fs, buffer source, merge m, range q, rmnode node)
{
    range i = range_intersection(q, node->r);
    u64 source_offset = i.start - q.start;
    void * source_start = buffer_ref(source, source_offset);

#ifdef BOOT
    msg_err("File writing unsupported in stage2.\n");
    return;
#endif

    extent e = (extent)node;
    fs_dma_buf db = fs_allocate_dma_buffer(fs, e, i);
    if (db == INVALID_ADDRESS) {
        msg_err("failed; unable to allocate dma buffer, i span %d bytes\n", range_span(i));
        return;
    }

    tfs_debug("fs_write_extent: source (+off) %p, buf len %d, q %R, node %R,\n"
              "                 i %R, i len %d, ext start 0x%P, dma buf %p\n",
              source_start, buffer_length(source), q, node->r, i, range_span(i),
              ((extent)node)->block_start, db->buf);

    /* Check for unaligned block writes and initiate reads for them.
       This would all be obviated by a diskcache. */
    boolean tail_rmw = ((db->data_length + db->start_offset) & (fs->blocksize - 1)) != 0 &&
        (i.end != node->r.end); /* no need to rmw tail if we're at the end of the extent */
    boolean plural = range_span(db->blocks) > 1;

    /* just do a head op if one block and either head or tail are misaligned */
    boolean head = db->start_offset != 0 || (tail_rmw && !plural);
    boolean tail = tail_rmw && plural;

    status_handler sh = apply(m);
    if (head || tail) {
        merge m2 = allocate_merge(fs->h, closure(fs->h, fs_write_extent_aligned,
                                                 fs, db, source_start, sh));
        status_handler k = apply(m2);
        if (head)
            fs_write_extent_read_block(fs, db, 0, apply(m2));
        if (tail)
            fs_write_extent_read_block(fs, db, range_span(db->blocks) - 1, apply(m2));
        apply(k, STATUS_OK);
        return;
    }

    /* everything is aligned, so proceed to the write */
    fs_write_extent_aligned(fs, db, source_start, sh, STATUS_OK);
}

// wrap in an interface
static tuple soft_create(filesystem fs, tuple t, symbol a, merge m)
{
    tuple v;
    if (!(v = table_find(t, a))) {
        v = allocate_tuple();
        table_set(t, a, v);
        filesystem_write_eav(fs, t, a, v, apply(m));
    }
    return v;
}

/* create a new extent in the filesystem

   The life of an extent depends on a particular allocation of
   contiguous storage space. The extent is tied to this allocated area
   (nominally page size). Only the extent data length may be updated;
   the file offset, block start and allocation size are immutable. As
   an optimization, adjacent extents on the disk could be joined into
   larger extents with only a meta update.

*/

static extent create_extent(fsfile f, range r, merge m)
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

    tuple extents = soft_create(f->fs, f->md, sym(extents), m);
    table_set(extents, offs, e);
    filesystem_write_eav(f->fs, extents, offs, e, apply(m));
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
    boolean retval = parse_int(b, 10, i);
    b->start = start;
    return retval;
}

void ingest_extent(fsfile f, symbol off, tuple value)
{
    tfs_debug("ingest_extent: f %p, off %b, value %v\n", f, symbol_string(off), value);
    u64 length, file_offset, block_start, allocated;
    assert(off);
    assert(parse_int(alloca_wrap(symbol_string(off)), 10, &file_offset));
    assert(ingest_parse_int(value, sym(length), &length));
    assert(ingest_parse_int(value, sym(offset), &block_start));
    assert(ingest_parse_int(value, sym(allocated), &allocated));
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

boolean set_extent_length(fsfile f, extent ex, u64 length, merge m)
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
    filesystem_write_eav(f->fs, extents, offs, extent_tuple, apply(m));
    return true;
}

static CLOSURE_2_1(filesystem_write_meta_complete, void, range, io_status_handler, status);
static void filesystem_write_meta_complete(range q, io_status_handler ish, status s)
{
    u64 n = range_span(q);
    tfs_debug("%s: range %R, bytes %d, status %v\n", __func__, q, n, s);
    apply(ish, s, is_ok(s) ? n : 0);
}

static CLOSURE_5_1(filesystem_write_data_complete, void, fsfile, tuple, range, merge, status_handler, status);
static void filesystem_write_data_complete(fsfile f, tuple t, range q, merge m_meta, status_handler m_sh,
                                           status s)
{
    filesystem fs = f->fs;
    tfs_debug("%s: range %R, status %v\n", __func__, q, s);

    if (!is_ok(s)) {
        /* XXX need to cancel meta update rather than just flush... */
        filesystem_flush_log(fs);
        apply(m_sh, s);
        return;
    }

    if (fsfile_get_length(f) < q.end) {
        /* XXX bother updating resident filelength tuple? */
        fsfile_set_length(f, q.end);
        filesystem_write_eav(fs, t, sym(filelength), value_from_u64(fs->h, q.end), apply(m_meta));
    }

    filesystem_flush_log(fs);
    apply(m_sh, STATUS_OK);
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

/* XXX This needs to additionally block if a log flush is in flight. */
void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, io_status_handler ish)
{
    u64 len = buffer_length(b);
    range q = irange(offset, offset + len);
    u64 curr = offset;

    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        apply(ish, timm("result", "no such file"), 0);
        return;
    }

    tfs_debug("filesystem_write: tuple %p, buffer %p, q %R\n", t, b, q);

    rmnode node = rangemap_lookup_at_or_next(f->extentmap, q.start);

    /* meta merge completion is gated by data merge completion, thus the initial m_meta apply */
    merge m_meta = allocate_merge(fs->h, closure(fs->h, filesystem_write_meta_complete, q, ish));
    merge m_data = allocate_merge(fs->h, closure(fs->h, filesystem_write_data_complete,
                                                 f, t, q, m_meta, apply(m_meta)));

    /* hold data merge open until all extent operations have been initiated */
    status_handler sh = apply(m_data);
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
#ifdef HOST_BUILD
                u64 length = remain; /* mkfs: one large extent */
#else
                u64 length = MIN(MAX_EXTENT_SIZE, remain);
#endif
                range r = irange(curr, curr + length);
                extent ex = create_extent(f, r, m_meta);
                if (ex == INVALID_ADDRESS) {
                    msg_err("failed to create extent\n");
                    goto fail;
                }
                tfs_debug("   writing new extent %R\n", r);
                fs_write_extent(f->fs, b, m_data, q, &ex->node);
                curr += length;
                remain -= length;
            } while (remain > 0);
        }

        if (node != INVALID_ADDRESS) {
            /* overwrite any overlap with extent */
            range i = range_intersection(q, node->r);
            if (range_span(i)) {
                tfs_debug("   updating extent at %R (intersection %R)\n", node->r, i);
                fs_write_extent(f->fs, b, m_data, q, node);
            }
            curr = node->r.end;
            node = rangemap_next_node(f->extentmap, node);
        }
    } while(curr < q.end);

    /* all data I/O has been queued */
    apply(sh, STATUS_OK);
    return;

  fail:
    /* apply merge fail */
    apply(sh, timm("result", "write failed"));
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

#if 0
void link(tuple dir, fsfile f, buffer name)
{
    filesystem_write_eav(f->fs, soft_create(f->fs, dir, sym(children)),
                         intern(name), f->md);
    filesystem_flush_log(f->fs);
}
#endif

/* XXX these will all need to take completions - some ironing out of
   interface is in order */
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

    /* XXX this shouldn't be ignore - extend this when we add completion to interface */
    filesystem_write_eav(fs, children, basename_sym, entry, ignore_status);
    msg_debug("written!\n");
    filesystem_flush_log(fs);
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
