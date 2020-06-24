#include <tfs_internal.h>

//#define TFS_DEBUG
//#define TFS_REPORT_SHA256
#if defined(TFS_DEBUG)
#define tfs_debug(x, ...) do {rprintf("TFS: " x, ##__VA_ARGS__);} while(0)
#else
#define tfs_debug(x, ...)
#endif

#if defined(TFS_REPORT_SHA256) && !defined(BOOT)
static inline void report_sha256(buffer b)
{
    buffer sha = little_stack_buffer(32);
    sha256(sha, b);
    rprintf("   SHA256: %16lx%16lx%16lx%16lx\n",
            be64toh(*(u64*)buffer_ref(sha, 0)),
            be64toh(*(u64*)buffer_ref(sha, 8)),
            be64toh(*(u64*)buffer_ref(sha, 16)),
            be64toh(*(u64*)buffer_ref(sha, 24)));
}
#else
#define report_sha256(b)
#endif

u64 fsfile_get_length(fsfile f)
{
    return f->length;
}

void fsfile_set_length(fsfile f, u64 length)
{
    f->length = length;
    pagecache_set_node_length(f->cache_node, length);
}

tuple fsfile_get_meta(fsfile f)
{
    return f->md;
}

// XXX change to method get
void filesystem_read_sg(fsfile f, sg_list sg, range q, status_handler completion)
{
    apply(f->read, sg, q, completion);
}

void filesystem_write_sg(fsfile f, sg_list sg, range q, status_handler completion)
{
    apply(f->write, sg, q, completion);
}

static inline timestamp filesystem_get_time(filesystem fs, tuple t, symbol s)
{
    timestamp tim = 0;
    value time_val = table_find(t, s);
    if (time_val) {
        u64_from_value(time_val, &tim);
    }
    return tim;
}

timestamp filesystem_get_atime(filesystem fs, tuple t)
{
    return filesystem_get_time(fs, t, sym(atime));
}

timestamp filesystem_get_mtime(filesystem fs, tuple t)
{
    return filesystem_get_time(fs, t, sym(mtime));
}

static inline void filesystem_set_time(filesystem fs, tuple t, symbol s,
        timestamp tim)
{
    timestamp cur_time = 0;
    value time_val = table_find(t, s);
    if (time_val) {
        u64_from_value(time_val, &cur_time);
    }
    if (tim != cur_time) {
        if (time_val) {
            deallocate_buffer(time_val);
        }
        time_val = value_from_u64(fs->h, tim);
        assert(time_val);
        table_set(t, s, time_val);
    }
}

void filesystem_set_atime(filesystem fs, tuple t, timestamp tim)
{
    filesystem_set_time(fs, t, sym(atime), tim);
}

void filesystem_set_mtime(filesystem fs, tuple t, timestamp tim)
{
    filesystem_set_time(fs, t, sym(mtime), tim);
}

void fixup_directory(tuple parent, tuple dir)
{
    tuple c = children(dir);
    if (!c)
        return;

    table_foreach(c, k, v) {
        (void) k;
        if (tagof(v) == tag_tuple)
            fixup_directory(dir, v);
    }

    table_set(c, sym_this("."), dir);
    table_set(c, sym_this(".."), parent);
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

static inline extent allocate_extent(heap h, range blocks, u64 start_block, u64 allocated)
{
    extent e = allocate(h, sizeof(struct extent));
    if (e == INVALID_ADDRESS)
        return e;
    rmnode_init(&e->node, blocks);
    e->start_block = start_block;
    e->allocated = allocated;
    e->uninited = false;
    return e;
}

boolean filesystem_reserve_storage(filesystem fs, u64 start, u64 length)
{
    if (fs->w)
        return id_heap_set_area(fs->storage, start, length, true, true);
    return true;
}

void ingest_extent(fsfile f, symbol off, tuple value)
{
    tfs_debug("ingest_extent: f %p, off %b, value %v\n", f, symbol_string(off), value);
    u64 length, file_offset, start_block, allocated;
    assert(off);
    assert(parse_int(alloca_wrap(symbol_string(off)), 10, &file_offset));
    assert(ingest_parse_int(value, sym(length), &length));
    assert(ingest_parse_int(value, sym(offset), &start_block));
    assert(ingest_parse_int(value, sym(allocated), &allocated));
    tfs_debug("   file offset %ld, length %ld, start_block 0x%lx, allocated %ld\n",
              file_offset, length, start_block, allocated);

    if (!filesystem_reserve_storage(f->fs, start_block, allocated)) {
        /* soft error... */
        msg_err("unable to reserve storage at start 0x%lx, len 0x%lx\n",
                start_block, allocated);
    }
    range r = irangel(file_offset, length);
    extent ex = allocate_extent(f->fs->h, r, start_block, allocated);
    if (ex == INVALID_ADDRESS)
        halt("out of memory\n");
    if (table_find(value, sym(uninited)))
        ex->uninited = true;
    assert(rangemap_insert(f->extentmap, &ex->node));
}

void filesystem_storage_op(filesystem fs, sg_list sg, merge m, range blocks, block_io op)
{
    tfs_debug("%s: fs %p, sg %p, sg size %ld, blocks %R, op %F\n", __func__,
              fs, sg, sg->count, blocks, op);
    assert(op);
    u64 blocks_remain = range_span(blocks);
    u64 offset = 0;
    do {
        sg_buf sgb = sg_list_head_peek(sg);
        assert(sgb != INVALID_ADDRESS);
        u64 avail = sgb->size - sgb->offset;
        assert((avail & MASK(fs->blocksize_order)) == 0);
        u64 nblocks = MIN(avail >> fs->blocksize_order, blocks_remain);
        if (nblocks > 0) {
            u64 block_offset = blocks.start + offset;
            range q = irangel(block_offset, nblocks);
            assert(range_span(q) + sgb->offset < U64_FROM_BIT(fs->page_order));
            apply(op, sgb->buf + sgb->offset, q, apply_merge(m));
            offset += nblocks;
            blocks_remain -= nblocks;
            u64 n = nblocks << fs->blocksize_order;
            sgb->offset += n;
        }
        if (sgb->offset == sgb->size) {
            assert(sg_list_head_remove(sg) == sgb);
            sg_buf_release(sgb);
        }
    } while (blocks_remain > 0);
}

void zero_blocks(filesystem fs, merge m, range blocks)
{
    int blocks_per_page = U64_FROM_BIT(fs->page_order - fs->blocksize_order);
    tfs_debug("%s: fs %p, blocks %R\n", __func__, fs, blocks);
    while (range_span(blocks) > 0) {
        range r = irangel(blocks.start, MIN(range_span(blocks), blocks_per_page));
        tfs_debug("   zero %R\n", r);
        apply(fs->w, fs->zero_page, r, apply_merge(m));
        blocks.start = r.end;
    }
}

closure_function(4, 1, void, read_extent,
                 filesystem, fs, sg_list, sg, merge, m, range, blocks,
                 rmnode, node)
{
    filesystem fs = bound(fs);
    sg_list sg = bound(sg);
    extent e = (extent)node;
    range i = range_intersection(bound(blocks), node->r);
    u64 e_offset = i.start - node->r.start;
    u64 len = range_span(i);
    range blocks = irangel(e->start_block + e_offset, len);
    tfs_debug("%s: e %p, uninited %d, sg %p m %p blocks %R, i %R, len %ld, blocks %R\n",
              __func__, e, e->uninited, bound(sg), bound(m), bound(blocks), i, len, blocks);
    if (!e->uninited) {
        filesystem_storage_op(fs, sg, bound(m), blocks, fs->r);
    } else {
        sg_zero_fill(sg, range_span(blocks) << fs->blocksize_order);
    }
}

closure_function(3, 1, void, zero_hole,
                 filesystem, fs, sg_list, sg, range, blocks,
                 range, z)
{
    range i = range_intersection(bound(blocks), z);
    u64 length = range_span(i) << bound(fs)->blocksize_order;
    tfs_debug("%s: i %R, length %ld\n", __func__, i, length);
    sg_zero_fill(bound(sg), length);
}

io_status_handler ignore_io_status;

/* whole block reads, file length resolved in cache */
closure_function(2, 3, void, filesystem_storage_read,
                 filesystem, fs, fsfile, f,
                 sg_list, sg, range, q, status_handler, sh)
{
    filesystem fs = bound(fs);
    fsfile f = bound(f);
    merge m = allocate_merge(fs->h, sh);
    status_handler k = apply_merge(m);
    tfs_debug("%s: fsfile %p, sg %p, q %R, sh %F\n", __func__, f, sg, q, sh);

    /* read extent data and zero gaps */
    range blocks = range_rshift_pad(q, fs->blocksize_order);
    rangemap_range_lookup_with_gaps(f->extentmap, blocks,
                                    stack_closure(read_extent, fs, sg, m, blocks),
                                    stack_closure(zero_hole, fs, sg, blocks));
    apply(k, STATUS_OK);
}

/* TODO moving sg up to syscall level means eliminating this extra step */
closure_function(4, 1, void, filesystem_read_complete,
                 void *, dest, u64, limit, io_status_handler, io_complete, sg_list, sg,
                 status, s)
{
    u64 count = 0;
    if (is_ok(s)) {
        count = sg_copy_to_buf_and_release(bound(dest), bound(sg), bound(limit));
    }
    apply(bound(io_complete), s, count);
    closure_finish();
}

void filesystem_read_linear(fsfile f, void *dest, range q, io_status_handler io_complete)
{
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        apply(io_complete, timm("result", "failed to allocate sg list"), 0);
        return;
    }
    filesystem_read_sg(f, sg, q, closure(f->fs->h, filesystem_read_complete,
                                         dest, range_span(q), io_complete, sg));
}

closure_function(5, 1, void, read_entire_complete,
                 sg_list, sg, buffer_handler, bh, buffer, b, u64, length, status_handler, sh,
                 status, s)
{
    buffer b = bound(b);
    tfs_debug("read_entire_complete: status %v, addr %p\n", s, buffer_ref(b, 0));
    if (is_ok(s)) {
        u64 len = sg_copy_to_buf_and_release(buffer_ref(bound(b), 0), bound(sg), bound(length));
        buffer_produce(b, len);
        report_sha256(b);
        apply(bound(bh), b);
    } else {
        deallocate_buffer(b);
        apply(bound(sh), s);
    }
    closure_finish();
}

void filesystem_read_entire(filesystem fs, tuple t, heap bufheap, buffer_handler c, status_handler sh)
{
    tfs_debug("filesystem_read_entire: t %v, bufheap %p, buffer_handler %p, status_handler %p\n",
              t, bufheap, c, sh);
    fsfile f;
    if (!(f = table_find(fs->files, t))) {
        apply(sh, timm("result", "no such file %t", t));
        return;
    }

    u64 length = fsfile_get_length(f);
    buffer b = allocate_buffer(bufheap, pad(length, bufheap->pagesize));
    if (b == INVALID_ADDRESS)
        goto alloc_fail;

    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        deallocate_buffer(b);
        goto alloc_fail;
    }
    filesystem_read_sg(f, sg, irange(0, length),
                      closure(fs->h, read_entire_complete, sg, c, b, length, sh));
    return;
  alloc_fail:
    apply(sh, timm("result", "allocation failure"));
    return;
}

#ifndef BOOT
/* create a new extent in the filesystem

   The life an extent depends on a particular allocation of contiguous
   storage space. The extent is tied to this allocated area (nominally
   page size). Only the extent data length may be updated; the file
   offset, block start and allocation size are immutable. As an
   optimization, adjacent extents on the disk could be joined into
   larger extents with only a meta update.

*/

static extent create_extent(filesystem fs, range blocks, boolean uninited)
{
    // XXX align r start to block and zero-fill
    heap h = fs->h;
    u64 length = range_span(blocks) << fs->blocksize_order;
    u64 alignment = fs->alignment;
    u64 alloc_order = find_order(pad(length, alignment));
    u64 alloc_bytes = MAX(1 << alloc_order, MIN_EXTENT_SIZE);

    tfs_debug("create_extent: align %d, offset %ld, length %ld, alloc_order %ld, alloc_bytes %ld\n",
              alignment, blocks.start, length, alloc_order, alloc_bytes);

    u64 start_block = allocate_u64((heap)fs->storage, alloc_bytes);
    if (start_block == u64_from_pointer(INVALID_ADDRESS)) {
        msg_err("out of storage");
        return INVALID_ADDRESS;
    }
    tfs_debug("   start_block 0x%lx\n", start_block);

    extent ex = allocate_extent(h, blocks, start_block, alloc_bytes);
    if (ex == INVALID_ADDRESS)
        halt("out of memory\n");
    ex->uninited = uninited;

    return ex;
}

static void destroy_extent(filesystem fs, extent ex)
{
    deallocate_u64((heap)fs->storage, ex->start_block, ex->allocated);
    deallocate(fs->h, ex, sizeof(*ex));
}

closure_function(1, 1, void, destroy_extent_node,
                 filesystem, fs,
                 rmnode, n)
{
    destroy_extent(bound(fs), (extent)n);
}

closure_function(0, 1, void, assert_no_node,
                 rmnode, n)
{
    halt("tfs: temporary rangemap not empty on dealloc\n");
}

// wrap in an interface
static tuple soft_create(filesystem fs, tuple t, symbol a, merge m)
{
    tuple v;
    if (!(v = table_find(t, a))) {
        v = allocate_tuple();
        table_set(t, a, v);
        filesystem_write_eav(fs, t, a, v, apply_merge(m));
    }
    return v;
}

static void add_extent_to_file(fsfile f, extent ex, merge m)
{
    heap h = f->fs->h;

    // XXX encode this as an immediate bitstring
    tuple e = allocate_tuple();
    table_set(e, sym(offset), value_from_u64(h, ex->start_block));
    table_set(e, sym(length), value_from_u64(h, range_span(ex->node.r)));
    table_set(e, sym(allocated), value_from_u64(h, ex->allocated));
    if (ex->uninited)
        table_set(e, sym(uninited), null_value());
    assert(rangemap_insert(f->extentmap, &ex->node));
    tuple extents = soft_create(f->fs, f->md, sym(extents), m);
    symbol offs = intern_u64(ex->node.r.start);
    table_set(extents, offs, e);
    filesystem_write_eav(f->fs, extents, offs, e, apply_merge(m));
}

static void remove_extent_from_file(fsfile f, extent ex, merge m)
{
    tuple extents = table_find(f->md, sym(extents));
    assert(extents);
    symbol offs = intern_u64(ex->node.r.start);
    tuple e = table_find(extents, offs);
    assert(e);
    string offset = table_find(e, sym(offset));
    assert(offset);
    deallocate_buffer(offset);
    string length = table_find(e, sym(length));
    assert(length);
    deallocate_buffer(length);
    string allocated = table_find(e, sym(allocated));
    assert(allocated);
    deallocate_buffer(allocated);

    /* This tuple is not deallocated because it is already referenced in the
     * filesystem log and thus present in the dictionary. To avoid this leakage,
     * we need additional functionalities in the filesystem log, e.g.:
     * - being able to remove a dictionary entry without affecting the keys
     * associated to the other (present and future) entries
     * - being able to prune the log (and clean up the dictionary accordingly),
     * to remove any log entries that are no longer relevant in the current
     * status of the filesystem
     */

    /* might suggest we store a special value (invalid / zombie) that
       acts as a terminator for the tuple in the log ... the
       associated dictionary entry would remain allocated, and once
       the log history has expired (when there is such a function) to
       the point where the tuple is no longer referenced, the
       associated entry is retired and the slot becomes free for use
       again
    */

    clear_tuple(e);

    table_set(extents, offs, 0);
    rangemap_remove_node(f->extentmap, &ex->node);
    filesystem_write_eav(f->fs, extents, offs, 0, apply_merge(m));
}

static boolean add_extents(filesystem fs, range i, rangemap rm)
{
    while (range_span(i) >= MAX_EXTENT_SIZE) {
        range r = {.start = i.start, .end = i.start + MAX_EXTENT_SIZE};
        extent ex = create_extent(fs, r, true);
        if (ex == INVALID_ADDRESS) {
            return false;
        }
        assert(rangemap_insert(rm, &ex->node));
        i.start += MAX_EXTENT_SIZE;
    }
    if (range_span(i)) {
        extent ex = create_extent(fs, i, true);
        if (ex == INVALID_ADDRESS) {
            return false;
        }
        assert(rangemap_insert(rm, &ex->node));
    }
    return true;
}

static void add_extents_to_file(fsfile f, rangemap rm, merge m)
{
    tfs_debug("%s: tuple %p\n", __func__, f->md);
    rangemap_foreach(rm, node) {
        rangemap_remove_node(rm, node);
        add_extent_to_file(f, (extent) node, m);
    }
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

static void filesystem_flush_log(filesystem fs)
{
    log_flush(fs->tl, 0);
}

static u64 write_extent(fsfile f, extent ex, sg_list sg, range blocks, merge m)
{
    filesystem fs = f->fs;
    range i = range_intersection(blocks, ex->node.r);
    u64 e_offset = i.start - ex->node.r.start;
    range r = irangel(ex->start_block + e_offset, range_span(i));

    tfs_debug("%s: ex %p, uninited %d, sg %p, m %p, blocks %R, write %R\n",
              __func__, ex, ex->uninited, sg, m, blocks, r);

    if (sg && !ex->uninited)
        filesystem_storage_op(fs, sg, m, r, fs->w);
    else
        zero_blocks(fs, m, r);
    return i.end;
}

// TODO - the zero pad to block boundary on an unaligned write at end
// of file needs to happen in pagecache write

static extent new_extent(fsfile f, range blocks, merge m_meta)
{
    extent ex = create_extent(f->fs, blocks, false);
    if (ex == INVALID_ADDRESS) {
        apply(apply_merge(m_meta), timm("result", "unable to allocate extent of range %R"));
    } else {
        add_extent_to_file(f, ex, m_meta);
    }
    return ex;
}

static u64 fill_gap(fsfile f, sg_list sg, range blocks, merge m_meta, merge m_data)
{
    blocks = irangel(blocks.start, MIN(MAX_EXTENT_SIZE >> f->fs->blocksize_order,
                                       range_span(blocks)));
    tfs_debug("   writing new extent blocks %R\n", blocks);
    extent ex = new_extent(f, blocks, m_meta);
    if (ex == INVALID_ADDRESS)
        return -1ull;
    write_extent(f, ex, sg, blocks, m_data);
    return blocks.end;
}

static void update_extent_length(fsfile f, extent ex, u64 new_length, merge m)
{
    /* cheating; should be reinsert - update interface? */
    ex->node.r = irangel(ex->node.r.start, new_length);
    tuple extents = table_find(f->md, sym(extents));
    assert(extents);
    symbol offs = intern_u64(ex->node.r.start);
    tuple e = table_find(extents, offs);
    assert(e);
    string length = table_find(e, sym(length));
    assert(length);
    deallocate_buffer(length);
    value v = value_from_u64(f->fs->h, new_length);
    table_set(e, sym(length), v);
    filesystem_write_eav(f->fs, e, sym(length), v, apply_merge(m));
}

// integrity on fault: wait for all data writes to post before applying meta update?
static u64 extend(fsfile f, extent ex, sg_list sg, range blocks, u64 limit, merge m_meta, merge m_data)
{
    u64 free = ex->allocated - range_span(ex->node.r);
    range r = irangel(ex->node.r.end, free);
    range i = range_intersection(r, blocks);
    if (range_span(i) == 0)
        return blocks.start;
    assert(blocks.start >= ex->node.r.end); // XXX temp
    update_extent_length(f, ex, i.end, m_meta);
    range z = irange(ex->node.r.end, blocks.start);
    if (range_span(z) > 0) {
        write_extent(f, ex, 0, z, m_data);
    }
    write_extent(f, ex, sg, i, m_data);
    return i.end;
}

        /* cases:

           prev valid (no intersection, maybe extend)

                 qqqq
           nnnn

                qqqqq
           nnnnn

           next valid:

             qqqqqq
           nnnnnn

           qqqqqq
           nnnnnn

           qqqqqq
              nnnnnn

           qqqqqq
                 nnnnnn

           qqqqqq
                    nnnnnn

         
           - if next available:
             find intersection, write, and trim q

           1) next available and contains edge
                 - fs_write_extent, advance and continue

           2) 
                 - try to extend prev
                 - create extent to limit


        */

// XXX we can probably do without this if flush is inevitable / forced
closure_function(2, 1, void, filesystem_write_meta_complete,
                 fsfile, f, status_handler, sh,
                 status, s)
{
    tfs_debug("%s: fsfile %p, status %v\n", __func__, bound(f), s);
    filesystem_flush_log(bound(f)->fs);
    apply(bound(sh), s);
    closure_finish();
}

closure_function(4, 1, void, filesystem_write_data_complete,
                 fsfile, f, range, q, merge, m_meta, status_handler, m_sh,
                 status, s)
{
    fsfile f = bound(f);
    range q = bound(q);
    filesystem fs = f->fs;
    tfs_debug("%s: fsfile %p, range %R, status %v\n", __func__, f, q, s);

    if (!is_ok(s)) {
        /* XXX need to cancel meta update rather than just flush... */
        filesystem_flush_log(fs);
        apply(bound(m_sh), s);
        closure_finish();
        return;
    }

    if (fsfile_get_length(f) < q.end) {
        fsfile_set_length(f, q.end);
        tfs_debug("update length to %ld\n", q.end);
        filesystem_write_eav(fs, f->md, sym(filelength), value_from_u64(fs->h, q.end),
                             apply_merge(bound(m_meta)));
    }

    tfs_debug("flush\n");
    filesystem_flush_log(fs);
    tfs_debug("finish\n");
    apply(bound(m_sh), STATUS_OK);
    closure_finish();
}

/* XXX This needs to additionally block if a log flush is in flight.
   - or strong ordering of writes
*/
closure_function(2, 3, void, filesystem_storage_write,
                 filesystem, fs, fsfile, f,
                 sg_list, sg, range, q, status_handler, complete)
{
    filesystem fs = bound(fs);
    fsfile f = bound(f);
    assert(range_span(q) > 0);
    assert((q.start & MASK(fs->blocksize_order)) == 0);
    range blocks = range_rshift_pad(q, fs->blocksize_order);
    tfs_debug("%s: fsfile %p, q %R, blocks %R, sg %p, complete %F\n", __func__,
              f, q, blocks, sg, complete);

    /* meta merge completion is gated by data merge completion, thus the initial m_meta apply */
    merge m_meta = allocate_merge(fs->h, closure(fs->h, filesystem_write_meta_complete,
                                                 f, complete));
    merge m_data = allocate_merge(fs->h, closure(fs->h, filesystem_write_data_complete,
                                                 f, q, m_meta, apply_merge(m_meta)));

    /* hold data merge open until all extent operations have been initiated */
    status_handler sh = apply_merge(m_data);

    rmnode prev;            /* prior to edge, but could be extended */
    rmnode next;            /* intersecting or succeeding */
    prev = rangemap_lookup_max_lte(f->extentmap, blocks.start);
    if (prev == INVALID_ADDRESS) {
        /* gap */
        next = rangemap_first_node(f->extentmap);
    } else if (prev->r.end > blocks.start) {
        /* intersection */
        next = prev;
        prev = INVALID_ADDRESS;
    } else {
        next = INVALID_ADDRESS;
    }

    do {
        tfs_debug("   prev %p, next %p\n", prev, next);
        /* try to extend prev */
        u64 limit = next == INVALID_ADDRESS ? blocks.end : MIN(blocks.end, next->r.start);
        if (prev != INVALID_ADDRESS && prev->r.end < limit) {
            blocks.start = extend(f, (extent)prev, sg, blocks, limit, m_meta, m_data);
        }

        /* fill space */
        tfs_debug("   fill start %ld, limit %ld\n", blocks.start, limit);
        while (blocks.start < limit) {
            u64 edge = fill_gap(f, sg, irange(blocks.start, limit), m_meta, m_data);
            if (edge == -1ull)
                goto out;         /* error status via meta merge */
            blocks.start = edge;
        }

        if (next != INVALID_ADDRESS) {
            // XXX need extend here too
            if (blocks.start >= next->r.start) {
                blocks.start = write_extent(f, (extent)next, sg, blocks, m_data);
            }
        }
        assert(blocks.start <= blocks.end); // XXX tmp
        if (range_span(blocks) == 0)
            goto out;
        prev = next;
        if (prev != INVALID_ADDRESS)
            next = rangemap_next_node(f->extentmap, prev);
    } while (range_span(blocks) > 0);

    /* XXX do length update here rather than in data completion? */
  out:
    apply(sh, STATUS_OK);       /* error may have already been applied to merge */
}

closure_function(3, 1, void, filesystem_write_complete,
                 sg_list, sg, u64, length, io_status_handler, io_complete,
                 status, s)
{
    deallocate_sg_list(bound(sg));
    apply(bound(io_complete), s, bound(length));
    closure_finish();
}

void filesystem_write_linear(fsfile f, void *src, range q, io_status_handler io_complete)
{
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        apply(io_complete, timm("result", "failed to allocate sg list"), 0);
        return;
    }
    u64 length = range_span(q);
    sg_buf sgb = sg_list_tail_add(sg, length);
    sgb->buf = src;
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = 0;
    filesystem_write_sg(f, sg, q, closure(f->fs->h, filesystem_write_complete,
                                          sg, length, io_complete));
}

boolean filesystem_truncate(filesystem fs, fsfile f, u64 len,
        status_handler completion)
{
    if (fsfile_get_length(f) == len) {
        return true;
    }
    fsfile_set_length(f, len);
    filesystem_write_eav(fs, f->md, sym(filelength), value_from_u64(fs->h, len),
            completion);
    filesystem_flush_log(fs);
    return false;
}

closure_function(3, 1, void, log_flush_completed,
                 filesystem, fs, status_handler, completion, boolean, sync_complete,
                 status, s)
{
    if (is_ok(s) && !bound(sync_complete)) {
        bound(sync_complete) = true;
        pagecache_sync_volume(bound(fs)->pv, (status_handler)closure_self());
    } else {
        apply(bound(completion), s);
        closure_finish();
    }
}

void filesystem_flush(filesystem fs, status_handler completion)
{
    // XXX maybe filesystem_flush_log needs to be redone...doesn't seem right to ignore completion
    log_flush(fs->tl, closure(fs->h, log_flush_completed, fs, completion, false));
}

closure_function(2, 1, void, filesystem_op_complete,
                 fsfile, f, fs_status_handler, sh,
                 status, s)
{
    tfs_debug("%s: status %v\n", __func__, s);
    apply(bound(sh), bound(f), is_ok(s) ? FS_STATUS_OK : FS_STATUS_IOERR);
    closure_finish();
}

void filesystem_alloc(filesystem fs, tuple t, long offset, long len,
        boolean keep_size, fs_status_handler completion)
{
    fsfile f = table_find(fs->files, t);
    assert(f);
    tuple extents = table_find(t, sym(extents));
    if (!extents) {
        apply(completion, f, FS_STATUS_NOENT);
        return;
    }
    range q = irange(offset, offset + len);
    tfs_debug("%s: t %v, q %R%s\n", __func__, t, q,
            keep_size ? " (keep size)" : "");

    rangemap new_rm = allocate_rangemap(fs->h);
    assert(new_rm != INVALID_ADDRESS);
    fs_status status = FS_STATUS_OK;

    u64 lastedge = q.start;
    rmnode curr = rangemap_first_node(f->extentmap);
    while (curr != INVALID_ADDRESS) {
        u64 edge = curr->r.start;
        range i = range_intersection(irange(lastedge, edge), q);
        if (range_span(i)) {
            if (!add_extents(fs, i, new_rm)) {
                status = FS_STATUS_NOSPACE;
                goto error;
            }
        }
        lastedge = curr->r.end;
        curr = rangemap_next_node(f->extentmap, curr);
    }

    /* check for a gap between the last node and q.end */
    range i = range_intersection(irange(lastedge, q.end), q);
    if (range_span(i)) {
        if (!add_extents(fs, i, new_rm)) {
            status = FS_STATUS_NOSPACE;
            goto error;
        }
    }

    merge m = allocate_merge(fs->h,
            closure(fs->h, filesystem_op_complete, f, completion));
    status_handler sh = apply_merge(m);
    add_extents_to_file(f, new_rm, m);
    if (!keep_size && (q.end > fsfile_get_length(f))) {
        fsfile_set_length(f, q.end);
        filesystem_write_eav(fs, t, sym(filelength),
                value_from_u64(fs->h, q.end), apply_merge(m));
    }
    filesystem_flush_log(fs);
    apply(sh, STATUS_OK);
    deallocate_rangemap(new_rm, stack_closure(assert_no_node));
    return;

error:
    deallocate_rangemap(new_rm, stack_closure(destroy_extent_node, fs));
    apply(completion, f, status);
}

void filesystem_dealloc(filesystem fs, tuple t, long offset, long len,
                        fs_status_handler completion)
{
    fsfile f = table_find(fs->files, t);
    assert(f);
    tuple extents = table_find(t, sym(extents));
    if (!extents) {
        apply(completion, f, FS_STATUS_NOENT);
        return;
    }
    range blocks = range_rshift(irangel(offset, len), fs->blocksize_order);
    tfs_debug("%s: t %v, q %R\n", __func__, t, blocks);

    merge m = allocate_merge(fs->h,
            closure(fs->h, filesystem_op_complete, f, completion));
    status_handler sh = apply_merge(m);
    rangemap_foreach(f->extentmap, curr) {
        extent ex = (extent) curr;
        if (range_contains(blocks, curr->r)) {
            remove_extent_from_file(f, ex, m);
            destroy_extent(fs, ex);
            continue;
        }
        range i = range_intersection(curr->r, blocks);
        if (range_span(i))
            write_extent(f, ex, 0, i, m); /* zero */
    }
    filesystem_flush_log(fs);
    apply(sh, STATUS_OK);
}

static tuple fs_new_entry(filesystem fs)
{
    tuple t = allocate_tuple();
    assert(t);
    timestamp tim = now(CLOCK_ID_REALTIME);
    filesystem_set_atime(fs, t, tim);
    filesystem_set_mtime(fs, t, tim);
    return t;
}

static void cleanup_directory(tuple dir)
{
    tuple c = children(dir);
    if (!c) {
        return;
    }
    table_set(c, sym_this("."), 0);
    table_set(c, sym_this(".."), 0);
    table_foreach(c, k, v) {
        (void) k;
        if (tagof(v) == tag_tuple) {
            cleanup_directory(v);
        }
    }
}

static void fs_set_dir_entry(filesystem fs, tuple parent, symbol name_sym,
        tuple child, status_handler sh)
{
    if (child) {
        /* If this is a directory, remove its . and .. directory entries, which
         * must not be written in the log. */
        cleanup_directory(child);
    }
    tuple c = children(parent);
    table_set(c, name_sym, child);
    if (sh) {
        filesystem_write_eav(fs, c, name_sym, child, sh);
        filesystem_flush_log(fs);
    }
    else {
        filesystem_write_eav(fs, c, name_sym, child, ignore_status);
    }
    if (child) {
        /* If this is a directory, re-add its . and .. directory entries. */
        fixup_directory(parent, child);
    }
}

void do_mkentry(filesystem fs, tuple parent, const char *name, tuple entry, boolean persistent)
{
    symbol name_sym = sym_this(name);
    tuple c = children(parent);
    table_set(c, name_sym, entry);

    /* XXX rather than ignore, there should be a wakeup on a sync blockq */
    if (persistent) {
        filesystem_write_eav(fs, c, name_sym, entry, ignore_status);
        filesystem_flush_log(fs);
    }

    fixup_directory(parent, entry);
}

fs_status filesystem_mkentry(filesystem fs, tuple cwd, const char *fp, tuple entry, boolean persistent, boolean recursive)
{
    tuple parent = cwd ? cwd : fs->root;
    assert(children(parent));

    char *token, *rest;
    fs_status status = FS_STATUS_OK;

    int fp_len = runtime_strlen(fp);
    char *fp_copy = allocate(fs->h, fp_len + 1);
    assert(fp_copy != INVALID_ADDRESS);
    runtime_memcpy(fp_copy, fp, fp_len);
    fp_copy[fp_len] = '\0';
    rest = fp_copy;

    /* find the folder we need to mkentry in */
    while ((token = runtime_strtok_r(rest, "/", &rest))) {
        boolean final = *rest == '\0';
        tuple t = lookup(parent, sym_this(token));
        if (!t) {
            if (!final) {
                if (recursive) {
                    /* create intermediate directory */
                    tuple dir = fs_new_entry(fs);
                    table_set(dir, sym(children), allocate_tuple());
                    do_mkentry(fs, parent, token, dir, persistent);

                    parent = dir;
                    continue;
                }

                msg_err("a path component (\"%s\") is missing\n", token);
                status = FS_STATUS_NOENT;
                break;
            }

            do_mkentry(fs, parent, token, entry, persistent);
            break;
        }

        if (final) {
            msg_err("final path component (\"%s\") already exists\n", token);
            status = FS_STATUS_EXIST;
            break;
        }

        if (!children(t)) {
            msg_debug("a path component (\"%s\") is not a folder\n", token);
            status = FS_STATUS_NOTDIR;
            break;
        }

        parent = t;
    }

    deallocate(fs->h, fp_copy, fp_len + 1);
    return status;
}

fs_status filesystem_mkdirpath(filesystem fs, tuple cwd, const char *fp,
        boolean persistent)
{
    tuple dir = fs_new_entry(fs);
    /* 'make it a folder' by attaching a children node to the tuple */
    table_set(dir, sym(children), allocate_tuple());

    return filesystem_mkentry(fs, cwd, fp, dir, persistent, false);
}

tuple filesystem_mkdir(filesystem fs, tuple parent, const char *name,
        status_handler completion)
{
    tuple dir = fs_new_entry(fs);
    table_set(dir, sym(children), allocate_tuple());
    fs_set_dir_entry(fs, parent, sym_this(name), dir, completion);
    return dir;
}

fsfile allocate_fsfile(filesystem fs, tuple md);

tuple filesystem_creat(filesystem fs, tuple parent, const char *name,
        status_handler completion)
{
    tuple dir = fs_new_entry(fs);
    static buffer off = 0;

    if (!off)
        off = wrap_buffer_cstring(fs->h, "0");

    /* 'make it a file' by adding an empty extents list */
    table_set(dir, sym(extents), allocate_tuple());
    table_set(dir, sym(filelength), off);

    fsfile f = allocate_fsfile(fs, dir);
    fsfile_set_length(f, 0);

    fs_set_dir_entry(fs, parent, sym_this(name), dir, completion);
    return dir;
}

tuple filesystem_symlink(filesystem fs, tuple parent, const char *name,
        const char *target, status_handler completion)
{
    tuple link = fs_new_entry(fs);
    table_set(link, sym(linktarget), buffer_cstring(fs->h, target));
    fs_set_dir_entry(fs, parent, sym_this(name), link, completion);
    return link;
}

void filesystem_delete(filesystem fs, tuple parent, symbol sym,
        status_handler completion)
{
    fs_set_dir_entry(fs, parent, sym, 0, completion);
}

void filesystem_rename(filesystem fs, tuple oldparent, symbol oldsym,
        tuple newparent, const char *newname, status_handler completion)
{
    tuple t = lookup(oldparent, oldsym);
    assert(t);
    symbol newchild_sym = sym_this(newname);
    fs_set_dir_entry(fs, oldparent, oldsym, 0, 0);
    fs_set_dir_entry(fs, newparent, newchild_sym, t, completion);
}

void filesystem_exchange(filesystem fs, tuple parent1, symbol sym1,
        tuple parent2, symbol sym2, status_handler completion)
{
    tuple child1;
    child1 = lookup(parent1, sym1);
    assert(child1);
    tuple child2;
    child2 = lookup(parent2, sym2);
    assert(child2);
    fs_set_dir_entry(fs, parent1, sym1, child2, 0);
    fs_set_dir_entry(fs, parent2, sym2, child1, completion);
}

#endif /* !BOOT */

fsfile allocate_fsfile(filesystem fs, tuple md)
{
    fsfile f = allocate(fs->h, sizeof(struct fsfile));
    if (f == INVALID_ADDRESS)
        return f;
    sg_io fs_read = closure(fs->h, filesystem_storage_read, fs, f);
    sg_io fs_write =
#ifndef BOOT
        closure(fs->h, filesystem_storage_write, fs, f);
#else
    0;
#endif
    pagecache_node pn = pagecache_allocate_node(fs->pv, fs_read, fs_write);

    if (pn == INVALID_ADDRESS) {
        deallocate(fs->h, f, sizeof(struct fsfile));
        return INVALID_ADDRESS;
    }
    f->extentmap = allocate_rangemap(fs->h);
    f->fs = fs;
    f->md = md;
    f->length = 0;
    table_set(fs->files, f->md, f);
    f->cache_node = pn;
    f->read = pagecache_node_get_reader(pn);
    f->write = pagecache_node_get_writer(pn);
    return f;
}

fsfile fsfile_from_node(filesystem fs, tuple n)
{
    return table_find(fs->files, n);
}

closure_function(2, 1, void, log_complete,
                 filesystem_complete, fc, filesystem, fs,
                 status, s)
{
    tfs_debug("%s: complete %p, fs %p, status %v\n", __func__, bound(fc), bound(fs), s);
    filesystem fs = bound(fs);
#ifndef BOOT // XXX
    fixup_directory(fs->root, fs->root);
#endif
    apply(bound(fc), fs, s);
    closure_finish();
}

closure_function(0, 2, void, ignore_io,
                 status, s, bytes, length) {}

void create_filesystem(heap h,
                       u64 alignment,
                       u64 blocksize,
                       u64 size,
                       block_io read,
                       block_io write,
                       pagecache pc,
                       tuple root,
                       boolean initialize,
                       filesystem_complete complete)
{
    tfs_debug("%s\n", __func__);
    filesystem fs = allocate(h, sizeof(struct filesystem));
    assert(fs != INVALID_ADDRESS);
    fs->h = h;
    ignore_io_status = closure(h, ignore_io);
    fs->files = allocate_table(h, identity_key, pointer_equal);
    fs->extents = allocate_table(h, identity_key, pointer_equal);
    fs->zero_page = pagecache_get_zero_page(pc);
    assert(fs->zero_page);
    fs->r = read;
    fs->pc = pc;
    fs->root = root;
    fs->alignment = alignment;
    fs->page_order = pagecache_get_page_order(pc);
    fs->size = size;
    assert((blocksize & (blocksize - 1)) == 0); /* power of 2 */
    fs->blocksize_order = find_order(blocksize);
    fs->pv = pagecache_allocate_volume(pc, size, fs->blocksize_order);
    assert(fs->pv != INVALID_ADDRESS);
#ifndef BOOT
    fs->w = write;
    fs->storage = create_id_heap(h, h, 0, size, fs_blocksize(fs));
    assert(fs->storage != INVALID_ADDRESS);
#else
    fs->w = 0;
    fs->storage = 0;
#endif
    fs->tl = log_create(h, fs, initialize, closure(h, log_complete, complete, fs));
}

tuple filesystem_getroot(filesystem fs)
{
    return fs->root;
}

u64 fs_blocksize(filesystem fs)
{
    return U64_FROM_BIT(fs->blocksize_order);
}

u64 fs_totalblocks(filesystem fs)
{
    return fs->storage->total >> fs->blocksize_order;
}

u64 fs_freeblocks(filesystem fs)
{
    return (fs->storage->total - fs->storage->allocated) >> fs->blocksize_order;
}
