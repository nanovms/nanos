#include <tfs_internal.h>

//#define TFS_DEBUG
//#define TFS_REPORT_SHA256
#if defined(TFS_DEBUG)
#define tfs_debug(x, ...) do {rprintf("TFS: " x, ##__VA_ARGS__);} while(0)
#else
#define tfs_debug(x, ...)
#endif

#ifdef BOOT
#define TFS_READ_ONLY
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

pagecache_volume filesystem_get_pagecache_volume(filesystem fs)
{
    return fs->pv;
}

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

sg_io fsfile_get_reader(fsfile f)
{
    return f->read;
}

sg_io fsfile_get_writer(fsfile f)
{
    return f->write;
}

pagecache_node fsfile_get_cachenode(fsfile f)
{
    return f->cache_node;
}

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

static inline extent allocate_extent(heap h, range file_blocks, range storage_blocks)
{
    extent e = allocate(h, sizeof(struct extent));
    if (e == INVALID_ADDRESS)
        return e;
    rmnode_init(&e->node, file_blocks);
    e->start_block = storage_blocks.start;
    e->allocated = range_span(storage_blocks);
    e->uninited = false;
    return e;
}

boolean filesystem_reserve_storage(filesystem fs, range blocks)
{
    if (fs->w)
        return id_heap_set_area(fs->storage, blocks.start, range_span(blocks), true, true);
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

    range storage_blocks = irangel(start_block, allocated);
    if (!filesystem_reserve_storage(f->fs, storage_blocks)) {
        /* soft error... */
        msg_err("unable to reserve storage blocks %R\n", storage_blocks);
    }
    range r = irangel(file_offset, length);
    extent ex = allocate_extent(f->fs->h, r, storage_blocks);
    if (ex == INVALID_ADDRESS)
        halt("out of memory\n");
    ex->md = value;
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

void zero_blocks(filesystem fs, range blocks, merge m)
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
                 sg_list, sg, range, q, status_handler, complete)
{
    filesystem fs = bound(fs);
    fsfile f = bound(f);
    merge m = allocate_merge(fs->h, complete);
    status_handler k = apply_merge(m);
    tfs_debug("%s: fsfile %p, sg %p, q %R, sh %F\n", __func__, f, sg, q, complete);

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
        apply(io_complete, timm("result", "failed to allocate sg list",
                                "fsstatus", "%d", FS_STATUS_NOMEM), 0);
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
        apply(sh, timm("result", "no such file %t", t,
                       "fsstatus", "%d", FS_STATUS_NOENT));
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
    apply(sh, timm("result", "allocation failure",
                   "fsstatus", "%d", FS_STATUS_NOMEM));
    return;
}

#ifndef TFS_READ_ONLY
fs_status filesystem_write_tuple(filesystem fs, tuple t)
{
    if (log_write(fs->tl, t) && (!fs->temp_log || log_write(fs->temp_log, t)))
        return FS_STATUS_OK;
    else
        return FS_STATUS_NOSPACE;
}

fs_status filesystem_write_eav(filesystem fs, tuple t, symbol a, value v)
{
    if (log_write_eav(fs->tl, t, a, v) &&
            (!fs->temp_log || log_write_eav(fs->temp_log, t, a, v)))
        return FS_STATUS_OK;
    else
        return FS_STATUS_NOSPACE;
}

/* create a new extent in the filesystem

   The life an extent depends on a particular allocation of contiguous
   storage space. The extent is tied to this allocated area (nominally
   page size). Only the extent data length may be updated; the file
   offset, block start and allocation size are immutable. As an
   optimization, adjacent extents on the disk could be joined into
   larger extents with only a meta update.

*/

static fs_status create_extent(filesystem fs, range blocks, boolean uninited, extent *ex)
{
    heap h = fs->h;
    u64 nblocks = MAX(range_span(blocks), MIN_EXTENT_SIZE >> fs->blocksize_order);

    tfs_debug("create_extent: blocks %R, uninited %d, nblocks %ld\n", blocks, uninited, nblocks);

    u64 start_block = allocate_u64((heap)fs->storage, nblocks);
    if (start_block == u64_from_pointer(INVALID_ADDRESS)) {
        /* In lieu of precise error handling up the stack, report here... */
        msg_err("out of storage allocating %ld blocks\n", nblocks);
        return FS_STATUS_NOSPACE;
    }

    range storage_blocks = irangel(start_block, nblocks);
    tfs_debug("   storage_blocks %R\n", storage_blocks);
    *ex = allocate_extent(h, blocks, storage_blocks);
    if (*ex == INVALID_ADDRESS)
        return FS_STATUS_NOMEM;
    (*ex)->md = 0;
    (*ex)->uninited = uninited;

    return FS_STATUS_OK;
}

static void destroy_extent(filesystem fs, extent ex)
{
    deallocate_u64((heap)fs->storage, ex->start_block, ex->allocated);
    deallocate(fs->h, ex, sizeof(*ex));
}

static fs_status add_extent_to_file(fsfile f, extent ex)
{
    heap h = f->fs->h;
    tuple extents;
    symbol a = sym(extents);
    assert(f->md);
    if (!(extents = table_find(f->md, a))) {
        extents = allocate_tuple();
        fs_status s = filesystem_write_eav(f->fs, f->md, a, extents);
        if (s != FS_STATUS_OK) {
            deallocate_tuple(extents);
            return s;
        }
        table_set(f->md, a, extents);
    }

    // XXX encode this as an immediate bitstring
    tuple e = allocate_tuple();
    ex->md = e;
    table_set(e, sym(offset), value_from_u64(h, ex->start_block));
    table_set(e, sym(length), value_from_u64(h, range_span(ex->node.r)));
    table_set(e, sym(allocated), value_from_u64(h, ex->allocated));
    if (ex->uninited)
        table_set(e, sym(uninited), null_value);
    symbol offs = intern_u64(ex->node.r.start);
    fs_status s = filesystem_write_eav(f->fs, extents, offs, e);
    if (s != FS_STATUS_OK) {
        destruct_tuple(e, true);
        return s;
    }
    table_set(extents, offs, e);
    tfs_debug("%s: f %p, reserve %R\n", __func__, f, ex->node.r);
    if (!rangemap_insert(f->extentmap, &ex->node)) {
        rbtree_dump(&f->extentmap->t, RB_INORDER);
        assert(0);
    }
    return FS_STATUS_OK;
}

static void remove_extent_from_file(fsfile f, extent ex)
{
    /* The tuple corresponding to this extent will be destroyed when the
     * filesystem log is compacted. */

    tuple extents = table_find(f->md, sym(extents));
    assert(extents);
    symbol offs = intern_u64(ex->node.r.start);
    filesystem_write_eav(f->fs, extents, offs, 0);
    table_set(extents, offs, 0);
    rangemap_remove_node(f->extentmap, &ex->node);
}

static fs_status add_extents(filesystem fs, range i, rangemap rm)
{
    extent ex;
    fs_status fss;
    while (range_span(i) >= MAX_EXTENT_SIZE) {
        range r = {.start = i.start, .end = i.start + MAX_EXTENT_SIZE};
        fss = create_extent(fs, r, true, &ex);
        if (fss != FS_STATUS_OK)
            return fss;
        assert(rangemap_insert(rm, &ex->node));
        i.start += MAX_EXTENT_SIZE;
    }
    if (range_span(i)) {
        fss = create_extent(fs, i, true, &ex);
        if (fss != FS_STATUS_OK)
            return fss;
        assert(rangemap_insert(rm, &ex->node));
    }
    return FS_STATUS_OK;
}

static u64 write_extent(fsfile f, extent ex, sg_list sg, range blocks, merge m)
{
    filesystem fs = f->fs;
    range i = range_intersection(blocks, ex->node.r);
    u64 data_offset = i.start - ex->node.r.start;
    range r = irangel(ex->start_block + data_offset, range_span(i));

    tfs_debug("   %s: ex %p, uninited %d, sg %p, m %p, blocks %R, write %R\n",
              __func__, ex, ex->uninited, sg, m, blocks, r);

    if (sg) {
        if (ex->uninited) {
            symbol a = sym(uninited);
            fs_status fss = filesystem_write_eav(f->fs, ex->md, a, 0);
            if (fss != FS_STATUS_OK) {
                apply(apply_merge(m), timm("result", "failed to write log",
                    "fsstatus", "%d", fss));
                goto out;
            }
            u64 data_end = i.end - ex->node.r.start;
            u64 extent_end = range_span(ex->node.r);
            if (data_offset > 0)
                zero_blocks(fs, range_add(irange(0, data_offset), ex->start_block), m);
            if (data_end < extent_end)
                zero_blocks(fs, range_add(irange(data_end, extent_end), ex->start_block), m);
            assert(ex->md);
            table_set(ex->md, a, 0);
            ex->uninited = false;
        }
        filesystem_storage_op(fs, sg, m, r, fs->w);
    } else {
        if (!ex->uninited)
            zero_blocks(fs, r, m);
    }
  out:
    return i.end;
}

static fs_status fill_gap(fsfile f, sg_list sg, range blocks, merge m, u64 *edge)
{
    blocks = irangel(blocks.start, MIN(MAX_EXTENT_SIZE >> f->fs->blocksize_order,
                                       range_span(blocks)));
    tfs_debug("   %s: writing new extent blocks %R\n", __func__, blocks);
    extent ex;
    fs_status fss = create_extent(f->fs, blocks, false, &ex);
    if (fss != FS_STATUS_OK)
        return fss;
    fss = add_extent_to_file(f, ex);
    if (fss != FS_STATUS_OK) {
        destroy_extent(f->fs, ex);
        return fss;
    }
    write_extent(f, ex, sg, blocks, m);
    *edge = blocks.end;
    return FS_STATUS_OK;
}

static fs_status update_extent_length(fsfile f, extent ex, u64 new_length)
{
    value v = value_from_u64(f->fs->h, new_length);
    fs_status s = filesystem_write_eav(f->fs, ex->md, sym(length), v);
    if (s != FS_STATUS_OK)
        return s;

    /* TODO cheating; should be reinsert - update rangemap interface? */
    tfs_debug("   %s: was %R\n", __func__, ex->node.r);
    ex->node.r = irangel(ex->node.r.start, new_length);
    tfs_debug("   %s: now %R\n", __func__, ex->node.r);
    assert(ex->md);
    string length = table_find(ex->md, sym(length));
    assert(length);
    deallocate_buffer(length);
    table_set(ex->md, sym(length), v);
    return FS_STATUS_OK;
}

static u64 extend(fsfile f, extent ex, sg_list sg, range blocks, merge m)
{
    u64 free = ex->allocated - range_span(ex->node.r);
    range r = irangel(ex->node.r.end, free);
    range i = range_intersection(r, blocks);
    tfs_debug("   %s: node %R, free 0x%lx (%R), i %R\n", __func__, ex->node.r, free, r, i);
    if (range_span(i) == 0)
        return blocks.start;
    assert(blocks.start >= ex->node.r.end); // XXX temp
    assert(ex->node.r.end <= i.start); // XXX temp
    range z = irange(ex->node.r.end, i.start);
    fs_status s = update_extent_length(f, ex, i.end - ex->node.r.start);
    if (s != FS_STATUS_OK) {
        apply(apply_merge(m), timm("result", "failed to update extent length",
            "fsstatus", "%d", s));
        goto out;
    }
    if (range_span(z) > 0) {
        tfs_debug("      zero %R\n", z);
        write_extent(f, ex, 0, z, m);
    }
    tfs_debug("      write %R\n", i);
    write_extent(f, ex, sg, i, m);
  out:
    return i.end;
}

closure_function(2, 3, void, filesystem_storage_write,
                 filesystem, fs, fsfile, f,
                 sg_list, sg, range, q, status_handler, complete)
{
    filesystem fs = bound(fs);
    fsfile f = bound(f);
    assert(range_span(q) > 0);
    assert((q.start & MASK(fs->blocksize_order)) == 0);
    range blocks = range_rshift_pad(q, fs->blocksize_order);
    tfs_debug("%s: fsfile %p, q %R, blocks %R, sg %p, sg count 0x%lx, complete %F\n", __func__,
              f, q, blocks, sg, sg ? sg->count : 0, complete);
    assert(!sg || sg->count >= range_span(blocks) << fs->blocksize_order);

    merge m = allocate_merge(fs->h, complete);
    status_handler sh = apply_merge(m);

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
        next = rangemap_next_node(f->extentmap, prev);
    }

    status s = STATUS_OK;
    do {
        tfs_debug("   prev %p, next %p\n", prev, next);
        u64 limit = next == INVALID_ADDRESS ? blocks.end : MIN(blocks.end, next->r.start);
        if (sg) {
            if (blocks.start < limit) {
                /* try to extend previous node */
                if (prev != INVALID_ADDRESS && prev->r.end < limit) {
                    tfs_debug("   extent start 0x%lx, limit 0x%lx\n", blocks.start, limit);
                    blocks.start = extend(f, (extent)prev, sg, irange(blocks.start, limit), m);
                }

                /* fill space */
                while (blocks.start < limit) {
                    tfs_debug("   fill start 0x%lx, limit 0x%lx\n", blocks.start, limit);
                    fs_status fss = fill_gap(f, sg, irange(blocks.start, limit), m, &blocks.start);
                    if (fss != FS_STATUS_OK) {
                        s = timm("result", "unable to create extent",
                                 "fsstatus", "%d", fss);
                        goto out;
                    }
                }
            }
        } else {
            /* zero: skip to start of next node */
            blocks.start = limit;
        }

        prev = next;
        if (next != INVALID_ADDRESS) {
            extent ex = (extent)next;
            next = rangemap_next_node(f->extentmap, next);

            if (!sg && range_contains(blocks, ex->node.r)) {
                blocks.start = ex->node.r.end;
                remove_extent_from_file(f, ex);
                destroy_extent(fs, ex);
                prev = INVALID_ADDRESS; /* prev isn't used in zero, but just to be safe */
            } else if (blocks.end > ex->node.r.start) {
                /* TODO: improve write_extent to trim extent on zero */
                blocks.start = write_extent(f, ex, sg, blocks, m);
            }
        }
        assert(blocks.start <= blocks.end); // XXX tmp
    } while (range_span(blocks) > 0);

    if (fsfile_get_length(f) < q.end) {
        tfs_debug("   append; update length to %ld\n", q.end);
        fs_status fss = filesystem_truncate(fs, f, q.end);
        if (fss != FS_STATUS_OK) {
            s = timm("result", "unable to set file length", "fsstatus", "%d",
                fss);
            goto out;
        }
    }
  out:
    apply(sh, s);
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
        apply(io_complete, timm("result", "failed to allocate sg list",
                                "fsstatus", "%d", FS_STATUS_NOMEM), 0);
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

fs_status filesystem_truncate(filesystem fs, fsfile f, u64 len)
{
    value v = value_from_u64(fs->h, len);
    if (v == INVALID_ADDRESS)
        return FS_STATUS_NOMEM;
    symbol l = sym(filelength);
    fs_status s = filesystem_write_eav(fs, f->md, l, v);
    if (s == FS_STATUS_OK) {
        table_set(f->md, l, v);
        fsfile_set_length(f, len);
    }
    return s;
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

static fs_status add_extents_to_file(fsfile f, rangemap rm)
{
    tfs_debug("%s: tuple %p\n", __func__, f->md);
    rangemap_foreach(rm, node) {
        rangemap_remove_node(rm, node);
        fs_status s = add_extent_to_file(f, (extent) node);
        if (s != FS_STATUS_OK)
            return s;
    }
    return FS_STATUS_OK;
}

/* no longer async, but keep completion to match dealloc... */
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

    range blocks = range_rshift_pad(irangel(offset, len), fs->blocksize_order);
    tfs_debug("%s: t %v, blocks %R%s\n", __func__, t, blocks,
              keep_size ? " (keep size)" : "");

    rangemap new_rm = allocate_rangemap(fs->h);
    assert(new_rm != INVALID_ADDRESS);
    fs_status status = FS_STATUS_OK;

    u64 lastedge = blocks.start;
    rmnode curr = rangemap_first_node(f->extentmap);
    while (curr != INVALID_ADDRESS) {
        u64 edge = curr->r.start;
        range i = range_intersection(irange(lastedge, edge), blocks);
        if (range_span(i)) {
            status = add_extents(fs, i, new_rm);
            if (status != FS_STATUS_OK)
                goto done;
        }
        lastedge = curr->r.end;
        curr = rangemap_next_node(f->extentmap, curr);
    }

    /* check for a gap between the last node and blocks.end */
    range i = range_intersection(irange(lastedge, blocks.end), blocks);
    if (range_span(i)) {
        status = add_extents(fs, i, new_rm);
        if (status != FS_STATUS_OK)
            goto done;
    }

    status = add_extents_to_file(f, new_rm);
    if (status != FS_STATUS_OK)
        goto done;
    u64 end = offset + len;
    if (!keep_size && (end > fsfile_get_length(f))) {
        status = filesystem_truncate(fs, f, end);
    }
done:
    deallocate_rangemap(new_rm, status == FS_STATUS_OK ? stack_closure(assert_no_node) :
                        stack_closure(destroy_extent_node, fs));
    apply(completion, f, status);
}

void filesystem_dealloc(filesystem fs, tuple t, long offset, long len,
                        fs_status_handler completion)
{
    fsfile f = table_find(fs->files, t);
    assert(f);
    /* A write with !sg indicates that the pagecache should zero the
       range. The null sg is propagated to the storage write for
       extent removal. */
    filesystem_write_sg(f, 0, irangel(offset, len), closure(fs->h, filesystem_op_complete, f, completion));
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

static fs_status fs_set_dir_entry(filesystem fs, tuple parent, symbol name_sym,
                                  tuple child)
{
    if (child) {
        /* If this is a directory, remove its . and .. directory entries, which
         * must not be written in the log. */
        cleanup_directory(child);
    }
    tuple c = children(parent);
    fs_status s = filesystem_write_eav(fs, c, name_sym, child);
    if (s == FS_STATUS_OK)
        table_set(c, name_sym, child);
    if (child) {
        /* If this is a directory, re-add its . and .. directory entries. */
        fixup_directory(parent, child);
    }
    return s;
}

fs_status do_mkentry(filesystem fs, tuple parent, const char *name, tuple entry,
                     boolean persistent)
{
    symbol name_sym = sym_this(name);
    tuple c = children(parent);
    fs_status s;

    /* XXX rather than ignore, there should be a wakeup on a sync blockq */
    if (persistent) {
        s = filesystem_write_eav(fs, c, name_sym, entry);
    } else {
        table_set(entry, sym(no_encode), null_value);
        s = FS_STATUS_OK;
    }

    if (s == FS_STATUS_OK)
        table_set(c, name_sym, entry);
    fixup_directory(parent, entry);
    return s;
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
                    status = do_mkentry(fs, parent, token, dir, persistent);
                    if (status != FS_STATUS_OK)
                        break;

                    parent = dir;
                    continue;
                }

                msg_err("a path component (\"%s\") is missing\n", token);
                status = FS_STATUS_NOENT;
                break;
            }

            status = do_mkentry(fs, parent, token, entry, persistent);
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

    return filesystem_mkentry(fs, cwd, fp, dir, persistent, true);
}

tuple filesystem_mkdir(filesystem fs, tuple parent, const char *name)
{
    tuple dir = fs_new_entry(fs);
    table_set(dir, sym(children), allocate_tuple());
    if (fs_set_dir_entry(fs, parent, sym_this(name), dir) == FS_STATUS_OK) {
        return dir;
    } else {
        cleanup_directory(dir);
        destruct_tuple(dir, true);
        return 0;
    }
}

fsfile allocate_fsfile(filesystem fs, tuple md);

tuple filesystem_creat(filesystem fs, tuple parent, const char *name)
{
    tuple dir = fs_new_entry(fs);

    /* 'make it a file' by adding an empty extents list */
    table_set(dir, sym(extents), allocate_tuple());

    if (fs_set_dir_entry(fs, parent, sym_this(name), dir) == FS_STATUS_OK) {
        fsfile f = allocate_fsfile(fs, dir);
        fsfile_set_length(f, 0);
    } else {
        destruct_tuple(dir, true);
        return 0;
    }

    return dir;
}

tuple filesystem_symlink(filesystem fs, tuple parent, const char *name,
                         const char *target)
{
    tuple link = fs_new_entry(fs);
    table_set(link, sym(linktarget), buffer_cstring(fs->h, target));
    if (fs_set_dir_entry(fs, parent, sym_this(name), link) == FS_STATUS_OK) {
        return link;
    } else {
        destruct_tuple(link, true);
        return 0;
    }
}

fs_status filesystem_delete(filesystem fs, tuple parent, symbol sym)
{
    return fs_set_dir_entry(fs, parent, sym, 0);
}

fs_status filesystem_rename(filesystem fs, tuple oldparent, symbol oldsym,
                       tuple newparent, const char *newname)
{
    tuple t = lookup(oldparent, oldsym);
    assert(t);
    symbol newchild_sym = sym_this(newname);
    fs_status s = fs_set_dir_entry(fs, newparent, newchild_sym, t);
    if (s == FS_STATUS_OK)
        s = fs_set_dir_entry(fs, oldparent, oldsym, 0);
    return s;
}

fs_status filesystem_exchange(filesystem fs, tuple parent1, symbol sym1,
                         tuple parent2, symbol sym2)
{
    tuple child1;
    child1 = lookup(parent1, sym1);
    assert(child1);
    tuple child2;
    child2 = lookup(parent2, sym2);
    assert(child2);
    fs_status s = fs_set_dir_entry(fs, parent1, sym1, child2);
    if (s == FS_STATUS_OK)
        s = fs_set_dir_entry(fs, parent2, sym2, child1);
    return s;
}

void filesystem_log_rebuild(filesystem fs, log new_tl, status_handler sh)
{
    tfs_debug("%s(%F)\n", __func__, sh);
    cleanup_directory(fs->root);
    if (log_write(new_tl, fs->root)) {
        fs->temp_log = new_tl;
        log_flush(new_tl, sh);
    } else {
        apply(sh, timm("result", "failed to write log"));
    }
    fixup_directory(fs->root, fs->root);
}

void filesystem_log_rebuild_done(filesystem fs, log new_tl)
{
    tfs_debug("%s\n", __func__);
    fs->tl = new_tl;
    fs->temp_log = 0;
}

#endif /* !TFS_READ_ONLY */

fsfile allocate_fsfile(filesystem fs, tuple md)
{
    fsfile f = allocate(fs->h, sizeof(struct fsfile));
    if (f == INVALID_ADDRESS)
        return f;
    sg_io fs_read = closure(fs->h, filesystem_storage_read, fs, f);
    sg_io fs_write =
#ifndef TFS_READ_ONLY
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
#ifndef TFS_READ_ONLY
    if (is_ok(s))
        fixup_directory(fs->root, fs->root);
#endif
    apply(bound(fc), fs, s);
    closure_finish();
}

closure_function(0, 2, void, ignore_io,
                 status, s, bytes, length) {}

const char *filesystem_get_label(filesystem fs)
{
    return fs->label;
}

void filesystem_get_uuid(filesystem fs, u8 *uuid)
{
    runtime_memcpy(uuid, fs->uuid, UUID_LEN);
}

void create_filesystem(heap h,
                       u64 blocksize,
                       u64 size,
                       block_io read,
                       block_io write,
                       const char *label,
                       filesystem_complete complete)
{
    tfs_debug("%s\n", __func__);
    filesystem fs = allocate(h, sizeof(struct filesystem));
    assert(fs != INVALID_ADDRESS);
    fs->h = h;
    if (!ignore_io_status)
        ignore_io_status = closure(h, ignore_io);
    fs->files = allocate_table(h, identity_key, pointer_equal);
    fs->zero_page = pagecache_get_zero_page();
    assert(fs->zero_page);
    fs->r = read;
    fs->root = 0;
    fs->page_order = pagecache_get_page_order();
    fs->size = size;
    assert((blocksize & (blocksize - 1)) == 0);
    fs->blocksize_order = find_order(blocksize);
    fs->pv = pagecache_allocate_volume(size, fs->blocksize_order);
    assert(fs->pv != INVALID_ADDRESS);
#ifndef TFS_READ_ONLY
    fs->w = write;
    fs->storage = create_id_heap(h, h, 0, size >> fs->blocksize_order, 1, false);
    assert(fs->storage != INVALID_ADDRESS);
    fs->temp_log = 0;
#else
    fs->w = 0;
    fs->storage = 0;
#endif
    if (label) {
        int label_len = runtime_strlen(label);
        if (label_len >= sizeof(fs->label))
            label_len = sizeof(fs->label) - 1;
        runtime_memcpy(fs->label, label, label_len);
        fs->label[label_len] = '\0';
    }
    fs->tl = log_create(h, fs, label != 0, closure(h, log_complete, complete, fs));
}

#ifndef BOOT

closure_function(1, 1, void, dealloc_extent_node,
                 filesystem, fs,
                 rmnode, n)
{
    deallocate(bound(fs)->h, n, sizeof(struct extent));
}

void deallocate_fsfile(filesystem fs, fsfile f)
{
    table_set(fs->files, f->md, 0);
    deallocate_rangemap(f->extentmap, stack_closure(dealloc_extent_node, fs));
    pagecache_deallocate_node(f->cache_node);
    deallocate(fs->h, f, sizeof(*f));
}

/* This is only for freeing up a filesystem that is only read; any pending
 * writes are not flushed). */
void destroy_filesystem(filesystem fs)
{
    tfs_debug("%s %p\n", __func__, fs);
    log_destroy(fs->tl);
    pagecache_dealloc_volume(fs->pv);
    if (fs->root) {
        cleanup_directory(fs->root);
        destruct_tuple(fs->root, true);
    }
    table_foreach(fs->files, k, v) {
        (void)k;
        deallocate_fsfile(fs, v);
    }
    deallocate_table(fs->files);
    destroy_id_heap(fs->storage);
    deallocate(fs->h, fs, sizeof(*fs));
}

#endif

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
    return fs->storage->total;
}

u64 fs_freeblocks(filesystem fs)
{
    return (fs->storage->total - fs->storage->allocated);
}
