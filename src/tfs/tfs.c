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
    rprintf("   SHA256: %016lx%016lx%016lx%016lx\n",
            be64toh(*(u64*)buffer_ref(sha, 0)),
            be64toh(*(u64*)buffer_ref(sha, 8)),
            be64toh(*(u64*)buffer_ref(sha, 16)),
            be64toh(*(u64*)buffer_ref(sha, 24)));
}
#else
#define report_sha256(b)
#endif

const char *string_from_fs_status(fs_status s)
{
    switch (s) {
    case FS_STATUS_NOSPACE:
        return "no space";
    case FS_STATUS_IOERR:
        return "I/O error";
    case FS_STATUS_NOENT:
        return "no entry";
    case FS_STATUS_EXIST:
        return "file exists";
    case FS_STATUS_NOTDIR:
        return "not a directory";
    case FS_STATUS_NOMEM:
        return "out of memory";
    case FS_STATUS_LINKLOOP:
        return "maximum link hops reached";
    default:
        return "unknown error";
    }
}

static tuple fs_tuple_from_inode(filesystem fs, inode n)
{
    tuple t = pointer_from_u64(n);
    return table_find(fs->files, t) ? t : 0;
}

filesystem fsfile_get_fs(fsfile f)
{
    return f->fs;
}

pagecache_volume filesystem_get_pagecache_volume(filesystem fs)
{
    return fs->pv;
}

u64 fsfile_get_length(fsfile f)
{
    return f->length;
}
KLIB_EXPORT(fsfile_get_length);

void fsfile_set_length(fsfile f, u64 length)
{
    f->length = length;
    pagecache_set_node_length(f->cache_node, length);
}

u64 fsfile_get_blocks(fsfile f)
{
    u64 blocks = 0;
    rangemap_foreach(f->extentmap, n) {
        blocks += range_span(n->r);
    }
    return blocks;
}

sg_io fsfile_get_reader(fsfile f)
{
    return f->read;
}

sg_io fsfile_get_writer(fsfile f)
{
    return f->write;
}
KLIB_EXPORT(fsfile_get_writer);

pagecache_node fsfile_get_cachenode(fsfile f)
{
    return f->cache_node;
}

void fsfile_reserve(fsfile f)
{
    refcount_reserve(&f->refcount);
}

void fsfile_release(fsfile f)
{
    refcount_release(&f->refcount);
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
    get_u64(t, s, &tim);
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
    value time_val = get_number(t, s);
    if (time_val) {
        u64_from_value(time_val, &cur_time);
    }
    if (tim != cur_time) {
        if (time_val) {
            deallocate_value(time_val);
        }
        time_val = value_from_u64(fs->h, tim);
        assert(time_val);
        set(t, s, time_val);
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

void fixup_directory(tuple parent, tuple dir);

closure_function(1, 2, boolean, fixup_directory_each,
                 tuple, dir,
                 value, s, value, v)
{
    if (is_tuple(v))
        fixup_directory(bound(dir), v);
    return true;
}

void fixup_directory(tuple parent, tuple dir)
{
    tuple c = children(dir);
    if (!c)
        return;

    iterate(c, stack_closure(fixup_directory_each, dir));
    set(c, sym_this("."), dir);
    set(c, sym_this(".."), parent);
}

static inline boolean ingest_parse_int(tuple value, symbol s, u64 * i)
{
    buffer b = get(value, s);
    // XXX type
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
    e->uninited = 0;
    return e;
}

#ifdef KERNEL
#define uninited_lock(u) spin_lock(&(u)->lock);
#define uninited_unlock(u) spin_unlock(&(u)->lock);
#else
#define uninited_lock(u)
#define uninited_unlock(u)
#endif

u64 filesystem_allocate_storage(filesystem fs, u64 nblocks)
{
    if (fs->w)
        return allocate_u64((heap)fs->storage, nblocks);
    return INVALID_PHYSICAL;
}

boolean filesystem_reserve_storage(filesystem fs, range blocks)
{
    if (fs->w)
        return id_heap_set_area(fs->storage, blocks.start, range_span(blocks), true, true);
    return true;
}

boolean filesystem_free_storage(filesystem fs, range blocks)
{
    if (fs->w)
        return id_heap_set_area(fs->storage, blocks.start, range_span(blocks), true, false);
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
    if (get(value, sym(uninited)))
        ex->uninited = INVALID_ADDRESS;
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

/* called with uninited lock held */
static void queue_uninited_op(filesystem fs, uninited u, sg_list sg, range blocks,
                              status_handler complete, block_io op)
{
    struct uninited_queued_op uqo;
    uqo.sg = sg;
    uqo.m = allocate_merge(fs->h, complete);
    if (uqo.m == INVALID_ADDRESS)
        goto alloc_fail;
    uqo.blocks = blocks;
    uqo.op = op;
    if (!buffer_append(u->op_queue, &uqo, sizeof(uqo))) {
        complete = apply_merge(uqo.m);
        goto alloc_fail;
    }
    return;
  alloc_fail:
    apply(complete, timm("result", "failed to allocate and enqueue uninited op"));
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
    tfs_debug("%s: e %p, uninited %p, sg %p m %p blocks %R, i %R, len %ld, blocks %R\n",
              __func__, e, e->uninited, bound(sg), bound(m), bound(blocks), i, len, blocks);
    if (!e->uninited) {
        filesystem_storage_op(fs, sg, bound(m), blocks, fs->r);
    } else if (e->uninited == INVALID_ADDRESS) {
        sg_zero_fill(sg, range_span(blocks) << fs->blocksize_order);
    } else {
        uninited_lock(e->uninited);
        if (e->uninited->initialized)
            filesystem_storage_op(fs, sg, bound(m), blocks, fs->r);
        else
            queue_uninited_op(fs, e->uninited, sg, blocks, apply_merge(bound(m)), fs->r);
        uninited_unlock(e->uninited);
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
    tfs_debug("%s: dest %p, status %v\n", __func__, bound(dest), s);
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
    if (!(f = table_find(fs->files, t)) || (f == INVALID_ADDRESS)) {
        apply(sh, timm("result", "no such file %v", t,
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

    tfs_debug("create_extent: blocks %R, uninited %p, nblocks %ld\n", blocks, uninited, nblocks);
    if (!filesystem_reserve_log_space(fs, &fs->next_extend_log_offset, 0, 0) ||
        !filesystem_reserve_log_space(fs, &fs->next_new_log_offset, 0, 0))
        return FS_STATUS_NOSPACE;

    u64 start_block = filesystem_allocate_storage(fs, nblocks);
    if (start_block == u64_from_pointer(INVALID_ADDRESS))
        return FS_STATUS_NOSPACE;

    range storage_blocks = irangel(start_block, nblocks);
    tfs_debug("   storage_blocks %R\n", storage_blocks);
    *ex = allocate_extent(h, blocks, storage_blocks);
    if (*ex == INVALID_ADDRESS)
        return FS_STATUS_NOMEM;
    (*ex)->md = 0;
    if (uninited)
        (*ex)->uninited = INVALID_ADDRESS;
    return FS_STATUS_OK;
}

static void destroy_extent(filesystem fs, extent ex)
{
    range q = irangel(ex->start_block, ex->allocated);
    if (!filesystem_free_storage(fs, q))
        msg_err("failed to mark extent at %R as free", q);
    if (ex->uninited && ex->uninited != INVALID_ADDRESS)
        refcount_release(&ex->uninited->refcount);
    deallocate(fs->h, ex, sizeof(*ex));
}

static fs_status add_extent_to_file(fsfile f, extent ex)
{
    if (f->md) {
        heap h = f->fs->h;
        tuple extents;
        symbol a = sym(extents);
        if (!(extents = get_tuple(f->md, a))) {
            extents = allocate_tuple();
            fs_status s = filesystem_write_eav(f->fs, f->md, a, extents);
            if (s != FS_STATUS_OK) {
                deallocate_value(extents);
                return s;
            }
            set(f->md, a, extents);
        }

        // XXX encode this as an immediate bitstring
        tuple e = allocate_tuple();
        ex->md = e;
        set(e, sym(offset), value_from_u64(h, ex->start_block));
        set(e, sym(length), value_from_u64(h, range_span(ex->node.r)));
        set(e, sym(allocated), value_from_u64(h, ex->allocated));
        if (ex->uninited == INVALID_ADDRESS)
            set(e, sym(uninited), null_value);
        symbol offs = intern_u64(ex->node.r.start);
        fs_status s = filesystem_write_eav(f->fs, extents, offs, e);
        if (s != FS_STATUS_OK) {
            destruct_tuple(e, true);
            return s;
        }
        set(extents, offs, e);
    }
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

    if (f->md) {
        tuple extents = get(f->md, sym(extents));
        assert(extents);
        symbol offs = intern_u64(ex->node.r.start);
        filesystem_write_eav(f->fs, extents, offs, 0);
        set(extents, offs, 0);
    }
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

define_closure_function(2, 1, void, uninited_complete,
                        uninited, u, status_handler, complete,
                        status, s)
{
    uninited u = bound(u);
    uninited_lock(u);
    if (!is_ok(s))
        s = timm_up(s, "result", "failed to convert uninited extent");
    apply(bound(complete), s);

    /* Issue dependent storage operations. Note that we issue these all at
       once, without waiting for completions, rather than in a sequential
       fashion. This mirrors the normal behavior of storage operations, and
       works thanks to the property of the pagecache issuing multiple
       operations (writes, really) using the same buffer. So, unlike with the
       contention between the zeroing of uninited sectors and subsequent r/w
       operations, out-of-order completion of requests is not an issue
       here. */
    while (buffer_length(u->op_queue) > 0) {
        assert(buffer_length(u->op_queue) % sizeof(uninited_queued_op) == 0);
        uninited_queued_op uqo = buffer_ref(u->op_queue, 0);
        tfs_debug("%s: issuing op, fs %p, sg %p, m %p, blocks %R, op %F\n",
                  __func__, u->fs, uqo->sg, uqo->m, uqo->blocks, uqo->op);
        if (uqo->sg)
            filesystem_storage_op(u->fs, uqo->sg, uqo->m, uqo->blocks, uqo->op);
        else
            zero_blocks(u->fs, uqo->blocks, uqo->m);
        buffer_consume(u->op_queue, sizeof(struct uninited_queued_op));
    }
    deallocate_buffer(u->op_queue);
    u->op_queue = 0;
    u->initialized = true;
    uninited_unlock(u);
    refcount_release(&u->refcount);
}

define_closure_function(2, 0, void, free_uninited,
                        heap, h, uninited, u)
{
    tfs_debug("%s: %p\n", __func__, bound(u));
    deallocate(bound(h), bound(u), sizeof(struct uninited));
}

static uninited allocate_uninited(filesystem fs, status_handler sh)
{
    uninited u = allocate(fs->h, sizeof(struct uninited));
    if (u == INVALID_ADDRESS)
        return u;
    u->fs = fs;
#ifdef KERNEL
    spin_lock_init(&u->lock);
#endif
    init_refcount(&u->refcount, 2, init_closure(&u->free, free_uninited, fs->h, u));
    u->op_queue = allocate_buffer(fs->h, sizeof(struct uninited_queued_op));
    if (u->op_queue == INVALID_ADDRESS) {
        deallocate(fs->h, u, sizeof(struct uninited));
        return INVALID_ADDRESS;
    }
    u->initialized = false;
    init_closure(&u->complete, uninited_complete, u, sh);
    return u;
}

static u64 write_extent(fsfile f, extent ex, sg_list sg, range blocks, merge m)
{
    filesystem fs = f->fs;
    range i = range_intersection(blocks, ex->node.r);
    u64 data_offset = i.start - ex->node.r.start;
    range r = irangel(ex->start_block + data_offset, range_span(i));

    tfs_debug("   %s: ex %p, uninited %p, sg %p, m %p, blocks %R, write %R\n",
              __func__, ex, ex->uninited, sg, m, blocks, r);

    if (ex->uninited == INVALID_ADDRESS) {
        /* Begin process of normalizing uninited extent */
        if (f->md) {
            assert(ex->md);
            symbol a = sym(uninited);
            tfs_debug("%s: log write %p, %p\n", __func__, ex->md, a);
            fs_status fss = filesystem_write_eav(fs, ex->md, a, 0);
            if (fss != FS_STATUS_OK) {
                apply(apply_merge(m), timm("result", "failed to write log",
                                           "fsstatus", "%d", fss));
                return i.end;
            }
            set(ex->md, a, 0);
        }
        ex->uninited = allocate_uninited(fs, apply_merge(m));
        tfs_debug("%s: new uninited %p\n", __func__, ex->uninited);
        if (ex->uninited == INVALID_ADDRESS)
            goto alloc_fail;
        m = allocate_merge(fs->h, (status_handler)&ex->uninited->complete);
        if (m == INVALID_ADDRESS)
            goto alloc_fail;
        status_handler k = apply_merge(m);
        if (sg) {
            u64 data_end = i.end - ex->node.r.start;
            u64 extent_end = range_span(ex->node.r);
            if (data_offset > 0)
                zero_blocks(fs, range_add(irange(0, data_offset), ex->start_block), m);
            if (data_end < extent_end)
                zero_blocks(fs, range_add(irange(data_end, extent_end), ex->start_block), m);
            filesystem_storage_op(fs, sg, m, r, fs->w);
        } else {
            zero_blocks(fs, r, m);
        }
        apply(k, STATUS_OK);
        return i.end;
    } else if (ex->uninited != 0) {
        uninited_lock(ex->uninited);
        if (ex->uninited->initialized) {
            uninited_unlock(ex->uninited);
            goto write;
        }
        queue_uninited_op(fs, ex->uninited, sg, r, apply_merge(m), fs->w);
        uninited_unlock(ex->uninited);
        return i.end;
    }
  write:
    if (sg)
        filesystem_storage_op(fs, sg, m, r, fs->w);
    else
        zero_blocks(fs, r, m);
    return i.end;
  alloc_fail:
    apply(apply_merge(m), timm("result", "unable to allocate memory for uninited write"));
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
    if (m)
        write_extent(f, ex, sg, blocks, m);
    *edge = blocks.end;
    return FS_STATUS_OK;
}

static fs_status update_extent_length(fsfile f, extent ex, u64 new_length)
{
    if (f->md) {
        assert(ex->md);
        value v = value_from_u64(f->fs->h, new_length);
        symbol l = sym(length);
        fs_status s = filesystem_write_eav(f->fs, ex->md, l, v);
        if (s != FS_STATUS_OK)
            return s;
        value oldval = get(ex->md, l);
        assert(oldval);
        deallocate_value(oldval);
        set(ex->md, l, v);
    }

    /* TODO cheating; should be reinsert - update rangemap interface? */
    tfs_debug("   %s: was %R\n", __func__, ex->node.r);
    ex->node.r = irangel(ex->node.r.start, new_length);
    tfs_debug("   %s: now %R\n", __func__, ex->node.r);
    return FS_STATUS_OK;
}

static fs_status extend(fsfile f, extent ex, sg_list sg, range blocks, merge m, u64 *edge)
{
    u64 free = ex->allocated - range_span(ex->node.r);
    range r = irangel(ex->node.r.end, free);
    range i = range_intersection(r, blocks);
    tfs_debug("   %s: node %R, free 0x%lx (%R), i %R\n", __func__, ex->node.r, free, r, i);
    if (range_span(i) == 0) {
        *edge = blocks.start;
        return FS_STATUS_OK;
    }
    assert(blocks.start >= ex->node.r.end); // XXX temp
    assert(ex->node.r.end <= i.start); // XXX temp
    range z = irange(ex->node.r.end, i.start);
    fs_status s = update_extent_length(f, ex, i.end - ex->node.r.start);
    if (s == FS_STATUS_OK) {
        if (m) {
            if (range_span(z) > 0) {
                tfs_debug("      zero %R\n", z);
                write_extent(f, ex, 0, z, m);
            }
            tfs_debug("      write %R\n", i);
            write_extent(f, ex, sg, i, m);
        }
        *edge = i.end;
    }
    return s;
}

static status extents_range_handler(filesystem fs, fsfile f, range blocks, sg_list sg, merge m)
{
    tfs_debug("%s: file %p blocks %R sg %p m %p\n", __func__, f, blocks, sg, m);

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

    do {
        tfs_debug("   prev %p, next %p\n", prev, next);
        u64 limit = next == INVALID_ADDRESS ? blocks.end : MIN(blocks.end, next->r.start);
        fs_status fss;
        if (!m || sg) {
            if (blocks.start < limit) {
                /* try to extend previous node */
                if (prev != INVALID_ADDRESS && prev->r.end < limit) {
                    tfs_debug("   extent start 0x%lx, limit 0x%lx\n", blocks.start, limit);
                    fss = extend(f, (extent)prev, sg, irange(blocks.start, limit), m, &blocks.start);
                    if (fss != FS_STATUS_OK) {
                        return timm("result", "unable to extend extent", "fsstatus", "%d", fss);
                    }
                }

                /* fill space */
                while (blocks.start < limit) {
                    tfs_debug("   fill start 0x%lx, limit 0x%lx\n", blocks.start, limit);
                    fss = fill_gap(f, sg, irange(blocks.start, limit), m, &blocks.start);
                    if (fss != FS_STATUS_OK) {
                        return timm("result", "unable to create extent", "fsstatus", "%d", fss);
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

            if (m && !sg && range_contains(blocks, ex->node.r)) {
                blocks.start = ex->node.r.end;
                remove_extent_from_file(f, ex);
                destroy_extent(fs, ex);
                prev = INVALID_ADDRESS; /* prev isn't used in zero, but just to be safe */
            } else if (blocks.end > ex->node.r.start) {
                /* TODO: improve write_extent to trim extent on zero */
                if (m)
                    blocks.start = write_extent(f, ex, sg, blocks, m);
                else
                    blocks.start = range_intersection(blocks, ex->node.r).end;
            }
        }
        assert(blocks.start <= blocks.end); // XXX tmp
    } while (range_span(blocks) > 0);

    return STATUS_OK;
}

closure_function(2, 1, status, filesystem_check_or_reserve_extent,
                 filesystem, fs, fsfile, f,
                 range, q)
{
    filesystem fs = bound(fs);
    fsfile f = bound(f);
    assert(range_span(q) > 0);
    range blocks = range_rshift_pad(q, fs->blocksize_order);
    tfs_debug("%s: file %p range %R blocks %R\n", __func__, f, q, blocks);

    return extents_range_handler(fs, f, blocks, 0, 0);
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

    status s = extents_range_handler(fs, f, blocks, sg, m);
    if (s != STATUS_OK)
        goto out;
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
KLIB_EXPORT(filesystem_write_linear);

fs_status filesystem_truncate(filesystem fs, fsfile f, u64 len)
{
    if (f->md) {
        value v = value_from_u64(fs->h, len);
        if (v == INVALID_ADDRESS)
            return FS_STATUS_NOMEM;
        symbol l = sym(filelength);
        fs_status s = filesystem_write_eav(fs, f->md, l, v);
        if (s != FS_STATUS_OK)
            return s;
        set(f->md, l, v);
        filesystem_update_mtime(fs, f->md);
    }
    fsfile_set_length(f, len);
    return FS_STATUS_OK;
}

closure_function(3, 1, void, log_flush_completed,
                 filesystem, fs, status_handler, completion, boolean, sync_complete,
                 status, s)
{
    if (is_ok(s) && !bound(sync_complete)) {
        bound(sync_complete) = true;
        pagecache_sync_volume(bound(fs)->pv, (status_handler)closure_self());
    } else {
        if (bound(fs)->flush)
            apply(bound(fs)->flush, bound(completion));
        else
            apply(bound(completion), s);
        closure_finish();
    }
}

void filesystem_flush(filesystem fs, status_handler completion)
{
    log_flush(fs->tl, closure(fs->h, log_flush_completed, fs, completion, false));
}

void filesystem_reserve(filesystem fs)
{
    refcount_reserve(&fs->refcount);
}

void filesystem_release(filesystem fs)
{
    refcount_release(&fs->refcount);
}

define_closure_function(1, 1, void, fs_free,
                        filesystem, fs,
                        status, s)
{
    if (!is_ok(s)) {
        msg_warn("failed to flush filesystem: %v\n", s);
        timm_dealloc(s);
    }
    filesystem fs = bound(fs);
    if (fs->sync_complete)
        apply(fs->sync_complete);
    destroy_filesystem(fs);
}

define_closure_function(1, 0, void, fs_sync,
                        filesystem, fs)
{
    filesystem fs = bound(fs);
    filesystem_flush(fs, init_closure(&fs->free, fs_free, fs));
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
void filesystem_alloc(fsfile f, long offset, long len,
                      boolean keep_size, fs_status_handler completion)
{
    assert(f);
    filesystem fs = f->fs;

    range blocks = range_rshift_pad(irangel(offset, len), fs->blocksize_order);
    tfs_debug("%s: blocks %R%s\n", __func__, blocks, keep_size ? " (keep size)" : "");

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

void filesystem_dealloc(fsfile f, long offset, long len,
                        fs_status_handler completion)
{
    assert(f);
    filesystem fs = f->fs;
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

static void cleanup_directory(tuple dir);

closure_function(0, 2, boolean, cleanup_directory_each,
                 value, s, value, v)
{
    if (is_tuple(v))
        cleanup_directory(v);
    return true;
}

static void cleanup_directory(tuple dir)
{
    tuple c = children(dir);
    if (!c) {
        return;
    }
    set(c, sym_this("."), 0);
    set(c, sym_this(".."), 0);
    iterate(c, stack_closure(cleanup_directory_each));
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
        set(c, name_sym, child);
    if (child) {
        /* If this is a directory, re-add its . and .. directory entries. */
        fixup_directory(parent, child);
    }
    return s;
}

closure_function(1, 2, boolean, file_unlink_each,
                 tuple, t,
                 value, k, value, v)
{
    if (is_tuple(v) && get(v, sym(no_encode))) {
        destruct_tuple(v, true);
        set(bound(t), k, 0);
    }
    return true;
}

static void file_unlink(filesystem fs, tuple t)
{
    fsfile f = fsfile_from_node(fs, t);
    table_set(fs->files, t, 0);
    if (f) {
        f->md = 0;
        refcount_release(&f->refcount);
    }

    /* If a tuple is not present in the filesystem log dictionary, it can (and should) be destroyed
     * now (it won't be destroyed when the filesystem log is rebuilt). */
    if (get(t, sym(no_encode)))
        destruct_tuple(t, true);
    else
        iterate(t, stack_closure(file_unlink_each, t));
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
        set(entry, sym(no_encode), null_value);
        s = FS_STATUS_OK;
    }

    if (s == FS_STATUS_OK) {
        set(c, name_sym, entry);
        table_set(fs->files, entry, INVALID_ADDRESS);
    }
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
                    set(dir, sym(children), allocate_tuple());
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
            msg_debug("final path component (\"%s\") already exists\n", token);
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
    set(dir, sym(children), allocate_tuple());

    return filesystem_mkentry(fs, cwd, fp, dir, persistent, true);
}

fs_status filesystem_mkdir(filesystem fs, inode cwd, const char *path)
{
    tuple cwd_t = filesystem_get_meta(fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple parent;
    fs_status fss = filesystem_resolve_cstring(&fs, cwd_t, path, 0, &parent);
    if ((fss != FS_STATUS_NOENT) || !parent) {
        return fss;
    }
    buffer name = little_stack_buffer(NAME_MAX + 1);
    if (!dirname_from_path(name, path))
        return FS_STATUS_NAMETOOLONG;
    tuple dir = fs_new_entry(fs);
    set(dir, sym(children), allocate_tuple());
    fss = fs_set_dir_entry(fs, parent, intern(name), dir);
    if (fss == FS_STATUS_OK) {
        table_set(fs->files, dir, INVALID_ADDRESS);
        filesystem_update_mtime(fs, parent);
    } else {
        cleanup_directory(dir);
        destruct_tuple(dir, true);
    }
    return fss;
}

fsfile allocate_fsfile(filesystem fs, tuple md);

static void deallocate_fsfile(filesystem fs, fsfile f, rmnode_handler extent_destructor)
{
    deallocate_rangemap(f->extentmap, extent_destructor);
    pagecache_deallocate_node(f->cache_node);
    deallocate(fs->h, f, sizeof(*f));
}

closure_function(1, 1, void, free_extent,
                 filesystem, fs,
                 rmnode, n)
{
    destroy_extent(bound(fs), (extent)n);
}

fs_status filesystem_get_node(filesystem *fs, inode cwd, const char *path, boolean nofollow,
                              boolean create, boolean exclusive, tuple *n, fsfile *f)
{
    tuple cwd_t = filesystem_get_meta(*fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple parent, t;
    fsfile fsf = 0;
    fs_status fss;
    if (nofollow)
        fss = filesystem_resolve_cstring(fs, cwd_t, path, &t, &parent);
    else
        fss = filesystem_resolve_cstring_follow(fs, cwd_t, path, &t, &parent);
    if (fss != FS_STATUS_OK) {
        if (create) {
            if (!parent)
                return FS_STATUS_NOENT;
            t = fs_new_entry(*fs);

            /* 'make it a file' by adding an empty extents list */
            set(t, sym(extents), allocate_tuple());

            fsf = allocate_fsfile(*fs, t);
            if (fsf != INVALID_ADDRESS) {
                fsfile_set_length(fsf, 0);
                fss = fs_set_dir_entry(*fs, parent, sym_this(filename_from_path(path)), t);
                if (fss != FS_STATUS_OK) {
                    table_set((*fs)->files, t, 0);
                    deallocate_fsfile(*fs, fsf, stack_closure(free_extent, *fs));
                }
            } else {
                fss = FS_STATUS_NOMEM;
            }
            if (fss == FS_STATUS_OK)
                filesystem_update_mtime(*fs, parent);
            else
                destruct_tuple(t, true);

        }
    } else {
        if (exclusive)
            return FS_STATUS_EXIST;
        fsf = fsfile_from_node(*fs, t);
    }
    if (fss == FS_STATUS_OK) {
        filesystem_update_atime(*fs, t);
        *n = t;
        if (f)
            *f = fsf;
    }

    return fss;
}

void filesystem_put_node(filesystem fs, tuple n)
{
}

tuple filesystem_get_meta(filesystem fs, inode n)
{
    tuple t = fs_tuple_from_inode(fs, n);
    return t;
}

void filesystem_put_meta(filesystem fs, tuple n)
{
}

fsfile filesystem_creat_unnamed(filesystem fs)
{
    fsfile f = allocate_fsfile(fs, 0);
    tfs_debug("%s: create unnamed file %p\n", __func__, f);
    fsfile_set_length(f, 0);
    return f;
}

fs_status filesystem_symlink(filesystem fs, inode cwd, const char *path, const char *target)
{
    tuple cwd_t = filesystem_get_meta(fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple parent;
    fs_status fss = filesystem_resolve_cstring(&fs, cwd_t, path, 0, &parent);
    if (fss == FS_STATUS_OK)
        return FS_STATUS_EXIST;
    if ((fss != FS_STATUS_NOENT) || !parent)
        return fss;
    tuple link = fs_new_entry(fs);
    set(link, sym(linktarget), buffer_cstring(fs->h, target));
    fss = fs_set_dir_entry(fs, parent, sym_this(filename_from_path(path)), link);
    if (fss != FS_STATUS_OK)
        destruct_tuple(link, true);
    else
        table_set(fs->files, link, INVALID_ADDRESS);
    return fss;
}

closure_function(1, 2, boolean, check_notempty_each,
                 boolean *, notempty,
                 value, k, value, v)
{
    assert(is_symbol(k));
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    char *p = cstring(symbol_string(k), tmpbuf);

    if (runtime_strcmp(p, ".") && runtime_strcmp(p, "..")) {
        tfs_debug(current, "%s: found entry '%s'\n", __func__, p);
        *bound(notempty) = true;
        return false;
    }
    return true;
}

fs_status filesystem_delete(filesystem fs, inode cwd, const char *path, boolean directory)
{
    tuple cwd_t = filesystem_get_meta(fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple parent, t;
    fs_status fss = filesystem_resolve_cstring(&fs, cwd_t, path, &t, &parent);
    if (fss != FS_STATUS_OK)
        return fss;
    tuple c = children(t);
    if (directory) {
        if (!c)
            return FS_STATUS_NOTDIR;
        boolean notempty = false;
        iterate(c, stack_closure(check_notempty_each, &notempty));
        if (notempty)
            return FS_STATUS_NOTEMPTY;
    } else {
        if (c)
            return FS_STATUS_ISDIR;
    }
    file_unlink(fs, t);
    fss = fs_set_dir_entry(fs, parent, sym_this(filename_from_path(path)), 0);
    if (fss == FS_STATUS_OK)
        filesystem_update_mtime(fs, parent);
    return fss;
}

fs_status filesystem_rename(filesystem oldfs, inode oldwd, const char *oldpath,
                            filesystem newfs, inode newwd, const char *newpath,
                            boolean noreplace)
{
    if (!oldpath[0] || !newpath[0])
        return FS_STATUS_NOENT;
    tuple oldwd_t = filesystem_get_meta(oldfs, oldwd);
    if (!oldwd_t)
        return FS_STATUS_NOENT;
    tuple old, oldparent;
    fs_status s = filesystem_resolve_cstring(&oldfs, oldwd_t, oldpath, &old, &oldparent);
    if (s != FS_STATUS_OK)
        return s;
    tuple newwd_t = fs_tuple_from_inode(newfs, newwd);
    if (!newwd_t)
        return FS_STATUS_NOENT;
    tuple new, newparent;
    s = filesystem_resolve_cstring(&newfs, newwd_t, newpath, &new, &newparent);
    if ((s != FS_STATUS_OK) && (s != FS_STATUS_NOENT))
        return s;
    if (!newparent)
        return FS_STATUS_NOENT;
    if (oldfs != newfs)
        return FS_STATUS_XDEV;
    if (s == FS_STATUS_OK) {
        if (noreplace)
            return FS_STATUS_EXIST;
        tuple c = children(new);
        if (c) {
            if (!is_dir(old))
                return FS_STATUS_ISDIR;
            boolean notempty = false;
            iterate(c, stack_closure(check_notempty_each, &notempty));
            if (notempty)
                return FS_STATUS_NOTEMPTY;
        } else if (is_dir(old))
            return FS_STATUS_NOTDIR;
    }
    if (file_tuple_is_ancestor(old, new, newparent))
        return FS_STATUS_INVAL;
    if ((newparent == oldparent) && (new == old))
        return FS_STATUS_OK;
    if (new)
        file_unlink(newfs, new);
    s = fs_set_dir_entry(newfs, newparent, sym_this(filename_from_path(newpath)), old);
    if (s == FS_STATUS_OK)
        s = fs_set_dir_entry(oldfs, oldparent, sym_this(filename_from_path(oldpath)), 0);
    if (s == FS_STATUS_OK) {
        filesystem_update_mtime(oldfs, oldparent);
        filesystem_update_mtime(newfs, newparent);
    }
    return s;
}

fs_status filesystem_exchange(filesystem fs1, inode wd1, const char *path1,
                              filesystem fs2, inode wd2, const char *path2)
{
    tuple wd1_t = filesystem_get_meta(fs1, wd1);
    if (!wd1_t)
        return FS_STATUS_NOENT;
    tuple n1, n2;
    tuple parent1, parent2;
    fs_status s = filesystem_resolve_cstring(&fs1, wd1_t, path1, &n1, &parent1);
    if (s != FS_STATUS_OK)
        return s;
    tuple wd2_t = fs_tuple_from_inode(fs2, wd2);
    if (!wd2_t)
        return FS_STATUS_NOENT;
    s = filesystem_resolve_cstring(&fs2, wd2_t, path2, &n2, &parent2);
    if (s != FS_STATUS_OK)
        return s;
    if (fs1 != fs2)
        return FS_STATUS_XDEV;
    if ((parent1 == parent2) && (n1 == n2))
        return FS_STATUS_OK;
    if (file_tuple_is_ancestor(n1, n2, parent2) || file_tuple_is_ancestor(n2, n1, parent1))
        return FS_STATUS_INVAL;
    s = fs_set_dir_entry(fs1, parent1, sym_this(filename_from_path(path1)), n2);
    if (s == FS_STATUS_OK)
        s = fs_set_dir_entry(fs2, parent2, sym_this(filename_from_path(path2)), n1);
    if (s == FS_STATUS_OK) {
        filesystem_update_mtime(fs1, parent1);
        filesystem_update_mtime(fs2, parent2);
    }
    return s;
}

static void enumerate_dir_entries(filesystem fs, tuple t);

closure_function(1, 2, boolean, enumerate_dir_entries_each,
                 filesystem, fs,
                 value, s, value, v)
{
    filesystem fs = bound(fs);
    if (is_tuple(v) && !table_find(fs->files, v))
        enumerate_dir_entries(fs, v);
    return true;
}

static void enumerate_dir_entries(filesystem fs, tuple t)
{
    table_set(fs->files, t, INVALID_ADDRESS);
    tuple c = children(t);
    if (c)
        iterate(c, stack_closure(enumerate_dir_entries_each, fs));
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

define_closure_function(1, 1, void, fsf_sync_complete,
                        fsfile, f,
                        status, s)
{
    if (!is_ok(s)) {
        msg_err("failed to sync page cache node: %v\n", s);
        timm_dealloc(s);
    }
    fsfile f = bound(f);
    deallocate_fsfile(f->fs, f, stack_closure(free_extent, f->fs));
}

closure_function(1, 0, void, free_extents,
                 fsfile, f)
{
    fsfile f = bound(f);
    pagecache_sync_node(f->cache_node, init_closure(&f->sync_complete, fsf_sync_complete, f));
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
    pagecache_node_reserve fs_reserve =
#ifndef TFS_READ_ONLY
        closure(fs->h, filesystem_check_or_reserve_extent, fs, f);
#else
    0;
#endif
    pagecache_node pn = pagecache_allocate_node(fs->pv, fs_read, fs_write, fs_reserve);
    if (pn == INVALID_ADDRESS) {
        deallocate(fs->h, f, sizeof(struct fsfile));
        return INVALID_ADDRESS;
    }
    f->extentmap = allocate_rangemap(fs->h);
    f->fs = fs;
    f->md = md;
    f->length = 0;
    if (md)
        table_set(fs->files, md, f);
    f->cache_node = pn;
    f->read = pagecache_node_get_reader(pn);
    f->write = pagecache_node_get_writer(pn);
#ifndef TFS_READ_ONLY
    init_refcount(&f->refcount, 1, closure(fs->h, free_extents, f));
#else
    init_refcount(&f->refcount, 1, 0);
#endif

    return f;
}

fsfile fsfile_from_node(filesystem fs, tuple n)
{
    fsfile fsf = table_find(fs->files, n);
    return (fsf != INVALID_ADDRESS) ? fsf : 0;
}

closure_function(2, 1, void, log_complete,
                 filesystem_complete, fc, filesystem, fs,
                 status, s)
{
    tfs_debug("%s: complete %p, fs %p, status %v\n", __func__, bound(fc), bound(fs), s);
    filesystem fs = bound(fs);
#ifndef TFS_READ_ONLY
    if (is_ok(s)) {
        enumerate_dir_entries(fs, fs->root);
        fixup_directory(fs->root, fs->root);
    }
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

boolean filesystem_reserve_log_space(filesystem fs, u64 *next_offset, u64 *offset, u64 size)
{
    if (size == 0)
        size = filesystem_log_blocks(fs);
    if (*next_offset == INVALID_PHYSICAL) {
        *next_offset = filesystem_allocate_storage(fs, size);
        if (*next_offset == INVALID_PHYSICAL)
            return false;
    }
    if (offset) {
        *offset = *next_offset;
        *next_offset = filesystem_allocate_storage(fs, size);
    }
    return true;
}

void create_filesystem(heap h,
                       u64 blocksize,
                       u64 size,
                       block_io read,
                       block_io write,
                       block_flush flush,
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
    fs->flush = flush;
    fs->storage = create_id_heap(h, h, 0, size >> fs->blocksize_order, 1, false);
    assert(fs->storage != INVALID_ADDRESS);
    fs->temp_log = 0;
    init_refcount(&fs->refcount, 1, init_closure(&fs->sync, fs_sync, fs));
    fs->sync_complete = 0;
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
    fs->next_extend_log_offset = INVALID_PHYSICAL;
    fs->next_new_log_offset = INVALID_PHYSICAL;
    fs->tl = log_create(h, fs, label != 0, closure(h, log_complete, complete, fs));
}

#ifndef BOOT

closure_function(1, 1, void, dealloc_extent_node,
                 filesystem, fs,
                 rmnode, n)
{
    deallocate(bound(fs)->h, n, sizeof(struct extent));
}

/* If the filesystem is not read-only, this function can only be called after flushing any pending
 * writes. */
void destroy_filesystem(filesystem fs)
{
    tfs_debug("%s %p\n", __func__, fs);
    log_destroy(fs->tl);
    if (fs->root) {
        cleanup_directory(fs->root);
        destruct_tuple(fs->root, true);
    }
    table_foreach(fs->files, k, v) {
        (void)k;
        if (v != INVALID_ADDRESS)
            deallocate_fsfile(fs, v, stack_closure(dealloc_extent_node, fs));
    }
    pagecache_dealloc_volume(fs->pv);
    deallocate_table(fs->files);
    destroy_id_heap(fs->storage);
    deallocate(fs->h, fs, sizeof(*fs));
}

#endif

/* Note: This function is used to retrieve the root metadata for a given
   filesystem. To access the system-wide root tuple for other uses, such as to
   probe for configuration options or to register a management interface, use
   get_root_tuple() in src/kernel/init.c. */

tuple filesystem_getroot(filesystem fs)
{
    return fs->root;
}

u64 fs_blocksize(filesystem fs)
{
    return U64_FROM_BIT(fs->blocksize_order);
}
KLIB_EXPORT(fs_blocksize);

u64 fs_totalblocks(filesystem fs)
{
    return fs->storage->total;
}
KLIB_EXPORT(fs_totalblocks);

u64 fs_usedblocks(filesystem fs)
{
    return fs->storage->allocated;
}
KLIB_EXPORT(fs_usedblocks);

u64 fs_freeblocks(filesystem fs)
{
    return heap_free((heap)fs->storage);
}

static struct {
    filesystem (*get_root_fs)();    /* return filesystem at "/" */
    inode (*get_mountpoint)(tuple, filesystem *);   /* find mount point and parent filesystem */
} fs_path_helper;

void fs_set_path_helper(filesystem (*get_root_fs)(), inode (*get_mountpoint)(tuple, filesystem *))
{
    assert(get_root_fs);
    fs_path_helper.get_root_fs = get_root_fs;
    fs_path_helper.get_mountpoint = get_mountpoint;
}

static tuple lookup_follow(filesystem *fs, tuple t, symbol a, tuple *p)
{
    *p = t;
    t = lookup(t, a);
    if (!t)
        return t;
    if (fs_path_helper.get_mountpoint) {
        tuple m = get_tuple(t, sym(mount));
        if (m) {
            buffer b = get(m, sym(fs));
            if (b && (buffer_length(b) == sizeof(u64))) {
                filesystem child_fs = pointer_from_u64(*((u64 *)buffer_ref(b, 0)));
                t = child_fs->root;
                if (fs)
                    *fs = child_fs;
            }
        } else if ((t == *p) && (a == sym_this("..")) &&
                   (t != filesystem_getroot(fs_path_helper.get_root_fs()))) {
            /* t is the root of its filesystem: look for a mount point for this
             * filesystem, and if found look up the parent of the mount directory.
             */
            filesystem parent_fs;
            inode n = fs_path_helper.get_mountpoint(t, &parent_fs);
            tuple mp = n ? fs_tuple_from_inode(parent_fs, n) : 0;
            if (mp) {
                *p = mp;
                t = lookup(mp, a);
                if (fs)
                    *fs = parent_fs;
            }
        }
    }
    return t;
}

/* If the file path being resolved crosses a filesystem boundary (i.e. a mount
 * point), the 'fs' argument (if non-null) is updated to point to the new
 * filesystem. */
// fused buffer wrap, split, and resolve
int filesystem_resolve_cstring(filesystem *fs, tuple cwd, const char *f, tuple *entry,
                    tuple *parent)
{
    assert(fs_path_helper.get_root_fs);
    assert(f);

    tuple t = *f == '/' ? filesystem_getroot(fs_path_helper.get_root_fs()) : cwd;
    if (fs && (*f == '/'))
        *fs = fs_path_helper.get_root_fs();
    tuple p = t;
    buffer a = little_stack_buffer(NAME_MAX);
    char y;
    int nbytes;
    int err;

    while ((y = *f)) {
        if (y == '/') {
            if (buffer_length(a)) {
                t = lookup_follow(fs, t, intern(a), &p);
                if (!t) {
                    err = FS_STATUS_NOENT;
                    goto done;
                }
                err = filesystem_follow_links(fs, t, p, &t);
                if (err) {
                    t = false;
                    goto done;
                }
                if (!children(t))
                    return FS_STATUS_NOTDIR;
                buffer_clear(a);
            }
            f++;
        } else {
            nbytes = push_utf8_character(a, f);
            if (!nbytes) {
                msg_err("Invalid UTF-8 sequence.\n");
                err = FS_STATUS_NOENT;
                p = false;
                goto done;
            }
            f += nbytes;
        }
    }

    if (buffer_length(a)) {
        if (!children(t))
            return FS_STATUS_NOTDIR;
        t = lookup_follow(fs, t, intern(a), &p);
    }
    err = FS_STATUS_NOENT;
done:
    if (!t && (*f == '/') && (*(f + 1)))
        /* The path being resolved contains entries under a non-existent
         * directory. */
        p = false;
    if (parent)
        *parent = p;
    if (entry)
        *entry = t;
    return (t ? 0 : err);
}

/* If the file path being resolved crosses a filesystem boundary (i.e. a mount
 * point), the 'fs' argument (if non-null) is updated to point to the new
 * filesystem. */
int filesystem_resolve_cstring_follow(filesystem *fs, tuple cwd, const char *f, tuple *entry,
        tuple *parent)
{
    tuple t, p;
    int ret = filesystem_resolve_cstring(fs, cwd, f, &t, &p);
    if (!ret) {
        ret = filesystem_follow_links(fs, t, p, &t);
    }
    if ((ret == 0) && entry) {
        *entry = t;
    }
    if (parent) {
        *parent = p;
    }
    return ret;
}

#define SYMLINK_HOPS_MAX    8

int filesystem_follow_links(filesystem *fs, tuple link, tuple parent,
                            tuple *target)
{
    if (!is_symlink(link)) {
        return 0;
    }

    tuple target_t;
    buffer buf = little_stack_buffer(NAME_MAX + 1);
    int hop_count = 0;
    while (true) {
        buffer target_b = linktarget(link);
        if (!target_b) {
            *target = link;
            return 0;
        }
        int ret = filesystem_resolve_cstring(fs, parent, cstring(target_b, buf), &target_t,
                &parent);
        if (ret) {
            return ret;
        }
        if (is_symlink(target_t)) {
            if (hop_count++ == SYMLINK_HOPS_MAX) {
                return FS_STATUS_LINKLOOP;
            }
        }
        link = target_t;
    }
}

fs_status filesystem_mk_socket(filesystem *fs, inode cwd, const char *path, void *s, inode *n)
{
    tuple cwd_t = filesystem_get_meta(*fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple sock, parent;
    fs_status fss = filesystem_resolve_cstring(fs, cwd_t, path, &sock, &parent);
    if (fss == FS_STATUS_OK)
        return FS_STATUS_EXIST;
    if ((fss != FS_STATUS_NOENT) || !parent)
        return fss;
    sock = allocate_tuple();
    if (sock == INVALID_ADDRESS)
        return FS_STATUS_NOMEM;
    tuple sock_handle = allocate_tuple();
    if (sock_handle == INVALID_ADDRESS) {
        fss = FS_STATUS_NOMEM;
        goto err;
    }
    set(sock, sym(handle), sock_handle);
    buffer b = allocate_buffer((*fs)->h, sizeof(u64));
    if (b == INVALID_ADDRESS) {
        fss = FS_STATUS_NOMEM;
        goto err;
    }
    buffer_write_le64(b, u64_from_pointer(s));
    set(sock_handle, sym(value), b);
    set(sock_handle, sym(no_encode), null_value);
    set(sock, sym(socket), null_value);
    fss = do_mkentry(*fs, parent, filename_from_path(path), sock, true);
    if (fss == FS_STATUS_OK) {
        *n = inode_from_tuple(sock);
        filesystem_reserve(*fs);
        return fss;
    }
  err:
    destruct_tuple(sock, true);
    return fss;
}

fs_status filesystem_get_socket(filesystem *fs, inode cwd, const char *path, tuple *n, void **s)
{
    tuple cwd_t = filesystem_get_meta(*fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple t, sock_handle;
    fs_status fss = filesystem_resolve_cstring(fs, cwd_t, path, &t, 0);
    if (fss != FS_STATUS_OK)
        return fss;
    if (!get(t, sym(socket)) || !(sock_handle = get(t, sym(handle))))
        return FS_STATUS_INVAL;
    buffer b = get(sock_handle, sym(value));    // XXX untyped binary
    if (!b || (buffer_length(b) != sizeof(*s))) {
        return FS_STATUS_INVAL;
    }
    *n = t;
    *s = pointer_from_u64(*((u64 *)buffer_ref(b, 0)));
    return FS_STATUS_OK;
}

fs_status filesystem_clear_socket(filesystem fs, inode n)
{
    tuple t = filesystem_get_meta(fs, n);
    fs_status fss;
    if (t) {
        tuple sock_handle = get_tuple(t, sym(handle));
        buffer b = get(sock_handle, sym(value));    // XXX untyped binary
        buffer_clear(b);
        fss = FS_STATUS_OK;
    } else {
        fss = FS_STATUS_NOENT;
    }
    filesystem_release(fs);
    return fss;
}

fs_status filesystem_mount(filesystem parent, inode mount_dir, filesystem child)
{
    tuple mount_dir_t = fs_tuple_from_inode(parent, mount_dir);
    if (!mount_dir_t)
        return FS_STATUS_NOENT;
    tuple mount = allocate_tuple();
    if (mount == INVALID_ADDRESS)
        return FS_STATUS_NOMEM;
    buffer b = allocate_buffer(parent->h, sizeof(u64));
    if (b == INVALID_ADDRESS) {
        deallocate_value(mount);
        return FS_STATUS_NOMEM;
    }
    buffer_write_le64(b, u64_from_pointer(child));
    set(mount, sym(fs), b);
    set(mount, sym(no_encode), null_value); /* non-persistent entry */
    set(mount_dir_t, sym(mount), mount);
    return FS_STATUS_OK;
}

void filesystem_unmount(filesystem parent, inode mount_dir, filesystem child, thunk complete)
{
    tuple mount_dir_t = fs_tuple_from_inode(parent, mount_dir);
    if (mount_dir_t) {
        tuple mount = get_tuple(mount_dir_t, sym(mount));
        set(mount_dir_t, sym(mount), 0);
        destruct_tuple(mount, true);
    }
    child->sync_complete = complete;
    filesystem_release(child);
}

boolean dirname_from_path(buffer dest, const char *path)
{
    int pathlen = runtime_strlen(path);
    const char *last_delim = path_find_last_delim(path, PATH_MAX);
    const char *dirname;
    int len;
    if (!last_delim) {
        dirname = path;
        len = pathlen;
    } else if (last_delim < path + pathlen - 1) {
        dirname = last_delim + 1;
        len = pathlen - (dirname - path);
    } else {    /* The path ends with '/'. */
        const char *delim = path_find_last_delim(path, last_delim - path);
        if (!delim) {
            dirname = path;
            len = pathlen - 1;
        } else {
            dirname = delim + 1;
            len = last_delim - dirname;
        }
    }
    if (len >= dest->length)
        return false;
    if (!buffer_write(dest, dirname, len))
        return false;
    return true;
}

closure_function(4, 2, boolean, file_get_path_each,
                 tuple, p, char *, buf, u64, len, int *, cur_len,
                 value, k, value, v)
{
    if (v != bound(p))
        return true;

    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    char *name = cstring(symbol_string(k), tmpbuf);
    int name_len = runtime_strlen(name);
    if (bound(len) < 1 + name_len + *bound(cur_len)) {
        *bound(cur_len) = 0;
        return false;
    }
    char *buf = bound(buf);
    runtime_memcpy(buf + 1 + name_len, buf, *bound(cur_len));
    buf[0] = '/';
    runtime_memcpy(buf + 1, name, name_len);
    *bound(cur_len) += 1 + name_len;
    return false;
}

int file_get_path(filesystem fs, inode ino, char *buf, u64 len)
{
    if (len < 2) {
        return -1;
    }
    tuple n = filesystem_get_meta(fs, ino);
    if (!n)
        return -1;
    tuple c = children(n);
    if (!c) {   /* Retrieving path of non-directory tuples is not supported. */
        return -1;
    }
    buf[0] = '\0';
    int cur_len = 1;
    tuple p;
    do {
        n = lookup_follow(0, n, sym_this(".."), &p);
        assert(n);
        if (n == p) {   /* this is the root directory */
            if (cur_len == 1) {
                buf[0] = '/';
                buf[1] = '\0';
                cur_len = 2;
            }
            c = 0;
        } else {
            c = children(n);
        }
        if (!c)
            return cur_len;

        iterate(c, stack_closure(file_get_path_each, p, buf, len, &cur_len));
    } while (cur_len > 0);
    return -1;
}

/* Check if t1 is a (direct or indirect) ancestor of t2 (whose parent is p2). */
boolean file_tuple_is_ancestor(tuple t1, tuple t2, tuple p2)
{
    while (p2 != t1) {
        tuple p = lookup(p2, sym_this(".."));
        if (p == p2)
            return false;   /* we reached the filesystem root */
        p2 = p;
    }
    return true;
}
