#include <tfs_internal.h>

//#define TFS_DEBUG
#if defined(TFS_DEBUG)
#ifdef KERNEL
#define tfs_debug(x, ...) do {tprintf(sym(tfs), 0, x, ##__VA_ARGS__);} while(0)
#else
#define tfs_debug(x, ...) do {rprintf("TFS: " x, ##__VA_ARGS__);} while(0)
#endif
#else
#define tfs_debug(x, ...)
#endif

#ifdef BOOT
#define TFS_READ_ONLY
#endif

#ifdef KERNEL

#define tfs_storage_lock(fs)    spin_lock(&(fs)->storage_lock)
#define tfs_storage_unlock(fs)  spin_unlock(&(fs)->storage_lock)

#else

#define tfs_storage_lock(fs)    ((void)fs)
#define tfs_storage_unlock(fs)  ((void)fs)

#endif

#define fs_is_tfs(fs)   ((fs)->get_meta == fs_tuple_from_inode)

#define tfs_from_file(f)    ((tfs)((f)->f.fs))

/* Called with fs locked */
static tuple fs_tuple_from_inode(filesystem fs, inode n)
{
    tuple t = pointer_from_u64(n);
    return table_find(((tfs)fs)->files, t) ? t : 0;
}

static s64 tfsfile_get_blocks(fsfile f)
{
    s64 blocks = 0;
    rangemap_foreach(((tfsfile)f)->extentmap, n) {
        blocks += range_span(n->r);
    }
    return blocks;
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

void fixup_directory(tuple parent, tuple n)
{
    tuple c = children(n);
    if (c)
        iterate(c, stack_closure(fixup_directory_each, n));
    set(n, sym_this(".."), parent);
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

closure_function(2, 1, boolean, tfs_storage_alloc,
                 u64, nblocks, u64 *, start_block,
                 range, r)
{
    if (range_span(r) >= bound(nblocks)) {
        *bound(start_block) = r.start;
        return false;
    }
    return true;
}

u64 filesystem_allocate_storage(tfs fs, u64 nblocks)
{
    if (fs->storage) {
        tfs_storage_lock(fs);
        u64 start_block;
        int result = rangemap_range_find_gaps(fs->storage,
                                              irange(0, fs->fs.size >> fs->fs.blocksize_order),
                                              stack_closure(tfs_storage_alloc,
                                                            nblocks, &start_block));
        boolean success = (result == RM_ABORT) &&
                          rangemap_insert_range(fs->storage, irangel(start_block, nblocks));
        tfs_storage_unlock(fs);
        if (success)
            return start_block;
    }
    return INVALID_PHYSICAL;
}

boolean filesystem_reserve_storage(tfs fs, range blocks)
{
    if (fs->storage) {
        tfs_storage_lock(fs);
        boolean success = !rangemap_range_intersects(fs->storage, blocks) &&
                          rangemap_insert_range(fs->storage, blocks);
        tfs_storage_unlock(fs);
        return success;
    }
    return true;
}

boolean filesystem_free_storage(tfs fs, range blocks)
{
    if (fs->storage) {
        tfs_storage_lock(fs);
        boolean success = rangemap_insert_hole(fs->storage, blocks);
        tfs_storage_unlock(fs);
        return success;
    }
    return true;
}

void ingest_extent(tfsfile f, symbol off, tuple value)
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
    tfs fs = tfs_from_file(f);
    if (!filesystem_reserve_storage(fs, storage_blocks)) {
        /* soft error... */
        msg_err("unable to reserve storage blocks %R\n", storage_blocks);
    }
    range r = irangel(file_offset, length);
    extent ex = allocate_extent(fs->fs.h, r, storage_blocks);
    if (ex == INVALID_ADDRESS)
        halt("out of memory\n");
    ex->md = value;
    if (get(value, sym(uninited)))
        ex->uninited = INVALID_ADDRESS;
    assert(rangemap_insert(f->extentmap, &ex->node));
}

closure_function(1, 2, boolean, tfs_ingest_extent,
                 tfsfile, f,
                 value, s, value, v)
{
    assert(is_symbol(s));
    ingest_extent(bound(f), s, v);
    return true;
}

static boolean enumerate_dir_entries(tfs fs, tuple t);

closure_function(1, 2, boolean, enumerate_dir_entries_each,
                 tfs, fs,
                 value, s, value, v)
{
    tfs fs = bound(fs);
    if (is_tuple(v))
        return enumerate_dir_entries(fs, v);
    return true;
}

static boolean enumerate_dir_entries(tfs fs, tuple t)
{
    tuple extents = get_tuple(t, sym(extents));
    if (extents) {
        tfsfile f = allocate_fsfile(fs, t);
        if (f == INVALID_ADDRESS)
            return false;
        table_set(fs->files, t, f);
        string filelength = get(t, sym(filelength));
        u64 len;
        if (filelength && u64_from_value(filelength, &len))
            fsfile_set_length(&f->f, len);
        return iterate(extents, stack_closure(tfs_ingest_extent, f));
    }
    table_set(fs->files, t, INVALID_ADDRESS);
    tuple c = children(t);
    if (c)
        return iterate(c, stack_closure(enumerate_dir_entries_each, fs));
    return true;
}

void filesystem_storage_op(tfs fs, sg_list sg, range blocks, boolean write,
                           status_handler completion)
{
    tfs_debug("%s: fs %p, sg %p, sg size %ld, blocks %R, %c\n", __func__,
              fs, sg, sg->count, blocks, write ? 'w' : 'r');
    struct storage_req req = {
        .op = write ? STORAGE_OP_WRITESG : STORAGE_OP_READSG,
        .blocks = blocks,
        .data = sg,
        .completion = completion,
    };
    apply(fs->req_handler, &req);
}

closure_function(2, 1, void, zero_blocks_complete,
                 sg_list, sg, status_handler, completion,
                 status, s)
{
    sg_list sg = bound(sg);
    sg_list_release(sg);
    deallocate_sg_list(sg);
    apply(bound(completion), s);
    closure_finish();
}

void zero_blocks(tfs fs, range blocks, merge m)
{
    int blocks_per_page = U64_FROM_BIT(fs->page_order - fs->fs.blocksize_order);
    tfs_debug("%s: fs %p, blocks %R\n", __func__, fs, blocks);
    status_handler completion = apply_merge(m);
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        apply(completion, timm("result", "failed to allocate sg list"));
        return;
    }
    status_handler zero_blocks_completion = closure(fs->fs.h, zero_blocks_complete, sg, completion);
    if (zero_blocks_completion == INVALID_ADDRESS) {
        apply(completion, timm("result", "failed to allocate completion"));
        deallocate_sg_list(sg);
        return;
    }
    range r = blocks;
    while (range_span(r) > 0) {
        u64 length = MIN(range_span(r), blocks_per_page);
        sg_buf sgb = sg_list_tail_add(sg, length);
        if (sgb == INVALID_ADDRESS) {
            apply(zero_blocks_completion, timm("result", "failed to allocate sg buf"));
            return;
        }
        sgb->buf = fs->zero_page;
        sgb->offset = 0;
        sgb->size = U64_FROM_BIT(fs->page_order);
        sgb->refcount = 0;
        r.start += length;
    }
    struct storage_req req = {
        .op = STORAGE_OP_WRITESG,
        .blocks = blocks,
        .data = sg,
        .completion = zero_blocks_completion,
    };
    apply(fs->req_handler, &req);
}

/* called with uninited lock held */
static void queue_uninited_op(tfs fs, uninited u, sg_list sg, range blocks,
                              status_handler complete, boolean write)
{
    struct uninited_queued_op uqo;
    uqo.sg = sg;
    uqo.m = allocate_merge(fs->fs.h, complete);
    if (uqo.m == INVALID_ADDRESS)
        goto alloc_fail;
    uqo.blocks = blocks;
    uqo.write = write;
    if (!buffer_append(u->op_queue, &uqo, sizeof(uqo))) {
        complete = apply_merge(uqo.m);
        goto alloc_fail;
    }
    return;
  alloc_fail:
    apply(complete, timm("result", "failed to allocate and enqueue uninited op"));
}

closure_function(4, 1, boolean, read_extent,
                 tfs, fs, sg_list, sg, merge, m, range, blocks,
                 rmnode, node)
{
    tfs fs = bound(fs);
    sg_list sg = bound(sg);
    extent e = (extent)node;
    range i = range_intersection(bound(blocks), node->r);
    u64 e_offset = i.start - node->r.start;
    u64 len = range_span(i);
    range blocks = irangel(e->start_block + e_offset, len);
    tfs_debug("%s: e %p, uninited %p, sg %p m %p blocks %R, i %R, len %ld, blocks %R\n",
              __func__, e, e->uninited, bound(sg), bound(m), bound(blocks), i, len, blocks);
    if (!e->uninited) {
        filesystem_storage_op(fs, sg, blocks, false, apply_merge(bound(m)));
    } else if (e->uninited == INVALID_ADDRESS) {
        sg_zero_fill(sg, range_span(blocks) << fs->fs.blocksize_order);
    } else {
        uninited_lock(e->uninited);
        if (e->uninited->initialized)
            filesystem_storage_op(fs, sg, blocks, false, apply_merge(bound(m)));
        else
            queue_uninited_op(fs, e->uninited, sg, blocks, apply_merge(bound(m)), false);
        uninited_unlock(e->uninited);
    }
    return true;
}

closure_function(3, 1, boolean, zero_hole,
                 tfs, fs, sg_list, sg, range, blocks,
                 range, z)
{
    range i = range_intersection(bound(blocks), z);
    u64 length = range_span(i) << bound(fs)->fs.blocksize_order;
    tfs_debug("%s: i %R, length %ld\n", __func__, i, length);
    sg_zero_fill(bound(sg), length);
    return true;
}

BSS_RO_AFTER_INIT io_status_handler ignore_io_status;

/* whole block reads, file length resolved in cache */
closure_function(2, 3, void, filesystem_storage_read,
                 tfs, fs, tfsfile, f,
                 sg_list, sg, range, q, status_handler, complete)
{
    tfs fs = bound(fs);
    tfsfile f = bound(f);
    merge m = allocate_merge(fs->fs.h, complete);
    status_handler k = apply_merge(m);
    tfs_debug("%s: fsfile %p, sg %p, q %R, sh %F\n", __func__, f, sg, q, complete);

    /* read extent data and zero gaps */
    range blocks = range_rshift_pad(q, fs->fs.blocksize_order);
    filesystem_lock(&fs->fs);
    rangemap_range_lookup_with_gaps(f->extentmap, blocks,
                                    stack_closure(read_extent, fs, sg, m, blocks),
                                    stack_closure(zero_hole, fs, sg, blocks));
    filesystem_unlock(&fs->fs);
    apply(k, STATUS_OK);
}

#ifndef TFS_READ_ONLY
static tuple cleanup_directory(tuple dir);

fs_status filesystem_write_tuple(tfs fs, tuple t)
{
    if (fs->fs.ro)
        return FS_STATUS_READONLY;
    if (log_write(fs->tl, t) && (!fs->temp_log || log_write(fs->temp_log, t)))
        return FS_STATUS_OK;
    else
        return FS_STATUS_NOSPACE;
}

fs_status filesystem_write_eav(tfs fs, tuple t, symbol a, value v, boolean cleanup)
{
    if (fs->fs.ro)
        return FS_STATUS_READONLY;
    tuple parent = cleanup ? cleanup_directory(v) : 0;
    boolean success = log_write_eav(fs->tl, t, a, v);
    if (success && fs->temp_log) {
        /* The above log_write_eav() call might have started a TFS log rebuild, in which case the
         * entire directory tree has been fixed up again and we have to do another cleanup. */
        if (cleanup)
            cleanup_directory(v);
        success = log_write_eav(fs->temp_log, t, a, v);
    }
    if (cleanup)
        fixup_directory(parent, v);
    if (success)
        return FS_STATUS_OK;
    else
        return FS_STATUS_NOSPACE;
}

static fs_status tfs_truncate(filesystem fs, fsfile f, u64 len)
{
    if (f->md) {
        value v = value_from_u64(fs->h, len);
        if (v == INVALID_ADDRESS)
            return FS_STATUS_NOMEM;
        symbol l = sym(filelength);
        fs_status s = filesystem_write_eav((tfs)fs, f->md, l, v, false);
        if (s != FS_STATUS_OK)
            return s;
        set(f->md, l, v);
        f->status |= FSF_DIRTY_DATASYNC;
        filesystem_update_mtime(fs, f->md);
    }
    return FS_STATUS_OK;
}

/* create a new extent in the filesystem

   The life an extent depends on a particular allocation of contiguous
   storage space. The extent is tied to this allocated area (nominally
   page size). Only the extent data length and allocation size may be
   updated; the file offset and block start are immutable. As an
   optimization, adjacent extents on the disk could be joined into
   larger extents with only a meta update.

*/

static fs_status create_extent(tfs fs, range blocks, boolean uninited, extent *ex)
{
    assert(!fs->fs.ro);
    heap h = fs->fs.h;
    u64 nblocks = MAX(range_span(blocks), MIN_EXTENT_SIZE >> fs->fs.blocksize_order);

    tfs_debug("create_extent: blocks %R, uninited %p, nblocks %ld\n", blocks, uninited, nblocks);
    if (!filesystem_reserve_log_space(fs, &fs->next_extend_log_offset, 0, 0) ||
        !filesystem_reserve_log_space(fs, &fs->next_new_log_offset, 0, 0))
        return FS_STATUS_NOSPACE;

    u64 start_block = filesystem_allocate_storage(fs, nblocks);
    while (start_block == u64_from_pointer(INVALID_ADDRESS)) {
        if (nblocks <= (MIN_EXTENT_ALLOC_SIZE >> fs->fs.blocksize_order))
            break;
        nblocks /= 2;
        start_block = filesystem_allocate_storage(fs, nblocks);
    }
    if (start_block == u64_from_pointer(INVALID_ADDRESS))
        return FS_STATUS_NOSPACE;

    range storage_blocks = irangel(start_block, nblocks);
    tfs_debug("   storage_blocks %R\n", storage_blocks);
    if ((nblocks < range_span(blocks)))
        blocks.end = blocks.start + nblocks;
    *ex = allocate_extent(h, blocks, storage_blocks);
    if (*ex == INVALID_ADDRESS)
        return FS_STATUS_NOMEM;
    (*ex)->md = 0;
    if (uninited)
        (*ex)->uninited = INVALID_ADDRESS;
    return FS_STATUS_OK;
}

static void destroy_extent(tfs fs, extent ex)
{
    range q = irangel(ex->start_block, ex->allocated);
    if (!filesystem_free_storage(fs, q))
        msg_err("failed to mark extent at %R as free", q);
    if (ex->uninited && ex->uninited != INVALID_ADDRESS)
        refcount_release(&ex->uninited->refcount);
    deallocate(fs->fs.h, ex, sizeof(*ex));
}

static fs_status add_extent_to_file(tfsfile f, extent ex)
{
    tuple md = f->f.md;
    if (md) {
        tfs fs = tfs_from_file(f);
        heap h = fs->fs.h;
        tuple extents;
        symbol a = sym(extents);
        if (!(extents = get_tuple(md, a))) {
            extents = allocate_tuple();
            fs_status s = filesystem_write_eav(fs, md, a, extents, false);
            if (s != FS_STATUS_OK) {
                deallocate_value(extents);
                return s;
            }
            set(md, a, extents);
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
        fs_status s = filesystem_write_eav(fs, extents, offs, e, false);
        if (s != FS_STATUS_OK) {
            destruct_value(e, true);
            return s;
        }
        set(extents, offs, e);
        f->f.status |= FSF_DIRTY_DATASYNC;
    }
    tfs_debug("%s: f %p, reserve %R\n", __func__, f, ex->node.r);
    if (!rangemap_insert(f->extentmap, &ex->node)) {
        rbtree_dump(&f->extentmap->t, RB_INORDER);
        assert(0);
    }
    return FS_STATUS_OK;
}

static void remove_extent_from_file(tfsfile f, extent ex)
{
    /* The tuple corresponding to this extent will be destroyed when the
     * filesystem log is compacted. */

    tuple md = f->f.md;
    if (md) {
        tuple extents = get(md, sym(extents));
        assert(extents);
        symbol offs = intern_u64(ex->node.r.start);
        filesystem_write_eav(tfs_from_file(f), extents, offs, 0, false);
        set(extents, offs, 0);
    }
    rangemap_remove_node(f->extentmap, &ex->node);
}

static fs_status add_extents(tfs fs, range i, rangemap rm)
{
    extent ex;
    fs_status fss;
    while (range_span(i)) {
        fss = create_extent(fs, i, true, &ex);
        if (fss != FS_STATUS_OK)
            return fss;
        assert(rangemap_insert(rm, &ex->node));
        i.start = ex->node.r.end;
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
        tfs_debug("%s: issuing op, fs %p, sg %p, m %p, blocks %R, write %d\n",
                  __func__, u->fs, uqo->sg, uqo->m, uqo->blocks, uqo->write);
        if (uqo->sg)
            filesystem_storage_op(u->fs, uqo->sg, uqo->blocks, uqo->write, apply_merge(uqo->m));
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

static uninited allocate_uninited(tfs fs, status_handler sh)
{
    heap h = fs->fs.h;
    uninited u = allocate(h, sizeof(struct uninited));
    if (u == INVALID_ADDRESS)
        return u;
    u->fs = fs;
#ifdef KERNEL
    spin_lock_init(&u->lock);
#endif
    init_refcount(&u->refcount, 2, init_closure(&u->free, free_uninited, h, u));
    u->op_queue = allocate_buffer(h, sizeof(struct uninited_queued_op));
    if (u->op_queue == INVALID_ADDRESS) {
        deallocate(h, u, sizeof(struct uninited));
        return INVALID_ADDRESS;
    }
    u->initialized = false;
    init_closure(&u->complete, uninited_complete, u, sh);
    return u;
}

static u64 write_extent(tfsfile f, extent ex, sg_list sg, range blocks, merge m)
{
    tfs fs = tfs_from_file(f);
    range i = range_intersection(blocks, ex->node.r);
    u64 data_offset = i.start - ex->node.r.start;
    range r = irangel(ex->start_block + data_offset, range_span(i));

    tfs_debug("   %s: ex %p, uninited %p, sg %p, m %p, blocks %R, write %R\n",
              __func__, ex, ex->uninited, sg, m, blocks, r);

    if (ex->uninited == INVALID_ADDRESS) {
        /* Begin process of normalizing uninited extent */
        if (f->f.md) {
            assert(ex->md);
            symbol a = sym(uninited);
            tfs_debug("%s: log write %p, %p\n", __func__, ex->md, a);
            fs_status fss = filesystem_write_eav(fs, ex->md, a, 0, false);
            if (fss != FS_STATUS_OK) {
                apply(apply_merge(m), timm("result", "failed to write log",
                                           "fsstatus", "%d", fss));
                return i.end;
            }
            set(ex->md, a, 0);
            f->f.status |= FSF_DIRTY_DATASYNC;
        }
        ex->uninited = allocate_uninited(fs, apply_merge(m));
        tfs_debug("%s: new uninited %p\n", __func__, ex->uninited);
        if (ex->uninited == INVALID_ADDRESS)
            goto alloc_fail;
        m = allocate_merge(fs->fs.h, (status_handler)&ex->uninited->complete);
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
            filesystem_storage_op(fs, sg, r, true, apply_merge(m));
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
        queue_uninited_op(fs, ex->uninited, sg, r, apply_merge(m), true);
        uninited_unlock(ex->uninited);
        return i.end;
    }
  write:
    if (sg)
        filesystem_storage_op(fs, sg, r, true, apply_merge(m));
    else
        zero_blocks(fs, r, m);
    return i.end;
  alloc_fail:
    apply(apply_merge(m), timm("result", "unable to allocate memory for uninited write"));
    return i.end;
}

static fs_status fill_gap(tfsfile f, sg_list sg, range blocks, merge m, u64 *edge)
{
    tfs_debug("   %s: writing new extent blocks %R\n", __func__, blocks);
    extent ex;
    tfs fs = tfs_from_file(f);
    fs_status fss = create_extent(fs, blocks, m ? false : true, &ex);
    if (fss != FS_STATUS_OK)
        return fss;
    blocks = ex->node.r;
    fss = add_extent_to_file(f, ex);
    if (fss != FS_STATUS_OK) {
        destroy_extent(fs, ex);
        return fss;
    }
    if (m)
        write_extent(f, ex, sg, blocks, m);
    *edge = blocks.end;
    return FS_STATUS_OK;
}

static fs_status update_extent(tfsfile f, extent ex, symbol l, u64 val)
{
    if (f->f.md) {
        assert(ex->md);
        value v = value_from_u64(f->f.fs->h, val);
        fs_status s = filesystem_write_eav(tfs_from_file(f), ex->md, l, v, false);
        if (s != FS_STATUS_OK)
            return s;
        value oldval = get(ex->md, l);
        assert(oldval);
        deallocate_value(oldval);
        set(ex->md, l, v);
        f->f.status |= FSF_DIRTY_DATASYNC;
    }
    return FS_STATUS_OK;
}

static fs_status update_extent_allocated(tfsfile f, extent ex, u64 allocated)
{
    fs_status s = update_extent(f, ex, sym(allocated), allocated);
    if (s != FS_STATUS_OK)
        return s;
    tfs_debug("   %s: was 0x%lx, now 0x%lx\n", __func__, ex->allocated, allocated);
    ex->allocated = allocated;
    return FS_STATUS_OK;
}

static fs_status update_extent_length(tfsfile f, extent ex, u64 new_length)
{
    fs_status s = update_extent(f, ex, sym(length), new_length);
    if (s != FS_STATUS_OK)
        return s;

    /* TODO cheating; should be reinsert - update rangemap interface? */
    tfs_debug("   %s: was %R\n", __func__, ex->node.r);
    ex->node.r = irangel(ex->node.r.start, new_length);
    tfs_debug("   %s: now %R\n", __func__, ex->node.r);
    return FS_STATUS_OK;
}

static fs_status extend(tfsfile f, extent ex, sg_list sg, range blocks, merge m, u64 *edge)
{
    u64 free = ex->allocated - range_span(ex->node.r);
    range r = irangel(ex->node.r.end, free);
    if (blocks.end > r.end) {
        tfs fs = tfs_from_file(f);
        range new = irangel(ex->start_block + ex->allocated, blocks.end - r.end);
        u64 limit = fs->fs.size >> fs->fs.blocksize_order;
        if (new.end > limit)
            new.end = limit;
        if (range_span(new) && filesystem_reserve_storage(fs, new)) {
            fs_status s = update_extent_allocated(f, ex, ex->allocated + range_span(new));
            if (s == FS_STATUS_OK) {
                r.end = blocks.end;
                free = r.end - ex->node.r.end;
            } else {
                filesystem_free_storage(fs, new);
            }
        }
    }
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

static status extents_range_handler(tfs fs, tfsfile f, range q, sg_list sg, merge m)
{
    assert(range_span(q) > 0);
    range blocks = range_rshift_pad(q, fs->fs.blocksize_order);
    tfs_debug("%s: file %p blocks %R sg %p m %p\n", __func__, f, blocks, sg, m);
    assert(!sg || sg->count >= range_span(blocks) << fs->fs.blocksize_order);

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

    if (fsfile_get_length(&f->f) < q.end) {
        tfs_debug("   append; update length to %ld\n", q.end);
        fs_status fss = filesystem_truncate_locked(&fs->fs, &f->f, q.end);
        if (fss != FS_STATUS_OK)
            return timm("result", "unable to set file length", "fsstatus", "%d", fss);
    }
    return STATUS_OK;
}

closure_function(2, 1, status, filesystem_check_or_reserve_extent,
                 tfs, fs, tfsfile, f,
                 range, q)
{
    tfs fs = bound(fs);
    tfsfile f = bound(f);
    tfs_debug("%s: file %p range %R\n", __func__, f, q);
    if (fs->fs.ro)
       return timm("result", "read-only filesystem", "fsstatus", "%d", FS_STATUS_READONLY);
    filesystem_lock(&fs->fs);
    status s = extents_range_handler(fs, f, q, 0, 0);
    filesystem_unlock(&fs->fs);
    return s;
}

closure_function(2, 3, void, filesystem_storage_write,
                 tfs, fs, tfsfile, f,
                 sg_list, sg, range, q, status_handler, complete)
{
    tfs fs = bound(fs);
    tfsfile f = bound(f);
    assert((q.start & MASK(fs->fs.blocksize_order)) == 0);
    tfs_debug("%s: fsfile %p, q %R, sg %p, sg count 0x%lx, complete %F\n", __func__,
              f, q, sg, sg ? sg->count : 0, complete);
    if (fs->fs.ro) {
        apply(complete, timm("result", "read-only filesystem", "fsstatus", "%d", FS_STATUS_READONLY));
        return;
    }

    merge m = allocate_merge(fs->fs.h, complete);
    status_handler sh = apply_merge(m);

    filesystem_lock(&fs->fs);
    status s = extents_range_handler(fs, f, q, sg, m);
    filesystem_unlock(&fs->fs);
    apply(sh, s);
}

closure_function(3, 1, void, fs_cache_sync_complete,
                 tfs, fs, status_handler, completion, boolean, flush_log,
                 status, s)
{
    if (!is_ok(s)) {
#ifdef KERNEL
        async_apply_status_handler(bound(completion), s);
#else
        apply(bound(completion), s);
#endif
        closure_finish();
        return;
    }
    if (bound(flush_log)) {
        bound(flush_log) = false;
        tfs fs = bound(fs);
        filesystem_lock(&fs->fs);
        log_flush(fs->tl, (status_handler)closure_self());
        filesystem_unlock(&fs->fs);
        return;
    }
    struct storage_req req = {
        .op = STORAGE_OP_FLUSH,
        .blocks = irange(0, 0),
        .completion = bound(completion),
    };
    apply(bound(fs)->req_handler, &req);
    closure_finish();
}

static status_handler tfs_get_sync_handler(filesystem fs, fsfile fsf, boolean datasync,
                                           status_handler completion)
{
    boolean flush_log;
    if (fsf)
        flush_log = datasync ? (fsf->status & FSF_DIRTY_DATASYNC) : (fsf->status & FSF_DIRTY);
    else
        flush_log = true;
    return closure(fs->h, fs_cache_sync_complete, (tfs)fs, completion, flush_log);
}

closure_function(2, 1, void, filesystem_op_complete,
                 fsfile, f, fs_status_handler, sh,
                 status, s)
{
    tfs_debug("%s: status %v\n", __func__, s);
    apply(bound(sh), bound(f), is_ok(s) ? FS_STATUS_OK : FS_STATUS_IOERR);
    closure_finish();
}

closure_function(1, 1, boolean, destroy_extent_node,
                 tfs, fs,
                 rmnode, n)
{
    destroy_extent(bound(fs), (extent)n);
    return true;
}

closure_function(0, 1, boolean, assert_no_node,
                 rmnode, n)
{
    halt("tfs: temporary rangemap not empty on dealloc\n");
}

static fs_status add_extents_to_file(tfsfile f, rangemap rm)
{
    tfs_debug("%s: tuple %p\n", __func__, f->f.md);
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
    if (!fs_is_tfs(fs)) {
        apply(completion, f, FS_STATUS_INVAL);
        return;
    }

    range blocks = range_rshift_pad(irangel(offset, len), fs->blocksize_order);
    tfs_debug("%s: blocks %R%s\n", __func__, blocks, keep_size ? " (keep size)" : "");

    rangemap new_rm = allocate_rangemap(fs->h);
    assert(new_rm != INVALID_ADDRESS);
    fs_status status = FS_STATUS_OK;

    tfsfile fsf = (tfsfile)f;
    tfs tfs = (struct tfs *)fs;
    filesystem_lock(fs);
    u64 lastedge = blocks.start;
    rmnode curr = rangemap_first_node(fsf->extentmap);
    while (curr != INVALID_ADDRESS) {
        u64 edge = curr->r.start;
        range i = range_intersection(irange(lastedge, edge), blocks);
        if (range_span(i)) {
            status = add_extents(tfs, i, new_rm);
            if (status != FS_STATUS_OK)
                goto done;
        }
        lastedge = curr->r.end;
        curr = rangemap_next_node(fsf->extentmap, curr);
    }

    /* check for a gap between the last node and blocks.end */
    range i = range_intersection(irange(lastedge, blocks.end), blocks);
    if (range_span(i)) {
        status = add_extents(tfs, i, new_rm);
        if (status != FS_STATUS_OK)
            goto done;
    }

    status = add_extents_to_file(fsf, new_rm);
    if (status != FS_STATUS_OK)
        goto done;
    u64 end = offset + len;
    if (!keep_size && (end > fsfile_get_length(f))) {
        status = filesystem_truncate_locked(fs, f, end);
    }
done:
    filesystem_unlock(fs);
    deallocate_rangemap(new_rm, (status == FS_STATUS_OK ?
                                 stack_closure(assert_no_node) :
                                 stack_closure(destroy_extent_node, tfs)));
    apply(completion, f, status);
}

void filesystem_dealloc(fsfile f, long offset, long len,
                        fs_status_handler completion)
{
    assert(f);
    /* A write with !sg indicates that the pagecache should zero the
       range. The null sg is propagated to the storage write for
       extent removal. */
    status_handler sh;
#ifdef KERNEL
    sh = contextual_closure(filesystem_op_complete, f, completion);
#else
    sh = closure(f->fs->h, filesystem_op_complete, f, completion);
#endif
    filesystem_write_sg(f, 0, irangel(offset, len), sh);
}

closure_function(0, 2, boolean, cleanup_directory_each,
                 value, s, value, v)
{
    if (is_tuple(v))
        cleanup_directory(v);
    return true;
}

static tuple cleanup_directory(tuple n)
{
    tuple parent = table_remove(&n->t, sym(..));
    if (!parent)
        return 0;
    tuple c = children(n);
    if (c)
        iterate(c, stack_closure(cleanup_directory_each));
    return parent;
}

static void destruct_dir_entry(tuple n)
{
    cleanup_directory(n);
    destruct_value(n, true);
}

static boolean tfs_file_unlink(tfs fs, tuple t)
{
    tfsfile f = table_remove(fs->files, t);
    if (f == INVALID_ADDRESS)   /* directory entry other than regular file */
        f = 0;
    if (f) {
        f->f.md = 0;
        refcount_release(&f->f.refcount);
    }

    /* If a tuple is not present in the filesystem log dictionary, it can (and should) be destroyed
     * now (it won't be destroyed when the filesystem log is rebuilt). */
    return (get(t, sym(no_encode)) != 0);
}

static fs_status do_mkentry(tfs fs, tuple parent, const char *name, tuple entry,
                            boolean persistent)
{
    symbol name_sym = sym_this(name);
    tuple c = children(parent);
    fs_status s;

    /* XXX rather than ignore, there should be a wakeup on a sync blockq */
    if (persistent) {
        s = filesystem_write_eav(fs, c, name_sym, entry, false);
    } else {
        set(entry, sym(no_encode), null_value);
        s = FS_STATUS_OK;
    }

    if (s == FS_STATUS_OK) {
        set(c, name_sym, entry);
        table_set(fs->files, entry, INVALID_ADDRESS);
        fs_notify_create(entry, parent, name_sym);
    }
    fixup_directory(parent, entry);
    return s;
}

fs_status filesystem_mkentry(filesystem fs, tuple cwd, const char *fp, tuple entry, boolean persistent, boolean recursive)
{
    if (fs->ro)
        return FS_STATUS_READONLY;
    if (!fs_is_tfs(fs))
        return FS_STATUS_INVAL;
    tfs tfs = (struct tfs *)fs;
    filesystem_lock(fs);
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
                    status = do_mkentry(tfs, parent, token, dir, persistent);
                    if (status != FS_STATUS_OK)
                        break;

                    parent = dir;
                    continue;
                }

                msg_err("a path component (\"%s\") is missing\n", token);
                status = FS_STATUS_NOENT;
                break;
            }

            status = do_mkentry(tfs, parent, token, entry, persistent);
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

    filesystem_unlock(fs);
    deallocate(fs->h, fp_copy, fp_len + 1);
    return status;
}

fs_status filesystem_mkdirpath(filesystem fs, tuple cwd, const char *fp,
        boolean persistent)
{
    if (!fs_is_tfs(fs))
        return FS_STATUS_INVAL;
    tuple dir = fs_new_entry(fs);
    /* 'make it a folder' by attaching a children node to the tuple */
    set(dir, sym(children), allocate_tuple());

    return filesystem_mkentry(fs, cwd, fp, dir, persistent, true);
}

tfsfile allocate_fsfile(tfs fs, tuple md);

static void deallocate_fsfile(tfs fs, tfsfile f, rmnode_handler extent_destructor)
{
    deallocate_rangemap(f->extentmap, extent_destructor);
    pagecache_deallocate_node(f->f.cache_node);
    deallocate(fs->fs.h, f, sizeof(*f));
}

closure_function(1, 1, boolean, free_extent,
                 tfs, fs,
                 rmnode, n)
{
    destroy_extent(bound(fs), (extent)n);
    return true;
}

/* Called with fs locked. */
fs_status filesystem_creat_unnamed(filesystem fs, fsfile *f)
{
    if (!fs_is_tfs(fs))
        return FS_STATUS_INVAL;
    if (fs->ro)
        return FS_STATUS_READONLY;
    *f = (fsfile)allocate_fsfile((tfs)fs, 0);
    if (*f == INVALID_ADDRESS)
        return FS_STATUS_NOMEM;
    tfs_debug("%s: create unnamed file %p\n", __func__, *f);
    fsfile_set_length(*f, 0);
    return FS_STATUS_OK;
}

static fs_status tfs_create(filesystem fs, tuple parent, string name, tuple md, fsfile *f)
{
    tfs tfs = (struct tfs *)fs;
    tfsfile fsf = 0;
    fs_status fss;
    if (is_regular(md)) {
        set(md, sym(extents), allocate_tuple());
        fsf = allocate_fsfile(tfs, md);
        if (fsf == INVALID_ADDRESS)
            return FS_STATUS_NOMEM;
        if (f) {
            *f = &fsf->f;
            fsfile_reserve(*f);
        }
    }
    fss = filesystem_write_eav(tfs, children(parent), intern(name), md, false);
    if (fss == FS_STATUS_OK) {
        if (!fsf)
            table_set(tfs->files, md, INVALID_ADDRESS);
    } else if (fsf) {
        table_set(tfs->files, md, 0);
        deallocate_fsfile(tfs, fsf, stack_closure(free_extent, tfs));
    }
    return fss;
}

static fs_status tfs_unlink(filesystem fs, tuple parent, string name, tuple md,
                            boolean *destruct_md)
{
    tfs tfs = (struct tfs *)fs;
    fs_status fss = filesystem_write_eav(tfs, children(parent), intern(name), 0, false);
    if (fss == FS_STATUS_OK) {
        *destruct_md = tfs_file_unlink(tfs, md);
    }
    return fss;
}

static fs_status tfs_rename(filesystem fs, tuple old_parent, string old_name, tuple old_md,
                            tuple new_parent, string new_name, tuple new_md, boolean exchange,
                            boolean *destruct_md)
{
    if (!exchange) {
        if (new_md) {
            tuple c = children(new_md);
            if (c) {
                if (!is_dir(old_md))
                    return FS_STATUS_ISDIR;
                boolean notempty = (tuple_count(c) != 0);
                if (notempty)
                    return FS_STATUS_NOTEMPTY;
            } else if (is_dir(old_md))
                return FS_STATUS_NOTDIR;
        }
        if (file_tuple_is_ancestor(old_md, new_md, new_parent))
            return FS_STATUS_INVAL;
    } else {
        if (file_tuple_is_ancestor(old_md, new_md, new_parent) ||
            file_tuple_is_ancestor(new_md, old_md, old_parent))
            return FS_STATUS_INVAL;
    }
    tfs tfs = (struct tfs *)fs;
    fs_status s = filesystem_write_eav(tfs, children(new_parent), intern(new_name), old_md, true);
    if (s == FS_STATUS_OK)
        s = filesystem_write_eav(tfs, children(old_parent), intern(old_name), exchange ? new_md : 0,
                                 exchange && new_md);
    if ((s == FS_STATUS_OK) && !exchange && new_md)
        *destruct_md = tfs_file_unlink(tfs, new_md);
    return s;
}

closure_function(1, 1, boolean, tfs_storage_freeblocks,
                 u64 *, free_blocks,
                 range, r)
{
    *bound(free_blocks) += range_span(r);
    return true;
 }

static u64 tfs_freeblocks(filesystem fs)
{
    u64 free_blocks = 0;
    range q = irangel(0, fs->size >> fs->blocksize_order);
    tfs tfs = (struct tfs *)fs;
    tfs_storage_lock(tfs);
    rangemap_range_find_gaps(tfs->storage, q, stack_closure(tfs_storage_freeblocks, &free_blocks));
    tfs_storage_unlock(tfs);
    return free_blocks;
}

void filesystem_log_rebuild(tfs fs, log new_tl, status_handler sh)
{
    tfs_debug("%s(%F)\n", __func__, sh);
    tuple root = fs->fs.root;
    cleanup_directory(root);
    boolean ok = log_write(new_tl, root);
    fixup_directory(root, root);
    if (ok) {
        fs->temp_log = new_tl;
        log_flush(new_tl, sh);
    } else {
        filesystem_unlock(&fs->fs);
        apply(sh, timm("result", "failed to write log"));
        filesystem_lock(&fs->fs);
    }
}

void filesystem_log_rebuild_done(tfs fs, log new_tl)
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
        msg_err("failed to purge page cache node: %v\n", s);
        timm_dealloc(s);
    }
    tfsfile f = (tfsfile)bound(f);
    tfs fs = tfs_from_file(f);
    deallocate_fsfile(fs, f, stack_closure(free_extent, fs));
}

closure_function(1, 0, void, free_extents,
                 fsfile, f)
{
    fsfile f = bound(f);
    pagecache_purge_node(f->cache_node, init_closure(&f->sync_complete, fsf_sync_complete, f));
}

#endif /* !TFS_READ_ONLY */

tfsfile allocate_fsfile(tfs fs, tuple md)
{
    heap h = fs->fs.h;
    tfsfile f = allocate(h, sizeof(struct tfsfile));
    if (f == INVALID_ADDRESS)
        return f;
    fsfile fsf = &f->f;
    sg_io fs_read = closure(h, filesystem_storage_read, fs, f);
    sg_io fs_write =
#ifndef TFS_READ_ONLY
        closure(h, filesystem_storage_write, fs, f);
#else
    0;
#endif
    pagecache_node_reserve fs_reserve =
#ifndef TFS_READ_ONLY
        closure(h, filesystem_check_or_reserve_extent, fs, f);
#else
    0;
#endif
    thunk fs_free =
#ifndef TFS_READ_ONLY
        closure(h, free_extents, fsf);
#else
        0;
#endif
    if (fsfile_init(&fs->fs, fsf, md, fs_read, fs_write, fs_reserve, fs_free) != FS_STATUS_OK) {
        deallocate_closure(fs_read);
        if (fs_write)
            deallocate_closure(fs_write);
        if (fs_reserve)
            deallocate_closure(fs_reserve);
        if (fs_free)
            deallocate_closure(fs_free);
        deallocate(h, f, sizeof(struct tfsfile));
        return INVALID_ADDRESS;
    }
    f->extentmap = allocate_rangemap(h);
    fsf->get_blocks = tfsfile_get_blocks;
    if (md)
        table_set(fs->files, md, f);

    return f;
}

fsfile fsfile_from_node(filesystem fs, tuple n)
{
    fsfile fsf = table_find(((tfs)fs)->files, n);
    return (fsf != INVALID_ADDRESS) ? fsf : 0;
}

closure_function(2, 1, void, log_complete,
                 filesystem_complete, fc, tfs, fs,
                 status, s)
{
    tfs_debug("%s: complete %p, fs %p, status %v\n", __func__, bound(fc), bound(fs), s);
    tfs fs = bound(fs);
    if (is_ok(s)) {
        tuple root = fs->fs.root;
        if (enumerate_dir_entries(fs, root)) {
#ifndef TFS_READ_ONLY
            fixup_directory(root, root);
#endif
        } else {
            s = timm("result", "failed to enumerate directory entries");
        }
    }
    apply(bound(fc), &fs->fs, s);
    closure_finish();
}

closure_function(0, 2, void, ignore_io,
                 status, s, bytes, length) {}

const char *filesystem_get_label(filesystem fs)
{
    return ((tfs)fs)->label;
}

void filesystem_get_uuid(filesystem fs, u8 *uuid)
{
    runtime_memcpy(uuid, ((tfs)fs)->uuid, UUID_LEN);
}

boolean filesystem_reserve_log_space(tfs fs, u64 *next_offset, u64 *offset, u64 size)
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

static tuple tfs_lookup(filesystem fs, tuple parent, string name)
{
    return lookup(parent, intern(name));
}

static fs_status tfs_get_fsfile(filesystem fs, tuple n, fsfile *f)
{
    fsfile fsf = table_find(((tfs)fs)->files, n);
    if (!fsf)
        return FS_STATUS_NOENT;
    if (fsf == INVALID_ADDRESS) /* non-regular file */
        fsf = 0;
    else
        fsfile_reserve(fsf);
    *f = fsf;
    return FS_STATUS_OK;
}

static inode tfs_get_inode(filesystem fs, tuple t) {
    return u64_from_pointer(t);
}

void create_filesystem(heap h,
                       u64 blocksize,
                       u64 size,
                       storage_req_handler req_handler,
                       boolean ro,
                       const char *label,
                       filesystem_complete complete)
{
    tfs_debug("%s\n", __func__);
    tfs fs = allocate(h, sizeof(struct tfs));
    assert(fs != INVALID_ADDRESS);
    status s = filesystem_init(&fs->fs, h, size, blocksize, ro);
    if (!is_ok(s)) {
        deallocate(h, fs, sizeof(struct tfs));
        apply(complete, INVALID_ADDRESS, timm("result", "failed to init fs"));
        return;
    }
    if (!ignore_io_status)
        ignore_io_status = closure(h, ignore_io);
    fs->files = allocate_table(h, identity_key, pointer_equal);
    fs->zero_page = pagecache_get_zero_page();
    assert(fs->zero_page);
    fs->req_handler = req_handler;
    fs->fs.root = 0;
    fs->page_order = pagecache_get_page_order();
    fs->fs.lookup = tfs_lookup;
    fs->fs.get_fsfile = tfs_get_fsfile;
    fs->fs.get_inode = tfs_get_inode;
    fs->fs.get_meta = fs_tuple_from_inode;
#ifndef TFS_READ_ONLY
    fs->fs.create = tfs_create;
    fs->fs.unlink = tfs_unlink;
    fs->fs.rename = tfs_rename;
    fs->fs.truncate = tfs_truncate;
    fs->fs.get_freeblocks = tfs_freeblocks;
    fs->fs.get_sync_handler = tfs_get_sync_handler;
    fs->fs.destroy_fs = destroy_filesystem;
    fs->storage = allocate_rangemap(h);
    assert(fs->storage != INVALID_ADDRESS);
    spin_lock_init(&fs->storage_lock);
    fs->temp_log = 0;
#else
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

closure_function(1, 1, boolean, dealloc_extent_node,
                 filesystem, fs,
                 rmnode, n)
{
    deallocate(bound(fs)->h, n, sizeof(struct extent));
    return true;
}

closure_function(1, 1, boolean, tfs_storage_destroy,
                 heap, h,
                 rmnode, n)
{
    deallocate(bound(h), n, sizeof(*n));
    return false;
}

/* If the filesystem is not read-only, this function can only be called after flushing any pending
 * writes. */
void destroy_filesystem(filesystem fs)
{
    tfs_debug("%s %p\n", __func__, fs);
    tfs tfs = (struct tfs *)fs;
    log_destroy(tfs->tl);
    table_foreach(tfs->files, k, v) {
        fs_notify_release(k, true);
        if (v != INVALID_ADDRESS)
            deallocate_fsfile(tfs, v, stack_closure(dealloc_extent_node, fs));
    }
    if (fs->root)
        destruct_dir_entry(fs->root);
    pagecache_dealloc_volume(fs->pv);
    deallocate_table(tfs->files);
    deallocate_rangemap(tfs->storage, stack_closure(tfs_storage_destroy, fs->h));
    deallocate(fs->h, fs, sizeof(*fs));
}

#endif
