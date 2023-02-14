#include <tfs_internal.h>

//#define TFS_DEBUG
//#define TFS_REPORT_SHA256
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
    case FS_STATUS_READONLY:
        return "filesystem read-only";
    default:
        return "unknown error";
    }
}

/* Called with fs locked */
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

u64 filesystem_get_rdev(filesystem fs, tuple t)
{
    u64 rdev = 0;
    get_u64(t, sym(rdev), &rdev);
    return rdev;
}

void filesystem_set_rdev(filesystem fs, tuple t, u64 rdev)
{
    value rdev_val = value_from_u64(fs->h, rdev);
    set(t, sym(rdev), rdev_val);
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

closure_function(2, 1, boolean, fs_storage_alloc,
                 u64, nblocks, u64 *, start_block,
                 range, r)
{
    if (range_span(r) >= bound(nblocks)) {
        *bound(start_block) = r.start;
        return false;
    }
    return true;
}

u64 filesystem_allocate_storage(filesystem fs, u64 nblocks)
{
    if (fs->storage) {
        fs_storage_lock(fs);
        u64 start_block;
        int result = rangemap_range_find_gaps(fs->storage,
                                              irange(0, fs->size >> fs->blocksize_order),
                                              stack_closure(fs_storage_alloc,
                                                            nblocks, &start_block));
        boolean success = (result == RM_ABORT) &&
                          rangemap_insert_range(fs->storage, irangel(start_block, nblocks));
        fs_storage_unlock(fs);
        if (success)
            return start_block;
    }
    return INVALID_PHYSICAL;
}

boolean filesystem_reserve_storage(filesystem fs, range blocks)
{
    if (fs->storage) {
        fs_storage_lock(fs);
        boolean success = !rangemap_range_intersects(fs->storage, blocks) &&
                          rangemap_insert_range(fs->storage, blocks);
        fs_storage_unlock(fs);
        return success;
    }
    return true;
}

boolean filesystem_free_storage(filesystem fs, range blocks)
{
    if (fs->storage) {
        fs_storage_lock(fs);
        boolean success = rangemap_insert_hole(fs->storage, blocks);
        fs_storage_unlock(fs);
        return success;
    }
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

closure_function(1, 2, boolean, tfs_ingest_extent,
                 fsfile, f,
                 value, s, value, v)
{
    assert(is_symbol(s));
    ingest_extent(bound(f), s, v);
    return true;
}

static boolean enumerate_dir_entries(filesystem fs, tuple t);

closure_function(1, 2, boolean, enumerate_dir_entries_each,
                 filesystem, fs,
                 value, s, value, v)
{
    filesystem fs = bound(fs);
    if (is_tuple(v))
        return enumerate_dir_entries(fs, v);
    return true;
}

static boolean enumerate_dir_entries(filesystem fs, tuple t)
{
    tuple extents = get_tuple(t, sym(extents));
    if (extents) {
        fsfile f = allocate_fsfile(fs, t);
        if (f == INVALID_ADDRESS)
            return false;
        table_set(fs->files, t, f);
        string filelength = get(t, sym(filelength));
        u64 len;
        if (filelength && u64_from_value(filelength, &len))
            fsfile_set_length(f, len);
        return iterate(extents, stack_closure(tfs_ingest_extent, f));
    }
    table_set(fs->files, t, INVALID_ADDRESS);
    tuple c = children(t);
    if (c)
        return iterate(c, stack_closure(enumerate_dir_entries_each, fs));
    return true;
}

void filesystem_storage_op(filesystem fs, sg_list sg, range blocks, boolean write,
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

void zero_blocks(filesystem fs, range blocks, merge m)
{
    int blocks_per_page = U64_FROM_BIT(fs->page_order - fs->blocksize_order);
    tfs_debug("%s: fs %p, blocks %R\n", __func__, fs, blocks);
    status_handler completion = apply_merge(m);
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        apply(completion, timm("result", "failed to allocate sg list"));
        return;
    }
    status_handler zero_blocks_completion = closure(fs->h, zero_blocks_complete, sg, completion);
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
static void queue_uninited_op(filesystem fs, uninited u, sg_list sg, range blocks,
                              status_handler complete, boolean write)
{
    struct uninited_queued_op uqo;
    uqo.sg = sg;
    uqo.m = allocate_merge(fs->h, complete);
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
        filesystem_storage_op(fs, sg, blocks, false, apply_merge(bound(m)));
    } else if (e->uninited == INVALID_ADDRESS) {
        sg_zero_fill(sg, range_span(blocks) << fs->blocksize_order);
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
                 filesystem, fs, sg_list, sg, range, blocks,
                 range, z)
{
    range i = range_intersection(bound(blocks), z);
    u64 length = range_span(i) << bound(fs)->blocksize_order;
    tfs_debug("%s: i %R, length %ld\n", __func__, i, length);
    sg_zero_fill(bound(sg), length);
    return true;
}

BSS_RO_AFTER_INIT io_status_handler ignore_io_status;

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
    filesystem_lock(fs);
    rangemap_range_lookup_with_gaps(f->extentmap, blocks,
                                    stack_closure(read_extent, fs, sg, m, blocks),
                                    stack_closure(zero_hole, fs, sg, blocks));
    filesystem_unlock(fs);
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
    tfs_debug("filesystem_read_entire: t %p, bufheap %p, buffer_handler %p, status_handler %p\n",
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
    if (fs->ro)
        return FS_STATUS_READONLY;
    if (log_write(fs->tl, t) && (!fs->temp_log || log_write(fs->temp_log, t)))
        return FS_STATUS_OK;
    else
        return FS_STATUS_NOSPACE;
}

fs_status filesystem_write_eav(filesystem fs, tuple t, symbol a, value v)
{
    if (fs->ro)
        return FS_STATUS_READONLY;
    if (log_write_eav(fs->tl, t, a, v) &&
            (!fs->temp_log || log_write_eav(fs->temp_log, t, a, v)))
        return FS_STATUS_OK;
    else
        return FS_STATUS_NOSPACE;
}

static fs_status filesystem_truncate_locked(filesystem fs, fsfile f, u64 len)
{
    if (fs->ro)
        return FS_STATUS_READONLY;
    if (f->md) {
        value v = value_from_u64(fs->h, len);
        if (v == INVALID_ADDRESS)
            return FS_STATUS_NOMEM;
        symbol l = sym(filelength);
        fs_status s = filesystem_write_eav(fs, f->md, l, v);
        if (s != FS_STATUS_OK)
            return s;
        set(f->md, l, v);
        f->status |= FSF_DIRTY_DATASYNC;
        filesystem_update_mtime(fs, f->md);
    }
    fsfile_set_length(f, len);
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

static fs_status create_extent(filesystem fs, range blocks, boolean uninited, extent *ex)
{
    assert(!fs->ro);
    heap h = fs->h;
    u64 nblocks = MAX(range_span(blocks), MIN_EXTENT_SIZE >> fs->blocksize_order);

    tfs_debug("create_extent: blocks %R, uninited %p, nblocks %ld\n", blocks, uninited, nblocks);
    if (!filesystem_reserve_log_space(fs, &fs->next_extend_log_offset, 0, 0) ||
        !filesystem_reserve_log_space(fs, &fs->next_new_log_offset, 0, 0))
        return FS_STATUS_NOSPACE;

    u64 start_block = filesystem_allocate_storage(fs, nblocks);
    while (start_block == u64_from_pointer(INVALID_ADDRESS)) {
        if (nblocks <= (MIN_EXTENT_ALLOC_SIZE >> fs->blocksize_order))
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
        f->status |= FSF_DIRTY_DATASYNC;
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
            f->status |= FSF_DIRTY_DATASYNC;
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

static fs_status fill_gap(fsfile f, sg_list sg, range blocks, merge m, u64 *edge)
{
    tfs_debug("   %s: writing new extent blocks %R\n", __func__, blocks);
    extent ex;
    fs_status fss = create_extent(f->fs, blocks, m ? false : true, &ex);
    if (fss != FS_STATUS_OK)
        return fss;
    blocks = ex->node.r;
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

static fs_status update_extent(fsfile f, extent ex, symbol l, u64 val)
{
    if (f->md) {
        assert(ex->md);
        value v = value_from_u64(f->fs->h, val);
        fs_status s = filesystem_write_eav(f->fs, ex->md, l, v);
        if (s != FS_STATUS_OK)
            return s;
        value oldval = get(ex->md, l);
        assert(oldval);
        deallocate_value(oldval);
        set(ex->md, l, v);
        f->status |= FSF_DIRTY_DATASYNC;
    }
    return FS_STATUS_OK;
}

static fs_status update_extent_allocated(fsfile f, extent ex, u64 allocated)
{
    fs_status s = update_extent(f, ex, sym(allocated), allocated);
    if (s != FS_STATUS_OK)
        return s;
    tfs_debug("   %s: was 0x%lx, now 0x%lx\n", __func__, ex->allocated, allocated);
    ex->allocated = allocated;
    return FS_STATUS_OK;
}

static fs_status update_extent_length(fsfile f, extent ex, u64 new_length)
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

static fs_status extend(fsfile f, extent ex, sg_list sg, range blocks, merge m, u64 *edge)
{
    u64 free = ex->allocated - range_span(ex->node.r);
    range r = irangel(ex->node.r.end, free);
    if (blocks.end > r.end) {
        filesystem fs = f->fs;
        range new = irangel(ex->start_block + ex->allocated, blocks.end - r.end);
        u64 limit = fs->size >> fs->blocksize_order;
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

static status extents_range_handler(filesystem fs, fsfile f, range q, sg_list sg, merge m)
{
    assert(range_span(q) > 0);
    range blocks = range_rshift_pad(q, fs->blocksize_order);
    tfs_debug("%s: file %p blocks %R sg %p m %p\n", __func__, f, blocks, sg, m);
    assert(!sg || sg->count >= range_span(blocks) << fs->blocksize_order);

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

    if (fsfile_get_length(f) < q.end) {
        tfs_debug("   append; update length to %ld\n", q.end);
        fs_status fss = filesystem_truncate_locked(fs, f, q.end);
        if (fss != FS_STATUS_OK)
            return timm("result", "unable to set file length", "fsstatus", "%d", fss);
    }
    return STATUS_OK;
}

closure_function(2, 1, status, filesystem_check_or_reserve_extent,
                 filesystem, fs, fsfile, f,
                 range, q)
{
    filesystem fs = bound(fs);
    fsfile f = bound(f);
    tfs_debug("%s: file %p range %R\n", __func__, f, q);
    if (fs->ro)
       return timm("result", "read-only filesystem", "fsstatus", "%d", FS_STATUS_READONLY);
    filesystem_lock(fs);
    status s = extents_range_handler(fs, f, q, 0, 0);
    filesystem_unlock(fs);
    return s;
}

closure_function(2, 3, void, filesystem_storage_write,
                 filesystem, fs, fsfile, f,
                 sg_list, sg, range, q, status_handler, complete)
{
    filesystem fs = bound(fs);
    fsfile f = bound(f);
    assert((q.start & MASK(fs->blocksize_order)) == 0);
    tfs_debug("%s: fsfile %p, q %R, sg %p, sg count 0x%lx, complete %F\n", __func__,
              f, q, sg, sg ? sg->count : 0, complete);
    if (fs->ro) {
        apply(complete, timm("result", "read-only filesystem", "fsstatus", "%d", FS_STATUS_READONLY));
        return;
    }

    merge m = allocate_merge(fs->h, complete);
    status_handler sh = apply_merge(m);

    filesystem_lock(fs);
    status s = extents_range_handler(fs, f, q, sg, m);
    filesystem_unlock(fs);
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
    if (sgb == INVALID_ADDRESS) {
        deallocate_sg_list(sg);
        apply(io_complete, timm("result", "failed to allocate sg buf",
                                "fsstatus", "%d", FS_STATUS_NOMEM), 0);
        return;
    }
    sgb->buf = src;
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = 0;
    filesystem_write_sg(f, sg, q, closure(f->fs->h, filesystem_write_complete,
                                          sg, length, io_complete));
}

fs_status filesystem_truncate(filesystem fs, fsfile f, u64 len)
{
    filesystem_lock(fs);
    fs_status fss = filesystem_truncate_locked(fs, f, len);
    if (f->md)
        fs_notify_modify(f->md);
    filesystem_unlock(fs);
    return fss;
}

closure_function(3, 1, void, fs_cache_sync_complete,
                 filesystem, fs, status_handler, completion, boolean, flush_log,
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
        filesystem fs = bound(fs);
        filesystem_lock(fs);
        log_flush(fs->tl, (status_handler)closure_self());
        filesystem_unlock(fs);
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

void filesystem_flush(filesystem fs, status_handler completion)
{
    status_handler sh = closure(fs->h, fs_cache_sync_complete, fs, completion, true);
    if (sh == INVALID_ADDRESS) {
        apply(completion, timm("result", "failed to allocate closure"));
        return;
    }
    pagecache_sync_volume(fs->pv, sh);
}

void fsfile_flush(fsfile fsf, boolean datasync, status_handler completion)
{
    boolean flush_log = datasync ? (fsf->status & FSF_DIRTY_DATASYNC) : (fsf->status & FSF_DIRTY);
    status_handler sh = closure(fsf->fs->h, fs_cache_sync_complete, fsf->fs, completion, flush_log);
    if (sh == INVALID_ADDRESS) {
        apply(completion, timm("result", "failed to allocate closure"));
        return;
    }
    if (flush_log)
        fsf->status &= ~FSF_DIRTY;
    pagecache_sync_node(fsf->cache_node, sh);
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

closure_function(1, 1, boolean, destroy_extent_node,
                 filesystem, fs,
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

    filesystem_lock(fs);
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
        status = filesystem_truncate_locked(fs, f, end);
    }
done:
    filesystem_unlock(fs);
    deallocate_rangemap(new_rm, (status == FS_STATUS_OK ?
                                 stack_closure(assert_no_node) :
                                 stack_closure(destroy_extent_node, fs)));
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

static void cleanup_directory(tuple n)
{
    set(n, sym_this(".."), 0);
    tuple c = children(n);
    if (c)
        iterate(c, stack_closure(cleanup_directory_each));
}

static fs_status fs_set_dir_entry(filesystem fs, tuple parent, symbol name_sym,
                                  tuple child)
{
    if (child) {
        /* Remove reference to parent, which must not be written in the log. */
        cleanup_directory(child);
    }
    tuple c = children(parent);
    fs_status s = filesystem_write_eav(fs, c, name_sym, child);
    if (s == FS_STATUS_OK) {
        set(c, name_sym, child);
        filesystem_update_mtime(fs, parent);
    }
    if (child) {
        /* Re-add reference to parent. */
        fixup_directory(parent, child);
    }
    return s;
}

static void destruct_dir_entry(tuple n)
{
    cleanup_directory(n);
    destruct_tuple(n, true);
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

/* Called with fs locked. */
static void file_unlink(filesystem fs, tuple t)
{
    fsfile f = table_remove(fs->files, t);
    if (f == INVALID_ADDRESS)   /* directory entry other than regular file */
        f = 0;
    if (f) {
        f->md = 0;
        refcount_release(&f->refcount);
    }
    fs_notify_release(t, false);

    /* If a tuple is not present in the filesystem log dictionary, it can (and should) be destroyed
     * now (it won't be destroyed when the filesystem log is rebuilt). */
    if (get(t, sym(no_encode)))
        destruct_dir_entry(t);
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
        fs_notify_create(entry, parent, name_sym);
    }
    fixup_directory(parent, entry);
    return s;
}

fs_status filesystem_mkentry(filesystem fs, tuple cwd, const char *fp, tuple entry, boolean persistent, boolean recursive)
{
    if (fs->ro)
        return FS_STATUS_READONLY;
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

    filesystem_unlock(fs);
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
        goto out;
    }
    buffer name = little_stack_buffer(NAME_MAX + 1);
    if (!dirname_from_path(name, path)) {
        fss = FS_STATUS_NAMETOOLONG;
        goto out;
    }
    tuple dir = fs_new_entry(fs);
    set(dir, sym(children), allocate_tuple());
    symbol name_sym = intern(name);
    fss = fs_set_dir_entry(fs, parent, name_sym, dir);
    if (fss == FS_STATUS_OK) {
        table_set(fs->files, dir, INVALID_ADDRESS);
        fs_notify_create(dir, parent, name_sym);
    } else {
        destruct_dir_entry(dir);
    }
  out:
    filesystem_unlock(fs);
    filesystem_release(fs);
    return fss;
}

fsfile allocate_fsfile(filesystem fs, tuple md);

static void deallocate_fsfile(filesystem fs, fsfile f, rmnode_handler extent_destructor)
{
    deallocate_rangemap(f->extentmap, extent_destructor);
    pagecache_deallocate_node(f->cache_node);
    deallocate(fs->h, f, sizeof(*f));
}

closure_function(1, 1, boolean, free_extent,
                 filesystem, fs,
                 rmnode, n)
{
    destroy_extent(bound(fs), (extent)n);
    return true;
}

fs_status filesystem_get_node(filesystem *fs, inode cwd, const char *path, boolean nofollow,
                              boolean create, boolean exclusive, boolean truncate, tuple *n,
                              fsfile *f)
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
            if (!parent) {
                fss = FS_STATUS_NOENT;
                goto out;
            }
            if ((*fs)->ro) {
                fss = FS_STATUS_READONLY;
                goto out;
            }
            t = fs_new_entry(*fs);

            /* 'make it a file' by adding an empty extents list */
            set(t, sym(extents), allocate_tuple());

            fsf = allocate_fsfile(*fs, t);
            if (fsf != INVALID_ADDRESS) {
                fsfile_set_length(fsf, 0);
                symbol name = sym_this(filename_from_path(path));
                fss = fs_set_dir_entry(*fs, parent, name, t);
                if (fss != FS_STATUS_OK) {
                    table_set((*fs)->files, t, 0);
                    deallocate_fsfile(*fs, fsf, stack_closure(free_extent, *fs));
                } else {
                    fs_notify_create(t, parent, name);
                }
            } else {
                fss = FS_STATUS_NOMEM;
            }
            if (fss != FS_STATUS_OK)
                destruct_dir_entry(t);

        }
    } else {
        if (exclusive) {
            fss = FS_STATUS_EXIST;
        } else {
            fsf = fsfile_from_node(*fs, t);
            if (fsf && truncate)
                fss = filesystem_truncate_locked(*fs, fsf, 0);
        }
    }
  out:
    if (fss == FS_STATUS_OK) {
        *n = t;
        if (f)
            *f = fsf;
    } else {
        filesystem_unlock(*fs);
        filesystem_release(*fs);
    }

    return fss;
}

void filesystem_put_node(filesystem fs, tuple n)
{
    filesystem_unlock(fs);
    filesystem_release(fs);
}

/* Called with fs unlocked; if inode number can be resolved, returns with fs locked. */
tuple filesystem_get_meta(filesystem fs, inode n)
{
    filesystem_lock(fs);
    tuple t = fs_tuple_from_inode(fs, n);
    if (!t)
        filesystem_unlock(fs);
    return t;
}

void filesystem_put_meta(filesystem fs, tuple n)
{
    filesystem_unlock(fs);
}

/* Called with fs locked. */
fs_status filesystem_creat_unnamed(filesystem fs, fsfile *f)
{
    if (fs->ro)
        return FS_STATUS_READONLY;
    *f = allocate_fsfile(fs, 0);
    if (*f == INVALID_ADDRESS)
        return FS_STATUS_NOMEM;
    tfs_debug("%s: create unnamed file %p\n", __func__, *f);
    fsfile_set_length(*f, 0);
    return FS_STATUS_OK;
}

fs_status filesystem_symlink(filesystem fs, inode cwd, const char *path, const char *target)
{
    tuple cwd_t = filesystem_get_meta(fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple parent;
    fs_status fss = filesystem_resolve_cstring(&fs, cwd_t, path, 0, &parent);
    if (fss == FS_STATUS_OK) {
        fss = FS_STATUS_EXIST;
        goto out;
    }
    if ((fss != FS_STATUS_NOENT) || !parent)
        goto out;
    if (fs->ro) {
        fss = FS_STATUS_READONLY;
        goto out;
    }
    tuple link = fs_new_entry(fs);
    set(link, sym(linktarget), buffer_cstring(fs->h, target));
    symbol name = sym_this(filename_from_path(path));
    fss = fs_set_dir_entry(fs, parent, name, link);
    if (fss != FS_STATUS_OK) {
        destruct_dir_entry(link);
    } else {
        table_set(fs->files, link, INVALID_ADDRESS);
        fs_notify_create(link, parent, name);
    }
  out:
    filesystem_unlock(fs);
    filesystem_release(fs);
    return fss;
}

fs_status filesystem_delete(filesystem fs, inode cwd, const char *path, boolean directory)
{
    tuple cwd_t = filesystem_get_meta(fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple parent, t;
    fs_status fss = filesystem_resolve_cstring(&fs, cwd_t, path, &t, &parent);
    if (fss != FS_STATUS_OK)
        goto out;
    tuple c = children(t);
    if (directory) {
        if (!c) {
            fss = FS_STATUS_NOTDIR;
            goto out;
        }
        boolean notempty = (tuple_count(c) != 0);
        if (notempty) {
            fss = FS_STATUS_NOTEMPTY;
            goto out;
        }
    } else {
        if (c) {
            fss = FS_STATUS_ISDIR;
            goto out;
        }
    }
    if (fs->ro) {
        fss = FS_STATUS_READONLY;
        goto out;
    }
    symbol name = sym_this(filename_from_path(path));
    fss = fs_set_dir_entry(fs, parent, name, 0);
    if (fss == FS_STATUS_OK) {
        fs_notify_delete(t, parent, name);
        file_unlink(fs, t);
    }
  out:
    filesystem_unlock(fs);
    filesystem_release(fs);
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
    filesystem fs_to_unlock;
    fs_status s = filesystem_resolve_cstring(&oldfs, oldwd_t, oldpath, &old, &oldparent);
    if (s != FS_STATUS_OK) {
        fs_to_unlock = oldfs;
        newfs = 0;
        goto out;
    }
    if (newfs != oldfs) {
        filesystem_unlock(oldfs);
        filesystem_lock(newfs);
    }
    tuple newwd_t = fs_tuple_from_inode(newfs, newwd);
    if (!newwd_t) {
        s = FS_STATUS_NOENT;
        fs_to_unlock = newfs;
        newfs = 0;
        goto out;
    }
    tuple new, newparent;
    s = filesystem_resolve_cstring(&newfs, newwd_t, newpath, &new, &newparent);
    fs_to_unlock = newfs;
    if ((s != FS_STATUS_OK) && (s != FS_STATUS_NOENT))
        goto out;
    if (!newparent) {
        s = FS_STATUS_NOENT;
        goto out;
    }
    if (oldfs != newfs) {
        s = FS_STATUS_XDEV;
        goto out;
    }
    if (oldfs->ro) {
        s = FS_STATUS_READONLY;
        goto out;
    }
    /* oldfs may have been unlocked in the process of resolving newpath, so check (now that the
     * filesystem is locked again) whether previously found tuples are still valid. */
    if (!table_find(oldfs->files, old) || !table_find(oldfs->files, oldparent)) {
        s = FS_STATUS_NOENT;
        goto out;
    }

    if (s == FS_STATUS_OK) {
        if (noreplace) {
            s = FS_STATUS_EXIST;
            goto out;
        }
        tuple c = children(new);
        if (c) {
            if (!is_dir(old)) {
                s = FS_STATUS_ISDIR;
                goto out;
            }
            boolean notempty = (tuple_count(c) != 0);
            if (notempty) {
                s = FS_STATUS_NOTEMPTY;
                goto out;
            }
        } else if (is_dir(old)) {
            s = FS_STATUS_NOTDIR;
            goto out;
        }
    }
    if (file_tuple_is_ancestor(old, new, newparent)) {
        s = FS_STATUS_INVAL;
        goto out;
    }
    if ((newparent == oldparent) && (new == old)) {
        s = FS_STATUS_OK;
        goto out;
    }
    symbol old_s = sym_this(filename_from_path(oldpath));
    symbol new_s = sym_this(filename_from_path(newpath));
    s = fs_set_dir_entry(newfs, newparent, new_s, old);
    if (s == FS_STATUS_OK)
        s = fs_set_dir_entry(oldfs, oldparent, old_s, 0);
    if (s == FS_STATUS_OK) {
        fs_notify_move(old, oldparent, old_s, newparent, new_s);
        if (new)
            file_unlink(newfs, new);
    }
  out:
    filesystem_unlock(fs_to_unlock);
    filesystem_release(oldfs);
    if (newfs)
        filesystem_release(newfs);
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
    filesystem fs_to_unlock;
    fs_status s = filesystem_resolve_cstring(&fs1, wd1_t, path1, &n1, &parent1);
    if (s != FS_STATUS_OK) {
        fs_to_unlock = fs1;
        fs2 = 0;
        goto out;
    }
    if (fs2 != fs1) {
        filesystem_unlock(fs1);
        filesystem_lock(fs2);
    }
    tuple wd2_t = fs_tuple_from_inode(fs2, wd2);
    if (!wd2_t) {
        s = FS_STATUS_NOENT;
        fs_to_unlock = fs2;
        fs2 = 0;
        goto out;
    }
    s = filesystem_resolve_cstring(&fs2, wd2_t, path2, &n2, &parent2);
    fs_to_unlock = fs2;
    if (s != FS_STATUS_OK)
        goto out;
    if (fs1 != fs2) {
        s = FS_STATUS_XDEV;
        goto out;
    }
    if (fs1->ro) {
        s = FS_STATUS_READONLY;
        goto out;
    }
    /* fs1 may have been unlocked in the process of resolving path2, so check (now that the
     * filesystem is locked again) whether previously found tuples are still valid. */
    if (!table_find(fs1->files, n1) || !table_find(fs1->files, parent1)) {
        s = FS_STATUS_NOENT;
        goto out;
    }

    if ((parent1 == parent2) && (n1 == n2))
        goto out;
    if (file_tuple_is_ancestor(n1, n2, parent2) || file_tuple_is_ancestor(n2, n1, parent1)) {
        s = FS_STATUS_INVAL;
        goto out;
    }
    s = fs_set_dir_entry(fs1, parent1, sym_this(filename_from_path(path1)), n2);
    if (s == FS_STATUS_OK)
        s = fs_set_dir_entry(fs2, parent2, sym_this(filename_from_path(path2)), n1);
  out:
    filesystem_unlock(fs_to_unlock);
    filesystem_release(fs1);
    if (fs2)
        filesystem_release(fs2);
    return s;
}

void filesystem_log_rebuild(filesystem fs, log new_tl, status_handler sh)
{
    tfs_debug("%s(%F)\n", __func__, sh);
    cleanup_directory(fs->root);
    boolean ok = log_write(new_tl, fs->root);
    fixup_directory(fs->root, fs->root);
    if (ok) {
        fs->temp_log = new_tl;
        log_flush(new_tl, sh);
    } else {
        filesystem_unlock(fs);
        apply(sh, timm("result", "failed to write log"));
        filesystem_lock(fs);
    }
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
        msg_err("failed to purge page cache node: %v\n", s);
        timm_dealloc(s);
    }
    fsfile f = bound(f);
    deallocate_fsfile(f->fs, f, stack_closure(free_extent, f->fs));
}

closure_function(1, 0, void, free_extents,
                 fsfile, f)
{
    fsfile f = bound(f);
    pagecache_purge_node(f->cache_node, init_closure(&f->sync_complete, fsf_sync_complete, f));
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
    f->status = 0;

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
    if (is_ok(s)) {
        if (enumerate_dir_entries(fs, fs->root)) {
#ifndef TFS_READ_ONLY
            fixup_directory(fs->root, fs->root);
#endif
        } else {
            s = timm("result", "failed to enumerate directory entries");
        }
    }
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
                       storage_req_handler req_handler,
                       boolean ro,
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
    fs->req_handler = req_handler;
    fs->root = 0;
    fs->page_order = pagecache_get_page_order();
    fs->size = size;
    assert((blocksize & (blocksize - 1)) == 0);
    fs->blocksize_order = find_order(blocksize);
    fs->pv = pagecache_allocate_volume(size, fs->blocksize_order);
    assert(fs->pv != INVALID_ADDRESS);
#ifndef TFS_READ_ONLY
    fs->storage = allocate_rangemap(h);
    assert(fs->storage != INVALID_ADDRESS);
    fs_storage_lock_init(fs);
    fs->temp_log = 0;
    init_refcount(&fs->refcount, 1, init_closure(&fs->sync, fs_sync, fs));
    fs->sync_complete = 0;
    filesystem_lock_init(fs);
#else
    fs->storage = 0;
#endif
    fs->ro = ro;
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

closure_function(1, 1, boolean, fs_storage_destroy,
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
    log_destroy(fs->tl);
    table_foreach(fs->files, k, v) {
        fs_notify_release(k, true);
        if (v != INVALID_ADDRESS)
            deallocate_fsfile(fs, v, stack_closure(dealloc_extent_node, fs));
    }
    if (fs->root)
        destruct_dir_entry(fs->root);
    pagecache_dealloc_volume(fs->pv);
    deallocate_table(fs->files);
    deallocate_rangemap(fs->storage, stack_closure(fs_storage_destroy, fs->h));
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

boolean filesystem_is_readonly(filesystem fs)
{
    return fs->ro;
}

void filesystem_set_readonly(filesystem fs)
{
    fs->ro = true;
}

u64 fs_blocksize(filesystem fs)
{
    return U64_FROM_BIT(fs->blocksize_order);
}

u64 fs_totalblocks(filesystem fs)
{
    return fs->size >> fs->blocksize_order;
}

closure_function(1, 1, boolean, fs_storage_usedblocks,
                 u64 *, used_blocks,
                 rmnode, n)
{
    *bound(used_blocks) += range_span(n->r);
    return true;
}

u64 fs_usedblocks(filesystem fs)
{
    u64 used_blocks = 0;
    fs_storage_lock(fs);
    rangemap_range_lookup(fs->storage, irange(0, fs->size >> fs->blocksize_order),
                          stack_closure(fs_storage_usedblocks, &used_blocks));
    fs_storage_unlock(fs);
    return used_blocks;
}

u64 fs_freeblocks(filesystem fs)
{
    return fs_totalblocks(fs) - fs_usedblocks(fs);
}

BSS_RO_AFTER_INIT static struct {
    filesystem (*get_root_fs)();    /* return filesystem at "/" */
    inode (*get_mountpoint)(tuple, filesystem *);   /* find mount point and parent filesystem */
} fs_path_helper;

void fs_set_path_helper(filesystem (*get_root_fs)(), inode (*get_mountpoint)(tuple, filesystem *))
{
    assert(get_root_fs);
    fs_path_helper.get_root_fs = get_root_fs;
    fs_path_helper.get_mountpoint = get_mountpoint;
}

/* Requires that a mount point does not change while at least one of its two filesystems (parent and
 * child) is locked. */
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
                filesystem_reserve(child_fs);
                filesystem_unlock(*fs);
                filesystem_release(*fs);
                filesystem_lock(child_fs);
                t = child_fs->root;
                *fs = child_fs;
            }
        } else if ((t == *p) && (a == sym_this("..")) &&
                   (t != filesystem_getroot(fs_path_helper.get_root_fs()))) {
            /* t is the root of its filesystem: look for a mount point for this
             * filesystem, and if found look up the parent of the mount directory.
             */
            filesystem parent_fs;
            inode n = fs_path_helper.get_mountpoint(t, &parent_fs);
            if (!n)
                return t;
            filesystem_reserve(parent_fs);
            filesystem_unlock(*fs);
            filesystem_release(*fs);
            filesystem_lock(parent_fs);
            tuple mp = fs_tuple_from_inode(parent_fs, n);
            *fs = parent_fs;
            if (mp) {
                *p = mp;
                t = lookup(mp, a);
            } else {
                /* The mount directory in the parent filesystem has disappeared before the
                 * filesystem could be locked. */
                t = 0;
            }
        }
    }
    return t;
}

/* Called with the filesystem pointed to by 'fs' locked.
 * If the file path being resolved crosses a filesystem boundary (i.e. a mount
 * point), the current filesystem is unlocked, the new filesystem is locked, and the 'fs' argument
 * is updated to point to the new filesystem.
 * The refcount of the filesystem returned via the 'fs' pointer is incremented. */
// fused buffer wrap, split, and resolve
int filesystem_resolve_cstring(filesystem *fs, tuple cwd, const char *f, tuple *entry,
                    tuple *parent)
{
    assert(fs_path_helper.get_root_fs);
    assert(f);

    tuple t;
    if (*f == '/') {
        filesystem root_fs = fs_path_helper.get_root_fs();
        filesystem_reserve(root_fs);
        if (root_fs != *fs) {
            filesystem_unlock(*fs);
            *fs = root_fs;
            filesystem_lock(*fs);
        }
        t = filesystem_getroot(root_fs);
    } else {
        filesystem_reserve(*fs);
        t = cwd;
    }
    tuple p = t;
    buffer a = little_stack_buffer(NAME_MAX);
    char y;
    int nbytes;
    int err;

    if (*f == '\0') /* an empty path should result in FS_STATUS_NOENT */
        t = 0;
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

/* Same as filesystem_resolve_cstring(), but if the path resolves to a symbolic link, the link is
 * followed. */
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
        filesystem prev = *fs;
        int ret = filesystem_resolve_cstring(fs, parent, cstring(target_b, buf), &target_t,
                &parent);
        filesystem_release(prev);
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

#ifdef KERNEL

fs_status filesystem_mk_socket(filesystem *fs, inode cwd, const char *path, void *s, inode *n)
{
    tuple cwd_t = filesystem_get_meta(*fs, cwd);
    if (!cwd_t)
        return FS_STATUS_NOENT;
    tuple sock, parent;
    fs_status fss = filesystem_resolve_cstring(fs, cwd_t, path, &sock, &parent);
    if (fss == FS_STATUS_OK) {
        fss = FS_STATUS_EXIST;
        goto out;
    }
    if ((fss != FS_STATUS_NOENT) || !parent)
        goto out;
    sock = allocate_tuple();
    if (sock == INVALID_ADDRESS) {
        fss = FS_STATUS_NOMEM;
        goto out;
    }
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
        goto out;
    }
  err:
    destruct_dir_entry(sock);
  out:
    filesystem_unlock(*fs);
    filesystem_release(*fs);
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
        goto out;
    if (!get(t, sym(socket)) || !(sock_handle = get(t, sym(handle)))) {
        fss = FS_STATUS_INVAL;
        goto out;
    }
    buffer b = get(sock_handle, sym(value));    // XXX untyped binary
    if (!b || (buffer_length(b) != sizeof(*s))) {
        fss = FS_STATUS_INVAL;
        goto out;
    }
    *n = t;
    *s = pointer_from_u64(*((u64 *)buffer_ref(b, 0)));
    return FS_STATUS_OK;
  out:
    filesystem_unlock(*fs);
    filesystem_release(*fs);
    return fss;
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
        filesystem_unlock(fs);
    } else {
        fss = FS_STATUS_NOENT;
    }
    filesystem_release(fs);
    return fss;
}

fs_status filesystem_mount(filesystem parent, inode mount_dir, filesystem child)
{
    spin_lock_2(&parent->lock, &child->lock);
    tuple mount_dir_t = fs_tuple_from_inode(parent, mount_dir);
    fs_status fss;
    if (!mount_dir_t) {
        fss = FS_STATUS_NOENT;
        goto out;
    }
    tuple mount = allocate_tuple();
    if (mount == INVALID_ADDRESS) {
        fss = FS_STATUS_NOMEM;
        goto out;
    }
    buffer b = allocate_buffer(parent->h, sizeof(u64));
    if (b == INVALID_ADDRESS) {
        deallocate_value(mount);
        fss = FS_STATUS_NOMEM;
        goto out;
    }
    buffer_write_le64(b, u64_from_pointer(child));
    set(mount, sym(fs), b);
    set(mount, sym(no_encode), null_value); /* non-persistent entry */
    set(mount_dir_t, sym(mount), mount);
    fss = FS_STATUS_OK;
  out:
    filesystem_unlock(child);
    filesystem_unlock(parent);
    return fss;
}

void filesystem_unmount(filesystem parent, inode mount_dir, filesystem child, thunk complete)
{
    spin_lock_2(&parent->lock, &child->lock);
    tuple mount_dir_t = fs_tuple_from_inode(parent, mount_dir);
    if (mount_dir_t) {
        tuple mount = get_tuple(mount_dir_t, sym(mount));
        set(mount_dir_t, sym(mount), 0);
        destruct_tuple(mount, true);
    }
    child->sync_complete = complete;
    filesystem_unlock(child);
    filesystem_unlock(parent);
    filesystem_release(child);
}

#endif

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
    filesystem_reserve(fs);
    int rv;
    tuple c ;
    buf[0] = '\0';
    int cur_len = 1;
    tuple p;
    do {
        n = lookup_follow(&fs, n, sym_this(".."), &p);
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
        if (!c) {
            rv = cur_len;
            goto out;
        }

        iterate(c, stack_closure(file_get_path_each, p, buf, len, &cur_len));
    } while (cur_len > 0);
    rv = -1;
  out:
    filesystem_unlock(fs);
    filesystem_release(fs);
    return rv;
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
