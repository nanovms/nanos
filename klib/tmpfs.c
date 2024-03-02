#include <kernel.h>
#include <pagecache.h>
#include <fs.h>
#include <storage.h>
#include <tmpfs.h>

typedef struct tmpfs_file {
    struct fsfile f;
    struct rangemap dirty;
    closure_struct(sg_io, read);
    closure_struct(sg_io, write);
    closure_struct(pagecache_node_reserve, reserve);
    closure_struct(thunk, free);
} *tmpfs_file;

static fs_status tmpfs_get_fsfile(filesystem fs, tuple n, fsfile *f)
{
    return fs_get_fsfile(((tmpfs)fs)->files, n, f);
}

static tuple tmpfs_get_meta(filesystem fs, inode n)
{
    return fs_tuple_from_inode(((tmpfs)fs)->files, n);
}

closure_func_basic(sg_io, void, tmpfsfile_read,
                   sg_list sg, range q, status_handler complete)
{
    sg_zero_fill(sg, range_span(q));
    apply(complete, STATUS_OK);
}

closure_function(2, 1, boolean, tmpfsfile_write_handler,
                 rangemap, dirty, pagecache_node, pn,
                 range r)
{
    if (rangemap_insert_range(bound(dirty), r)) {
        /* Pin the pages so that they cannot be evicted from the page cache. */
        pagecache_nodelocked_pin(bound(pn), r);

        return false;   /* abort the search, since the range map has been modified */
    }
    return true;
}

closure_func_basic(sg_io, void, tmpfsfile_write,
                   sg_list sg, range q, status_handler complete)
{
    tmpfs_file fsf = struct_from_field(closure_self(), tmpfs_file, write);
    tmpfs fs = (tmpfs)fsf->f.fs;
    range pages = range_rshift_pad(q, fs->page_order);
    int res;
    filesystem_lock(&fs->fs);
    do {
        res = rangemap_range_find_gaps(&fsf->dirty, pages,
                                       stack_closure(tmpfsfile_write_handler, &fsf->dirty,
                                                     fsf->f.cache_node));
    } while (res == RM_ABORT);
    filesystem_unlock(&fs->fs);

    /* If there are still gaps in the range map (res == RM_MATCH), it means a range could not be
     * inserted, i.e we are out of memory. */
    async_apply_status_handler(complete, (res == RM_NOMATCH) ? STATUS_OK : timm_oom);
}

closure_func_basic(pagecache_node_reserve, status, tmpfsfile_reserve,
                   range q)
{
    tmpfs_file fsf = struct_from_field(closure_self(), tmpfs_file, reserve);
    if (fsfile_get_length(&fsf->f) < q.end) {
        fs_status fss = filesystem_truncate(fsf->f.fs, &fsf->f, q.end);
        if (fss != FS_STATUS_OK) {
            status s = timm("result", "failed to update file length");
            return timm_append(s, "fsstatus", "%d", fss);
        }
    }
    return STATUS_OK;
}

closure_function(1, 1, boolean, tmpfs_dirty_destruct,
                 heap, h,
                 rmnode n)
{
    deallocate(bound(h), n, sizeof(*n));
    return false;
}

closure_func_basic(status_handler, void, tmpfsfile_sync_complete,
                   status s)
{
    if (!is_ok(s))  /* any error during node purge is innocuous */
        timm_dealloc(s);
    fsfile f = struct_from_closure(fsfile, sync_complete);
    tmpfs_file fsf = (tmpfs_file)f;
    pagecache_node pn = f->cache_node;
    rangemap dirty = &fsf->dirty;
    rangemap_foreach(dirty, n) {
        pagecache_node_unpin(pn, n->r);
    }
    destruct_rangemap(dirty, stack_closure(tmpfs_dirty_destruct, dirty->h));
    pagecache_deallocate_node(pn);
    deallocate(f->fs->h, fsf, sizeof(*fsf));
}

closure_func_basic(thunk, void, tmpfsfile_free)
{
    tmpfs_file fsf = struct_from_field(closure_self(), tmpfs_file, free);
    pagecache_node pn = fsf->f.cache_node;
    pagecache_purge_node(pn,
                         init_closure_func(&fsf->f.sync_complete, status_handler,
                                           tmpfsfile_sync_complete));
}

static s64 tmpfsfile_get_blocks(fsfile f)
{
    s64 pages = 0;
    rangemap_foreach(&((tmpfs_file)f)->dirty, n) {
        pages += range_span(n->r);
    }
    return (pages << ((tmpfs)f->fs)->page_order) >> SECTOR_OFFSET;
}

static fs_status tmpfs_create(filesystem fs, tuple parent, string name, tuple md, fsfile *f)
{
    tmpfs tmpfs = (struct tmpfs *)fs;
    tmpfs_file fsf;
    fs_status fss;
    if (!md || is_regular(md)) {
        heap h = fs->h;
        fsf = allocate(h, sizeof(*fsf));
        if (fsf == INVALID_ADDRESS)
            return FS_STATUS_NOMEM;
        fss = fsfile_init(fs, &fsf->f, md, init_closure_func(&fsf->read, sg_io, tmpfsfile_read),
                          init_closure_func(&fsf->write, sg_io, tmpfsfile_write),
                          init_closure_func(&fsf->reserve, pagecache_node_reserve,
                                            tmpfsfile_reserve),
                          init_closure_func(&fsf->free, thunk, tmpfsfile_free));
        if (fss != FS_STATUS_OK) {
            deallocate(h, fsf, sizeof(*fsf));
            return fss;
        }
        init_rangemap(&fsf->dirty, h);
        fsf->f.get_blocks = tmpfsfile_get_blocks;
        if (f)
            *f = &fsf->f;
        if (parent && name && md)
            fsfile_reserve(&fsf->f);
    } else {
        fsf = INVALID_ADDRESS;
    }
    if (md)
        table_set(tmpfs->files, md, fsf);
    return fss;
}

static fs_status tmpfs_unlink(filesystem fs, tuple parent, string name, tuple md,
                            boolean *destruct_md)
{
    fs_unlink(((tmpfs)fs)->files, md);
    *destruct_md = true;
    return FS_STATUS_OK;
}

static fs_status tmpfs_rename(filesystem fs, tuple old_parent, string old_name, tuple old_md,
                              tuple new_parent, string new_name, tuple new_md, boolean exchange,
                              boolean *destruct_md)
{
    fs_status s = fs_check_rename(old_parent, old_md, new_parent, new_md, exchange);
    if ((s == FS_STATUS_OK) && !exchange && new_md) {
        fs_unlink(((tmpfs)fs)->files, new_md);
        *destruct_md = true;
    }
    return s;
}

static fs_status tmpfs_truncate(filesystem fs, fsfile f, u64 len)
{
    return FS_STATUS_OK;
}

static u64 tmpfs_freeblocks(filesystem fs)
{
    return 0;
}

static status_handler tmpfs_get_sync_handler(filesystem fs, fsfile fsf, boolean datasync,
                                             status_handler completion)
{
    return completion;
}

filesystem tmpfs_new(void)
{
    heap h = heap_locked(get_kernel_heaps());
    tmpfs fs = allocate(h, sizeof(*fs));
    if (fs == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    status s = filesystem_init(&fs->fs, h, 0, 1, false);
    if (!is_ok(s)) {
        msg_err("%v\n", s);
        timm_dealloc(s);
        goto err_fsinit;
    }
    fs->files = allocate_table(h, identity_key, pointer_equal);
    if (fs->files == INVALID_ADDRESS)
        goto err_filetable;
    fs->page_order = pagecache_get_page_order();
    tuple root = allocate_tuple();
    set(root, sym(children), allocate_tuple());
    set(root, sym_this(".."), root);
    fs->fs.root = root;
    fs->fs.lookup = fs_lookup;
    fs->fs.get_fsfile = tmpfs_get_fsfile;
    fs->fs.get_inode = fs_get_inode;
    fs->fs.get_meta = tmpfs_get_meta;
    fs->fs.create = tmpfs_create;
    fs->fs.unlink = tmpfs_unlink;
    fs->fs.rename = tmpfs_rename;
    fs->fs.truncate = tmpfs_truncate;
    fs->fs.get_freeblocks = tmpfs_freeblocks;
    fs->fs.get_sync_handler = tmpfs_get_sync_handler;
    return &fs->fs;
  err_filetable:
    filesystem_deinit(&fs->fs);
  err_fsinit:
    deallocate(h, fs, sizeof(*fs));
    return INVALID_ADDRESS;
}

int init(status_handler complete)
{
    return KLIB_INIT_OK;
}
