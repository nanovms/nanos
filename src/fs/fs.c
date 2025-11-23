#ifdef KERNEL
#include <kernel.h>
#include <dma.h>
#include <pagecache.h>
#else
#include <runtime.h>
#endif
#include <errno.h>
#include <fs.h>

//#define FS_DEBUG
//#define FS_REPORT_SHA256
#if defined(FS_DEBUG)
#ifdef KERNEL
#define fs_debug(x, ...)    do {tprintf(sym(fs), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define fs_debug(x, ...)    do {rprintf("FS: " x, ##__VA_ARGS__);} while(0)
#endif
#else
#define fs_debug(x, ...)
#endif

#ifdef BOOT
#define FS_READ_ONLY
#endif

#if defined(FS_REPORT_SHA256) && !defined(BOOT)
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

u64 fsfile_get_length(fsfile f)
{
    return f->length;
}

void fsfile_set_length(fsfile f, u64 length)
{
    f->length = length;
#ifdef KERNEL
    pagecache_set_node_length(f->cache_node, length);
#endif
}

sg_io fsfile_get_reader(fsfile f)
{
    return f->read;
}

sg_io fsfile_get_writer(fsfile f)
{
    return f->write;
}

#ifdef KERNEL
pagecache_node fsfile_get_cachenode(fsfile f)
{
    return f->cache_node;
}
#endif

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
    value time_val = get(t, s);
    if (time_val) {
        u64_from_value(time_val, &cur_time);
    }
    if (tim != cur_time) {
        if (time_val) {
            deallocate_value(time_val);
        }
        time_val = value_from_u64(tim);
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
    value rdev_val = value_from_u64(rdev);
    set(t, sym(rdev), rdev_val);
}

closure_function(7, 1, void, filesystem_read_complete,
                 filesystem, fs, void *, dest, range, q, void *, head_buf, void *, tail_buf, io_status_handler, io_complete, sg_list, sg,
                 status s)
{
    fs_debug("%s: dest %p, status %v\n", func_ss, bound(dest), s);
    range q = bound(q);
    u64 count = range_span(q);
    if (is_ok(s)) {
        filesystem fs = bound(fs);
        u64 block_size = fs_blocksize(fs);
        heap h = fs->h;
        void *dest = bound(dest);
        void *head_buf = bound(head_buf);
        if (head_buf) {
            u64 head_len = block_size - (q.start & (block_size - 1));
            runtime_memcpy(dest, head_buf + block_size - head_len, MIN(head_len, count));
            deallocate(h, head_buf, block_size);
        }
        void *tail_buf = bound(tail_buf);
        if (tail_buf) {
            u64 tail_len = q.end & (block_size - 1);
            runtime_memcpy(dest + count - tail_len, tail_buf, tail_len);
            deallocate(h, tail_buf, block_size);
        }
    }
    deallocate_sg_list(bound(sg));
    apply(bound(io_complete), s, count);
    closure_finish();
}

void filesystem_read_linear(fsfile f, void *dest, range q, io_status_handler io_complete)
{
    sg_list sg = sg_new(3);
    if (sg == INVALID_ADDRESS) {
        status s = timm("result", "failed to allocate sg list");
        apply(io_complete, timm_append(s,
                                "fsstatus", "%d", -ENOMEM), 0);
        return;
    }
    filesystem fs = f->fs;
    u64 block_size = fs_blocksize(fs);
    range padded_q = q;
    heap h = fs->h;
    u64 head_len = block_size - (q.start & (block_size - 1));
    void *head_buf;
    if (head_len == block_size) {
        head_len = 0;
        head_buf = 0;
    } else {
        head_buf = allocate(h, block_size);
        if (head_buf == INVALID_ADDRESS)
            goto err_nomem;
        sg_buf sgb = sg_list_tail_add(sg, block_size);
        sgb->buf = head_buf;
        sgb->size = block_size;
        sgb->offset = 0;
        sgb->refcount = 0;
        padded_q.start -= block_size - head_len;
        if (padded_q.end < padded_q.start + block_size)
            padded_q.end = padded_q.start + block_size;
    }
    u64 tail_len = padded_q.end & (block_size - 1);
    s64 trimmed_len = range_span(q) - head_len - tail_len;
    if (trimmed_len > 0) {
        sg_buf sgb = sg_list_tail_add(sg, trimmed_len);
        sgb->buf = dest + head_len;
        sgb->size = trimmed_len;
        sgb->offset = 0;
        sgb->refcount = 0;
    }
    void *tail_buf;
    if (tail_len) {
        tail_buf = allocate(h, block_size);
        if (tail_buf == INVALID_ADDRESS) {
            if (head_buf)
                deallocate(h, head_buf, block_size);
            goto err_nomem;
        }
        sg_buf sgb = sg_list_tail_add(sg, block_size);
        sgb->buf = tail_buf;
        sgb->size = block_size;
        sgb->offset = 0;
        sgb->refcount = 0;
        padded_q.end += block_size - tail_len;
    } else {
        tail_buf = 0;
    }
    filesystem_read_sg(f, sg, padded_q, closure(f->fs->h, filesystem_read_complete, fs, dest, q,
                                                head_buf, tail_buf, io_complete, sg));
    return;
  err_nomem:
    deallocate_sg_list(sg);
    apply(io_complete, timm("result", "out of memory"), 0);
}

closure_function(5, 1, void, read_entire_complete,
                 sg_list, sg, buffer_handler, bh, buffer, b, fsfile, f, status_handler, sh,
                 status s)
{
    buffer b = bound(b);
    fs_debug("read_entire_complete: status %v, addr %p\n", s, buffer_end(b));
    fsfile f = bound(f);
    sg_list sg = bound(sg);
    if (is_ok(s)) {
        buffer_produce(b, fsfile_get_length(f));
        report_sha256(b);
        apply(bound(bh), b);
    } else {
        deallocate_buffer(b);
        apply(bound(sh), s);
    }
    deallocate_sg_list(sg);
    closure_finish();
    fsfile_release(f);
}

void filesystem_read_entire(filesystem fs, tuple t, heap bufheap, buffer_handler c, status_handler sh)
{
    fs_debug("filesystem_read_entire: t %p, bufheap %p, buffer_handler %p, status_handler %p\n",
             t, bufheap, c, sh);
    fsfile f;
    int fss = fs->get_fsfile(fs, t, &f);
    status s;
    if ((fss != 0) || !f) {
        s = timm("result", "no such file %v", t);
        apply(sh, timm_append(s,
                       "fsstatus", "%d", fss));
        return;
    }

    u64 length = fsfile_get_length(f);
    u64 padded_len = pad(length, fs_blocksize(f->fs));
    buffer b = allocate_buffer(bufheap, padded_len);
    if (b == INVALID_ADDRESS)
        goto alloc_fail;

    sg_list sg = sg_new(1);
    if (sg == INVALID_ADDRESS) {
        deallocate_buffer(b);
        goto alloc_fail;
    }
    sg_buf sgb = sg_list_tail_add(sg, padded_len);
    sgb->buf = buffer_ref(b, 0);
    sgb->size = padded_len;
    sgb->offset = 0;
    sgb->refcount = 0;
    filesystem_read_sg(f, sg, irange(0, length),
                      closure(fs->h, read_entire_complete, sg, c, b, f, sh));
    return;
  alloc_fail:
    s = timm("result", "allocation failure");
    apply(sh, timm_append(s,
                   "fsstatus", "%d", -ENOMEM));
    return;
}

#ifndef FS_READ_ONLY

int filesystem_truncate_locked(filesystem fs, fsfile f, u64 len)
{
    if (fs->ro)
        return -EROFS;
    int fsf = fs->truncate(fs, f, len);
    if (fsf == 0) {
        tuple md = f->md;
        if (md)
            filesystem_update_mtime(fs, md);
        fsfile_set_length(f, len);
    }
    return fsf;
}

closure_function(5, 1, void, filesystem_write_complete,
                 filesystem, fs, sg_list, sg, u64, length, void *, tail_buf, io_status_handler, io_complete,
                 status s)
{
    deallocate_sg_list(bound(sg));
    void *tail_buf = bound(tail_buf);
    if (tail_buf) {
        filesystem fs = bound(fs);
        deallocate(fs->h, tail_buf, fs_blocksize(fs));
    }
    apply(bound(io_complete), s, bound(length));
    closure_finish();
}

void filesystem_write_linear(fsfile f, void *src, range q, io_status_handler io_complete)
{
    u64 length = range_span(q);
    if (length == 0) {
        apply(io_complete, STATUS_OK, length);
        return;
    }
    filesystem fs = f->fs;
    u64 block_size = fs_blocksize(fs);
    assert((q.start & (block_size - 1)) == 0);
    sg_list sg = sg_new(2);
    if (sg == INVALID_ADDRESS) {
        status s = timm("result", "failed to allocate sg list");
        apply(io_complete, timm_append(s,
                                "fsstatus", "%d", -ENOMEM), 0);
        return;
    }
    u64 tail_len = length & (block_size - 1);
    sg_buf sgb = sg_list_tail_add(sg, length - tail_len);
    sgb->buf = src;
    sgb->size = length - tail_len;
    sgb->offset = 0;
    sgb->refcount = 0;
    void *tail_buf;
    if (tail_len) {
        tail_buf = allocate(fs->h, block_size);
        if (tail_buf == INVALID_ADDRESS) {
            deallocate_sg_list(sg);
            apply(io_complete, timm("result", "failed to allocate tail buffer"), 0);
            return;
        }
        sgb = sg_list_tail_add(sg, block_size);
        runtime_memcpy(tail_buf, src + length - tail_len, tail_len);
        zero(tail_buf + tail_len, block_size - tail_len);
        sgb->buf = tail_buf;
        sgb->size = block_size;
        sgb->offset = 0;
        sgb->refcount = 0;
    } else {
        tail_buf = 0;
    }
    filesystem_write_sg(f, sg, q, closure(fs->h, filesystem_write_complete,
                                          fs, sg, length, tail_buf, io_complete));
}

int filesystem_truncate(filesystem fs, fsfile f, u64 len)
{
    filesystem_lock(fs);
    int fss = filesystem_truncate_locked(fs, f, len);
    filesystem_unlock(fs);
    return fss;
}

void filesystem_flush(filesystem fs, status_handler completion)
{
    status_handler sh = fs->get_sync_handler(fs, 0, false, completion);
    if (sh == INVALID_ADDRESS) {
        apply(completion, timm("result", "failed to allocate closure"));
        return;
    }
#ifdef KERNEL
    pagecache_sync_volume(fs->pv, sh);
#else
    apply(sh, STATUS_OK);
#endif
}

void fsfile_flush(fsfile fsf, boolean datasync, status_handler completion)
{
    filesystem fs = fsf->fs;
    status_handler sh = fs->get_sync_handler(fs, fsf, datasync, completion);
    if (sh == INVALID_ADDRESS) {
        apply(completion, timm("result", "failed to allocate closure"));
        return;
    }
    if (datasync)
        fsf->status &= ~FSF_DIRTY_DATASYNC;
    else
        fsf->status &= ~FSF_DIRTY;
#ifdef KERNEL
    pagecache_sync_node(fsf->cache_node, sh);
#else
    apply(sh, STATUS_OK);
#endif
}

void filesystem_reserve(filesystem fs)
{
    refcount_reserve(&fs->refcount);
}

void filesystem_release(filesystem fs)
{
    refcount_release(&fs->refcount);
}

static void fsdir_set_parent(tuple n, tuple parent)
{
    if (is_dir(n))
        set(n, sym(..), parent);
}

closure_func_basic(status_handler, void, fs_free,
                   status s)
{
    if (!is_ok(s)) {
        msg_warn("filesystem failed to flush: %v", s);
        timm_dealloc(s);
    }
    filesystem fs = struct_from_closure(filesystem, free);
    if (fs->sync_complete)
        apply(fs->sync_complete);
    fs->destroy_fs(fs);
}

closure_func_basic(thunk, void, fs_sync)
{
    filesystem fs = struct_from_closure(filesystem, sync);
    filesystem_flush(fs, init_closure_func(&fs->free, status_handler, fs_free));
}

tuple fs_new_entry(filesystem fs)
{
    tuple t = allocate_tuple();
    assert(t);
    timestamp tim = now(CLOCK_ID_REALTIME);
    filesystem_set_atime(fs, t, tim);
    filesystem_set_mtime(fs, t, tim);
    return t;
}

static int fs_create_dir_entry(filesystem fs, tuple parent, string name, tuple md, fsfile *f)
{
    if (fs->ro)
        return -EROFS;
    int s = fs->create(fs, parent, name, md, f);
    if (s == 0) {
        symbol name_sym = intern(name);
        set(children(parent), name_sym, md);
        fsdir_set_parent(md, parent);
        filesystem_update_mtime(fs, parent);
        fs_notify_create(md, parent, name_sym);
    }
    return s;
}

closure_function(1, 2, boolean, file_unlink_each,
                 tuple, t,
                 value k, value v)
{
    if (is_tuple(v) && get(v, sym(no_encode))) {
        destruct_value(v, true);
        set(bound(t), k, 0);
    }
    return true;
}

static void file_unlink(tuple t, boolean destruct_md)
{
    fs_notify_release(t, false);
    set(t, sym_this(".."), 0);
    if (destruct_md)
        destruct_value(t, true);
    else
        iterate(t, stack_closure(file_unlink_each, t));
}

int filesystem_mkdir(filesystem fs, inode cwd, sstring path)
{
    tuple cwd_t = filesystem_get_meta(fs, cwd);
    if (!cwd_t)
        return -ENOENT;
    tuple parent;
    int fss = filesystem_resolve_sstring(&fs, cwd_t, path, 0, &parent);
    if ((fss != -ENOENT) || !parent) {
        if (fss == 0)
            fss = -EEXIST;
        goto out;
    }
    buffer name = little_stack_buffer(NAME_MAX + 1);
    if (!dirname_from_path(name, path)) {
        fss = -ENAMETOOLONG;
        goto out;
    }
    tuple dir = fs_new_entry(fs);
    set(dir, sym(children), allocate_tuple());
    fss = fs_create_dir_entry(fs, parent, name, dir, 0);
    if (fss != 0)
        destruct_value(dir, true);
  out:
    filesystem_unlock(fs);
    filesystem_release(fs);
    return fss;
}

int filesystem_get_node(filesystem *fs, inode cwd, sstring path, u8 flags, tuple *n,
                        tuple *parent_n,
                              fsfile *f)
{
    tuple cwd_t = filesystem_get_meta(*fs, cwd);
    if (!cwd_t)
        return -ENOENT;
    tuple parent, t;
    fsfile fsf = 0;
    int fss;
    if (!(flags & FS_NODE_FOLLOW))
        fss = filesystem_resolve_sstring(fs, cwd_t, path, &t, &parent);
    else
        fss = filesystem_resolve_sstring_follow(fs, cwd_t, path, &t, &parent);
    if (fss == -ENOENT) {
        if (flags & FS_NODE_CREATE) {
            if (!parent)
                goto out;
            t = fs_new_entry(*fs);
            buffer name = alloca_wrap_sstring(filename_from_path(path));
            fss = fs_create_dir_entry(*fs, parent, name, t, f);
            if (fss != 0)
                destruct_value(t, true);
        }
    } else if (fss == 0) {
        if (flags & FS_NODE_EXCL) {
            fss = -EEXIST;
        } else if (is_regular(t) && (f || (flags & FS_NODE_TRUNC))) {
            fss = (*fs)->get_fsfile(*fs, t, &fsf);
            if ((fss == 0) && fsf) {
                if (flags & FS_NODE_TRUNC)
                    fss = filesystem_truncate_locked(*fs, fsf, 0);
                if (!f || (fss != 0))
                    fsfile_release(fsf);
            }
        }
        if (f && (fss == 0))
            *f = fsf;
    }
  out:
    if (fss == 0) {
        *n = t;
        if (parent_n)
          *parent_n = parent;
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
    tuple t = fs->get_meta(fs, n);
    if (!t)
        filesystem_unlock(fs);
    return t;
}

void filesystem_put_meta(filesystem fs, tuple n)
{
    filesystem_unlock(fs);
}

/* Called with fs locked. */
int filesystem_creat_unnamed(filesystem fs, fsfile *f)
{
    if (fs->ro)
        return -EROFS;
    return fs->create(fs, 0, 0, 0, f);
}

int filesystem_symlink(filesystem fs, inode cwd, sstring path, sstring target)
{
    int target_len = target.len;
    if (target_len >= PATH_MAX)
        return -ENAMETOOLONG;
    tuple cwd_t = filesystem_get_meta(fs, cwd);
    if (!cwd_t)
        return -ENOENT;
    tuple parent;
    int fss = filesystem_resolve_sstring(&fs, cwd_t, path, 0, &parent);
    if (fss == 0) {
        fss = -EEXIST;
        goto out;
    }
    if ((fss != -ENOENT) || !parent)
        goto out;
    string target_s = allocate_string(target_len);
    if (target_s == INVALID_ADDRESS) {
        fss = -ENOMEM;
        goto out;
    }
    buffer_write_sstring(target_s, target);
    tuple link = fs_new_entry(fs);
    set(link, sym(linktarget), target_s);
    string name = alloca_wrap_sstring(filename_from_path(path));
    fss = fs_create_dir_entry(fs, parent, name, link, 0);
    if (fss != 0)
        destruct_value(link, true);
  out:
    filesystem_unlock(fs);
    filesystem_release(fs);
    return fss;
}

int filesystem_delete(filesystem fs, inode cwd, sstring path, boolean directory)
{
    tuple cwd_t = filesystem_get_meta(fs, cwd);
    if (!cwd_t)
        return -ENOENT;
    tuple parent, t;
    int fss = filesystem_resolve_sstring(&fs, cwd_t, path, &t, &parent);
    if (fss != 0)
        goto out;
    tuple c = children(t);
    if (directory) {
        if (!c) {
            fss = -ENOTDIR;
            goto out;
        }
        boolean notempty = (tuple_count(c) != 0);
        if (notempty) {
            fss = -ENOTEMPTY;
            goto out;
        }
    } else {
        if (c) {
            fss = -EISDIR;
            goto out;
        }
    }
    if (fs->ro) {
        fss = -EROFS;
        goto out;
    }
    string name = alloca_wrap_sstring(filename_from_path(path));
    boolean destruct_md;
    fss = fs->unlink(fs, parent, name, t, &destruct_md);
    if (fss == 0) {
        symbol name_sym = intern(name);
        set(children(parent), name_sym, 0);
        fs_notify_delete(t, parent, name_sym);
        fs_notify_release(t, false);
        file_unlink(t, destruct_md);
    }
  out:
    filesystem_unlock(fs);
    filesystem_release(fs);
    return fss;
}

int filesystem_rename(filesystem oldfs, inode oldwd, sstring oldpath,
                            filesystem newfs, inode newwd, sstring newpath,
                            boolean noreplace)
{
    if (sstring_is_empty(oldpath) || sstring_is_empty(newpath))
        return -ENOENT;
    tuple oldwd_t = filesystem_get_meta(oldfs, oldwd);
    if (!oldwd_t)
        return -ENOENT;
    tuple old, oldparent;
    filesystem fs_to_unlock;
    int s = filesystem_resolve_sstring(&oldfs, oldwd_t, oldpath, &old, &oldparent);
    if (s != 0) {
        fs_to_unlock = oldfs;
        newfs = 0;
        goto out;
    }
    inode old_n = oldfs->get_inode(oldfs, old);
    inode oldparent_n = oldfs->get_inode(oldfs, oldparent);
    if (newfs != oldfs) {
        filesystem_unlock(oldfs);
        filesystem_lock(newfs);
    }
    tuple newwd_t = newfs->get_meta(newfs, newwd);
    if (!newwd_t) {
        s = -ENOENT;
        fs_to_unlock = newfs;
        newfs = 0;
        goto out;
    }
    tuple new, newparent;
    s = filesystem_resolve_sstring(&newfs, newwd_t, newpath, &new, &newparent);
    fs_to_unlock = newfs;
    if ((s != 0) && (s != -ENOENT))
        goto out;
    if (!newparent) {
        s = -ENOENT;
        goto out;
    }
    if (oldfs != newfs) {
        s = -EXDEV;
        goto out;
    }
    if (oldfs->ro) {
        s = -EROFS;
        goto out;
    }
    /* oldfs may have been unlocked in the process of resolving newpath, so check (now that the
     * filesystem is locked again) whether previously found inodes are still valid. */
    old = oldfs->get_meta(oldfs, old_n);
    oldparent = oldfs->get_meta(oldfs, oldparent_n);
    if (!old || !oldparent) {
        s = -ENOENT;
        goto out;
    }

    if ((s == 0) && noreplace) {
        s = -EEXIST;
        goto out;
    }
    if ((newparent == oldparent) && (new == old)) {
        s = 0;
        goto out;
    }
    string oldname = alloca_wrap_sstring(filename_from_path(oldpath));
    symbol old_s = intern(oldname);
    string newname = alloca_wrap_sstring(filename_from_path(newpath));
    symbol new_s = intern(newname);
    boolean destruct_md;
    s = oldfs->rename(oldfs, oldparent, oldname, old, newparent, newname, new, false, &destruct_md);
    if (s == 0) {
        set(children(oldparent), old_s, 0);
        set(children(newparent), new_s, old);
        fsdir_set_parent(old, newparent);
        filesystem_update_mtime(oldfs, oldparent);
        if (newparent != oldparent)
            filesystem_update_mtime(oldfs, newparent);
        fs_notify_move(old, oldparent, old_s, newparent, new_s);
        if (new)
            file_unlink(new, destruct_md);
    }
  out:
    filesystem_unlock(fs_to_unlock);
    filesystem_release(oldfs);
    if (newfs)
        filesystem_release(newfs);
    return s;
}

int filesystem_exchange(filesystem fs1, inode wd1, sstring path1,
                              filesystem fs2, inode wd2, sstring path2)
{
    tuple wd1_t = filesystem_get_meta(fs1, wd1);
    if (!wd1_t)
        return -ENOENT;
    tuple n1, n2;
    tuple parent1, parent2;
    filesystem fs_to_unlock;
    int s = filesystem_resolve_sstring(&fs1, wd1_t, path1, &n1, &parent1);
    if (s != 0) {
        fs_to_unlock = fs1;
        fs2 = 0;
        goto out;
    }
    inode ino1 = fs1->get_inode(fs1, n1);
    inode ino1_parent = fs1->get_inode(fs1, parent1);
    if (fs2 != fs1) {
        filesystem_unlock(fs1);
        filesystem_lock(fs2);
    }
    tuple wd2_t = fs2->get_meta(fs2, wd2);
    if (!wd2_t) {
        s = -ENOENT;
        fs_to_unlock = fs2;
        fs2 = 0;
        goto out;
    }
    s = filesystem_resolve_sstring(&fs2, wd2_t, path2, &n2, &parent2);
    fs_to_unlock = fs2;
    if (s != 0)
        goto out;
    if (fs1 != fs2) {
        s = -EXDEV;
        goto out;
    }
    if (fs1->ro) {
        s = -EROFS;
        goto out;
    }
    /* fs1 may have been unlocked in the process of resolving path2, so check (now that the
     * filesystem is locked again) whether previously found inodes are still valid. */
    n1 = fs1->get_meta(fs1, ino1);
    parent1 = fs1->get_meta(fs1, ino1_parent);
    if (!n1 || !parent1) {
        s = -ENOENT;
        goto out;
    }

    if ((parent1 == parent2) && (n1 == n2))
        goto out;
    string name1 = alloca_wrap_sstring(filename_from_path(path1));
    string name2 = alloca_wrap_sstring(filename_from_path(path2));
    s = fs1->rename(fs1, parent1, name1, n1, parent2, name2, n2, true, 0);
    if (s == 0) {
        set(children(parent1), intern(name1), n2);
        fsdir_set_parent(n2, parent1);
        set(children(parent2), intern(name2), n1);
        fsdir_set_parent(n1, parent2);
        filesystem_update_mtime(fs1, parent1);
        if (parent2 != parent1)
            filesystem_update_mtime(fs1, parent2);
    }
  out:
    filesystem_unlock(fs_to_unlock);
    filesystem_release(fs1);
    if (fs2)
        filesystem_release(fs2);
    return s;
}

#endif /* !FS_READ_ONLY */

#ifndef DMA_BUFFERING
closure_function(2, 3, void, fs_io_func,
                 fs_io, io, fsfile, f,
                 sg_list sg, range r, status_handler completion)
{
    bound(io)(bound(f), sg, r, completion);
}
#endif

int fsfile_init(filesystem fs, fsfile f, tuple md,
#ifdef KERNEL
                      pagecache_node_reserve fs_reserve,
#endif
                      thunk fs_free)
{
    heap h = fs->h;
    sg_io fs_read, fs_write;
#ifdef DMA_BUFFERING
    fs_read = dma_new_reader(h, (sg_io_func)fs->file_read, f);
#else
    fs_read = closure(h, fs_io_func, fs->file_read, f);
#endif
    if (fs_read == INVALID_ADDRESS)
        return -ENOMEM;
#ifndef FS_READ_ONLY
#ifdef DMA_BUFFERING
    fs_write = dma_new_writer(h, (sg_io_func)fs->file_write, f);
#else
    fs_write = closure(h, fs_io_func, fs->file_write, f);
#endif
    if (fs_write == INVALID_ADDRESS) {
        deallocate_closure(fs_read);
        return -ENOMEM;
    }
#else
    fs_write = 0;
#endif
#ifdef KERNEL
    pagecache_node pn = pagecache_allocate_node(fs->pv, fs_read, fs_write, fs_reserve);
    if (pn == INVALID_ADDRESS) {
        deallocate_closure(fs_read);
        deallocate_closure(fs_write);
        return -ENOMEM;
    }
    f->cache_node = pn;
#endif
    f->fs = fs;
    f->md = md;
    f->length = 0;
    f->read = fs_read;
    f->write = fs_write;
    init_refcount(&f->refcount, 1, fs_free);
    f->status = 0;
    return 0;
}

status filesystem_init(filesystem fs, heap h, u64 size, u64 blocksize, boolean ro)
{
    fs->h = h;
    fs->size = size;
    assert((blocksize & (blocksize - 1)) == 0);
    fs->blocksize_order = find_order(blocksize);
#ifdef KERNEL
    fs->pv = pagecache_allocate_volume(size, fs->blocksize_order);
    if (fs->pv == INVALID_ADDRESS)
        return timm("result", "failed to allocate pagacache volume");
#endif
    fs->get_seals = 0;
    fs->set_seals = 0;
#ifndef FS_READ_ONLY
    init_refcount(&fs->refcount, 1, init_closure_func(&fs->sync, thunk, fs_sync));
    fs->sync_complete = 0;
    filesystem_lock_init(fs);
#endif
    fs->ro = ro;
    return STATUS_OK;
}

void filesystem_deinit(filesystem fs)
{
#ifdef KERNEL
    pagecache_dealloc_volume(fs->pv);
#endif
}

int fs_get_fsfile(table files, tuple n, fsfile *f)
{
    fsfile fsf = table_find(files, n);
    if (!fsf)
        return -ENOENT;
    if (fsf == INVALID_ADDRESS) /* non-regular file */
        fsf = 0;
    else
        fsfile_reserve(fsf);
    *f = fsf;
    return 0;
}

void fs_unlink(table files, tuple n)
{
    fsfile fsf = table_remove(files, n);
    if (fsf == INVALID_ADDRESS)   /* directory entry other than regular file */
        fsf = 0;
    if (fsf) {
        fsf->md = 0;
        fsfile_release(fsf);
    }
}

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

u64 fs_usedblocks(filesystem fs)
{
    return fs_totalblocks(fs) - fs_freeblocks(fs);
}

u64 fs_freeblocks(filesystem fs)
{
    return fs->get_freeblocks(fs);
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
static tuple lookup_follow(filesystem *fs, tuple t, string a, tuple *p)
{
    *p = t;
    t = (*fs)->lookup(*fs, t, a);
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

                /* The lookup call below, which should return childfs->root, may be needed by a
                 * filesystem to retrieve up-to-date contents of its root directory. */
                t = child_fs->lookup(child_fs, child_fs->root, alloca_wrap_cstring("."));

                *fs = child_fs;
            }
        } else if ((t == *p) && !buffer_strcmp(a, "..") &&
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
            tuple mp = parent_fs->get_meta(parent_fs, n);
            *fs = parent_fs;
            if (mp) {
                *p = mp;
                t = parent_fs->lookup(parent_fs, mp, a);
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
int filesystem_resolve_sstring(filesystem *fs, tuple cwd, sstring f, tuple *entry,
                    tuple *parent)
{
    assert(fs_path_helper.get_root_fs);

    tuple t;
    if (!sstring_is_empty(f) && (f.ptr[0] == '/')) {
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
    character c;
    int nbytes;
    int err;

    if (sstring_is_empty(f))    /* an empty path should result in -ENOENT */
        t = 0;
    while (!sstring_is_empty(f)) {
        c = utf8_decode(f, &nbytes);
        if (!nbytes) {
            msg_warn("%s: invalid UTF-8 sequence", func_ss);
            err = -ENOENT;
            p = false;
            goto done;
        }
        if (c == '/') {
            if (buffer_length(a)) {
                t = lookup_follow(fs, t, a, &p);
                if (!t) {
                    err = -ENOENT;
                    goto done;
                }
                err = filesystem_follow_links(fs, t, p, &t);
                if (err) {
                    t = false;
                    goto done;
                }
                if (!children(t))
                    return -ENOTDIR;
                buffer_clear(a);
            }
        } else {
            if (!push_character(a, c)) {
                err = -ENAMETOOLONG;
                t = 0;
                goto done;
            }
        }
        f.ptr += nbytes;
        f.len -= nbytes;
    }

    if (buffer_length(a)) {
        if (!children(t))
            return -ENOTDIR;
        t = lookup_follow(fs, t, a, &p);
    }
    err = -ENOENT;
done:
    if (!t && (f.len > 1) && (f.ptr[0] == '/'))
        /* The path being resolved contains entries under a non-existent
         * directory. */
        p = false;
    if (parent)
        *parent = p;
    if (entry)
        *entry = t;
    return (t ? 0 : err);
}

/* Same as filesystem_resolve_sstring(), but if the path resolves to a symbolic link, the link is
 * followed. */
int filesystem_resolve_sstring_follow(filesystem *fs, tuple cwd, sstring f, tuple *entry,
        tuple *parent)
{
    tuple t, p;
    int ret = filesystem_resolve_sstring(fs, cwd, f, &t, &p);
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
    int hop_count = 0;
    while (true) {
        buffer target_b = linktarget(link);
        if (!target_b) {
            *target = link;
            return 0;
        }
        filesystem prev = *fs;
        int ret = filesystem_resolve_sstring(fs, parent, buffer_to_sstring(target_b), &target_t,
                &parent);
        filesystem_release(prev);
        if (ret) {
            return ret;
        }
        if (is_symlink(target_t)) {
            if (hop_count++ == SYMLINK_HOPS_MAX) {
                return -ELOOP;
            }
        }
        link = target_t;
    }
}

#ifdef KERNEL

int filesystem_mk_socket(filesystem *fs, inode cwd, sstring path, void *s, inode *n)
{
    tuple cwd_t = filesystem_get_meta(*fs, cwd);
    if (!cwd_t)
        return -ENOENT;
    tuple sock, parent;
    int fss = filesystem_resolve_sstring(fs, cwd_t, path, &sock, &parent);
    if (fss == 0) {
        fss = -EEXIST;
        goto out;
    }
    if ((fss != -ENOENT) || !parent)
        goto out;
    sock = allocate_tuple();
    if (sock == INVALID_ADDRESS) {
        fss = -ENOMEM;
        goto out;
    }
    tuple sock_handle = allocate_tuple();
    if (sock_handle == INVALID_ADDRESS) {
        fss = -ENOMEM;
        goto err;
    }
    set(sock, sym(handle), sock_handle);
    buffer b = allocate_buffer((*fs)->h, sizeof(u64));
    if (b == INVALID_ADDRESS) {
        fss = -ENOMEM;
        goto err;
    }
    buffer_write_le64(b, u64_from_pointer(s));
    set(sock_handle, sym(value), b);
    set(sock_handle, sym(no_encode), null_value);
    set(sock, sym(socket), null_value);
    string name = alloca_wrap_sstring(filename_from_path(path));
    fss = fs_create_dir_entry(*fs, parent, name, sock, 0);
    if (fss == 0) {
        *n = (*fs)->get_inode(*fs, sock);
        filesystem_reserve(*fs);
        goto out;
    }
  err:
    destruct_value(sock, true);
  out:
    filesystem_unlock(*fs);
    filesystem_release(*fs);
    return fss;
}

int filesystem_get_socket(filesystem *fs, inode cwd, sstring path, tuple *n, void **s)
{
    tuple cwd_t = filesystem_get_meta(*fs, cwd);
    if (!cwd_t)
        return -ENOENT;
    tuple t, sock_handle;
    int fss = filesystem_resolve_sstring(fs, cwd_t, path, &t, 0);
    if (fss != 0)
        goto out;
    if (!get(t, sym(socket)) || !(sock_handle = get(t, sym(handle)))) {
        fss = -EINVAL;
        goto out;
    }
    buffer b = get(sock_handle, sym(value));    // XXX untyped binary
    if (!b || (buffer_length(b) != sizeof(*s))) {
        fss = -EINVAL;
        goto out;
    }
    *n = t;
    *s = pointer_from_u64(*((u64 *)buffer_ref(b, 0)));
    return 0;
  out:
    filesystem_unlock(*fs);
    filesystem_release(*fs);
    return fss;
}

int filesystem_clear_socket(filesystem fs, inode n)
{
    tuple t = filesystem_get_meta(fs, n);
    int fss;
    if (t) {
        tuple sock_handle = get_tuple(t, sym(handle));
        buffer b = get(sock_handle, sym(value));    // XXX untyped binary
        buffer_clear(b);
        fss = 0;
        filesystem_unlock(fs);
    } else {
        fss = -ENOENT;
    }
    filesystem_release(fs);
    return fss;
}

int filesystem_mount(filesystem parent, inode mount_dir, filesystem child)
{
    filesystem_lock(parent);
    tuple mount_dir_t = parent->get_meta(parent, mount_dir);
    int fss;
    if (!mount_dir_t) {
        fss = -ENOENT;
        goto out;
    }
    tuple mount = allocate_tuple();
    if (mount == INVALID_ADDRESS) {
        fss = -ENOMEM;
        goto out;
    }
    buffer b = allocate_buffer(parent->h, sizeof(u64));
    if (b == INVALID_ADDRESS) {
        deallocate_value(mount);
        fss = -ENOMEM;
        goto out;
    }
    buffer_write_le64(b, u64_from_pointer(child));
    set(mount, sym(fs), b);
    set(mount, sym(no_encode), null_value); /* non-persistent entry */
    set(mount_dir_t, sym(mount), mount);
    fss = 0;
  out:
    filesystem_unlock(parent);
    return fss;
}

void filesystem_unmount(filesystem parent, inode mount_dir, filesystem child, thunk complete)
{
    filesystem_lock(parent);
    tuple mount_dir_t = parent->get_meta(parent, mount_dir);
    if (mount_dir_t) {
        tuple mount = get_tuple(mount_dir_t, sym(mount));
        set(mount_dir_t, sym(mount), 0);
        destruct_value(mount, true);
    }
    child->sync_complete = complete;
    filesystem_unlock(parent);
    filesystem_release(child);
}

#endif

boolean dirname_from_path(buffer dest, sstring path)
{
    int pathlen = path.len;
    const char *last_delim = path_find_last_delim(path);
    const char *dirname;
    int len;
    if (!last_delim) {
        dirname = path.ptr;
        len = pathlen;
    } else if (last_delim < path.ptr + pathlen - 1) {
        dirname = last_delim + 1;
        len = pathlen - (dirname - path.ptr);
    } else {    /* The path ends with '/'. */
        path.len--;
        const char *delim = path_find_last_delim(path);
        if (!delim) {
            dirname = path.ptr;
            len = path.len;
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
                 value k, value v)
{
    if (v != bound(p))
        return true;

    string name = symbol_string(k);
    int name_len = buffer_length(name);
    if (bound(len) < 1 + name_len + *bound(cur_len)) {
        *bound(cur_len) = 0;
        return false;
    }
    char *buf = bound(buf);
    runtime_memcpy(buf + 1 + name_len, buf, *bound(cur_len));
    buf[0] = '/';
    runtime_memcpy(buf + 1, buffer_ref(name, 0), name_len);
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
        n = lookup_follow(&fs, n, alloca_wrap_cstring(".."), &p);
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

int fs_check_rename(tuple old_parent, tuple old_md, tuple new_parent, tuple new_md,
                          boolean exchange)
{
    if (!exchange) {
        if (new_md) {
            tuple c = children(new_md);
            if (c) {
                if (!is_dir(old_md))
                    return -EISDIR;
                boolean notempty = (tuple_count(c) != 0);
                if (notempty)
                    return -ENOTEMPTY;
            } else if (is_dir(old_md))
                return -ENOTDIR;
        }
        if (file_tuple_is_ancestor(old_md, new_md, new_parent))
            return -EINVAL;
    } else {
        if (file_tuple_is_ancestor(old_md, new_md, new_parent) ||
            file_tuple_is_ancestor(new_md, old_md, old_parent))
            return -EINVAL;
    }
    return 0;
}
