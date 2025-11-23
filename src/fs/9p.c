#include <kernel.h>
#include <pagecache.h>
#include <fs.h>
#include <9p.h>
#include <unix/system_structs.h>
#include <virtio/virtio_9p.h>

//#define P9_DEBUG
#ifdef P9_DEBUG
#define p9_debug(x, ...) do {tprintf(sym(9p), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define p9_debug(x, ...)
#endif

typedef struct p9_dentry {
    struct list l;
    u32 fid;
    u64 qid;
    tuple md;
    boolean pinned;
} *p9_dentry;

typedef struct p9fs {
    struct filesystem fs;
    heap fid_h;
    u32 msize;
    struct p9_dentry root;
    struct list dentries;
    struct list fsfiles;
    void *transport;
} *p9fs;

typedef struct p9_fsfile {
    struct fsfile f;
    struct list l;
    u64 blocks;
    u32 iounit;
    p9_dentry dentry;
    closure_struct(pagecache_node_reserve, reserve);
    closure_struct(thunk, free);
} *p9_fsfile;

static void p9_dentry_delete(p9fs fs, p9_dentry dentry);

static symbol p9_sym(struct p9_string *name)
{
    return intern(alloca_wrap_buffer(name->str, name->length));
}

static void p9_md_cleanup(tuple md)
{
    symbol parent_sym = sym_this("..");
    tuple parent = get_tuple(md, parent_sym);
    if (parent) {
        tuple c = children(parent);
        if (c) {
            symbol name = tuple_get_symbol(c, md);
            if (name)
                set(c, name, 0);
        }
        set(md, parent_sym, 0);
    }
    destruct_value(md, true);
}

static u32 p9_fid_new(p9fs fs)
{
    u32 fid;
  begin:
    fid = allocate_u64(fs->fid_h, 1);
    if (fid != (u32)-1)
        return fid;

    /* Try to release a fid by looking for and deleting an unused directory entry. */
    list_foreach_reverse(&fs->dentries, e) {
        p9_dentry dentry = struct_from_list(e, p9_dentry, l);
        if (!dentry->pinned && (dentry->fid != P9_NOFID) && !fs_file_is_busy(&fs->fs, dentry->md)) {
            p9_dentry_delete(fs, dentry);
            goto begin;
        }
    }
    assert(0);
}

static void p9_fid_release(p9fs fs, u32 fid)
{
    v9p_clunk(fs->transport, fid);
    deallocate_u64(fs->fid_h, fid, 1);
}

static p9_dentry p9_dentry_new(p9fs fs, u32 fid, u64 qid, tuple md)
{
    p9_dentry dentry = allocate(fs->fs.h, sizeof(*dentry));
    if (dentry == INVALID_ADDRESS)
        return 0;
    dentry->fid = fid;
    dentry->qid = qid;
    dentry->md = md;
    dentry->pinned = false;
    list_insert_after(list_end(&fs->dentries), &dentry->l);
    return dentry;
}

static void p9_dentry_delete(p9fs fs, p9_dentry dentry)
{
    if (list_inserted(&dentry->l))
        list_delete(&dentry->l);
    if (dentry->fid != P9_NOFID)
        p9_fid_release(fs, dentry->fid);
    if (dentry->md)
        p9_md_cleanup(dentry->md);
    deallocate(fs->fs.h, dentry, sizeof(*dentry));
}

static void p9_fsf_io(p9_fsfile fsf, boolean write,
                        sg_list sg, range q, status_handler complete)
{
    p9_debug("%s file %p, sg %p, r %R, sh %F\n", write ? ss("write") : ss("read"), fsf, sg, q,
             complete);
    p9fs p9fs = (struct p9fs *)fsf->f.fs;
    merge m = allocate_merge(p9fs->fs.h, complete);
    complete = apply_merge(m);
    u32 fid = fsf->dentry->fid;
    u64 len = range_span(q);
    u32 iounit = fsf->iounit;
    u64 offset = q.start;
    do {
        u32 count = MIN(iounit, len);
        sg_buf sgb = sg_list_head_peek(sg);
        count = MIN(count, sg_buf_len(sgb));
        if (write)
            v9p_write(p9fs->transport, fid, offset, count, sgb->buf + sgb->offset, apply_merge(m));
        else
            v9p_read(p9fs->transport, fid, offset, count, sgb->buf + sgb->offset, apply_merge(m));
        sg_consume(sg, count);
        offset += count;
        len -= count;
    } while (len > 0);
    apply(complete, STATUS_OK);
}

static void p9_fsf_read(fsfile f, sg_list sg, range q, status_handler completion)
{
    p9_fsf_io((p9_fsfile)f, false, sg, q, completion);
}

closure_function(3, 1, void, p9_fsf_write_complete,
                 fsfile, f, u64, write_end, status_handler, completion,
                 status s)
{
    if (is_ok(s)) {
        fsfile f = bound(f);
        tuple md = f->md;
        if (md)
            filesystem_update_mtime(f->fs, md);
        u64 write_end = bound(write_end);
        if (write_end > f->length)
            fsfile_set_length(f, write_end);
    }
    apply(bound(completion), s);
    closure_finish();
}

static void p9_fsf_write(fsfile f, sg_list sg, range q, status_handler completion)
{
    context ctx = context_from_closure(completion);
    status_handler write_complete;
    if (ctx)    /* direct I/O */
        write_complete = closure_from_context(ctx, p9_fsf_write_complete, f, q.end, completion);
    else    /* I/O via page cache */
        write_complete = closure(f->fs->h, p9_fsf_write_complete, f, q.end, completion);
    if (write_complete != INVALID_ADDRESS) {
        p9_fsf_io((p9_fsfile)f, true, sg, q, write_complete);
    } else {
        status s = timm("result", "out of memory");
        apply(completion, timm_append(s, "fsstatus", "%d", -ENOMEM));
    }
}

closure_func_basic(pagecache_node_reserve, status, p9_fsf_reserve,
                   range q)
{
    p9_fsfile fsf = struct_from_field(closure_self(), p9_fsfile, reserve);
    p9_debug("reserve file %p range %R\n", fsf, q);
    fsfile f = &fsf->f;
    if (f->length < q.end)
        f->length = q.end;
    return STATUS_OK;
}

static s64 p9_get_blocks(fsfile f)
{
    return ((p9_fsfile)f)->blocks;
}

static void p9_fsfile_delete(p9fs fs, p9_fsfile fsf)
{
    if (list_inserted(&fsf->l))
        list_delete(&fsf->l);
    pagecache_deallocate_node(fsf->f.cache_node);
    deallocate(fs->fs.h, fsf, sizeof(*fsf));
}

closure_func_basic(status_handler, void, p9fsf_sync_complete,
                   status s)
{
    if (!is_ok(s)) {
        msg_err("9p: failed to sync page cache node: %v", s);
        timm_dealloc(s);
    }
    fsfile f = struct_from_closure(fsfile, sync_complete);
    p9_fsfile fsf = (p9_fsfile)f;
    filesystem fs = f->fs;
    p9fs p9fs = (struct p9fs *)fs;
    filesystem_lock(fs);
    p9_dentry dentry = fsf->dentry;
    if (!list_inserted(&dentry->l))
        p9_dentry_delete(p9fs, dentry);
    p9_fsfile_delete(p9fs, fsf);
    filesystem_unlock(fs);
}

closure_func_basic(thunk, void, p9_fsf_free)
{
    p9_fsfile fsf = struct_from_field(closure_self(), p9_fsfile, free);
    p9_debug("free file %p, dentry %p, md %p\n", fsf, fsf->dentry, fsf->dentry->md);
    fsfile f = &fsf->f;
    filesystem fs = f->fs;
    filesystem_lock(fs);
    if (f->refcount.c != 0) {
        /* Someone obtained a reference to this fsfile before we could remove it from the open file
         * list. */
        filesystem_unlock(fs);
        return;
    }
    p9_dentry dentry = fsf->dentry;
    tuple md = dentry->md;
    if (md && !fs_file_is_busy(fs, md)) {
        /* dentry will be deallocated when the pagecache sync is done: delete its metadata tuple now
         * so that it cannot be looked up (e.g. via its parent tuple). */
        p9_md_cleanup(md);
        dentry->md = 0;

        f->md = 0;  /* so that it won't be accessed by the file write completion */
        list_delete(&dentry->l);
    }
    list_delete(&fsf->l);
    filesystem_unlock(fs);
    pagecache_sync_node(f->cache_node,
                        init_closure_func(&f->sync_complete, status_handler, p9fsf_sync_complete));
}

static p9_fsfile p9_fsfile_new(p9fs fs, p9_dentry dentry)
{
    heap h = fs->fs.h;
    p9_fsfile fsf = allocate(h, sizeof(*fsf));
    if (fsf == INVALID_ADDRESS)
        return 0;
    fsf->dentry = dentry;
    int s = fsfile_init(&fs->fs, &fsf->f, dentry->md,
                              init_closure_func(&fsf->reserve, pagecache_node_reserve,
                                                p9_fsf_reserve),
                              init_closure_func(&fsf->free, thunk, p9_fsf_free));
    if (s != 0) {
        deallocate(h, fsf, sizeof(*fsf));
        return 0;
    }
    fsf->f.get_blocks = p9_get_blocks;
    list_insert_after(list_end(&fs->fsfiles), &fsf->l);
    dentry->pinned = true;
    return fsf;
}

static void p9_cache_hit(struct list *l, struct list *elem)
{
    if (elem != list_begin(l)) {
        list_delete(elem);
        list_insert_after(list_end(l), elem);
    }
}

static void p9_dentry_cache_hit(p9fs fs, p9_dentry dentry)
{
    p9_cache_hit(&fs->dentries, &dentry->l);
}

static void p9_fsfile_cache_hit(p9fs fs, p9_fsfile f)
{
    p9_cache_hit(&fs->fsfiles, &f->l);
}

#define P9_GET_DENTRY_FROM(type, name)                              \
    static p9_dentry p9_get_dentry_from_##name(p9fs fs, type name)  \
    {                                                               \
        if (name == fs->root.name)                                  \
            return &fs->root;                                       \
        list_foreach(&fs->dentries, e) {                            \
             p9_dentry dentry = struct_from_list(e, p9_dentry, l);  \
             if (dentry->name == name) {                            \
                 p9_dentry_cache_hit(fs, dentry);                   \
                 return dentry;                                     \
             }                                                      \
        }                                                           \
        return 0;                                                   \
}

P9_GET_DENTRY_FROM(tuple, md)
P9_GET_DENTRY_FROM(inode, qid)

closure_function(4, 1, void, p9_cache_sync_complete,
                 filesystem, fs, fsfile, f, boolean, datasync, status_handler, completion,
                 status s)
{
    p9_debug("cache sync complete, status %v\n", s);
    if (is_ok(s)) {
        p9fs fs = (p9fs)bound(fs);
        p9_fsfile f = (p9_fsfile)bound(f);
        void *transport = fs->transport;
        boolean datasync = bound(datasync);
        p9_debug("  file %p, datasync %d\n", f, datasync);
        int fss;
        filesystem_lock(&fs->fs);
        if (f)
            fss = v9p_fsync(transport, f->dentry->fid, datasync);
        else
            list_foreach(&fs->fsfiles, e) {
                f = struct_from_list(e, p9_fsfile, l);
                fss = v9p_fsync(transport, f->dentry->fid, datasync);
                if (fss != 0)
                    break;
            }
        filesystem_unlock(&fs->fs);
        if (fss != 0)
            s = timm("result", "fsync failed (%d)", fss);
    }
    async_apply_status_handler(bound(completion), s);
    closure_finish();
}

closure_function(2, 2, boolean, p9_dir_cleanup,
                 p9fs, fs, tuple, other_c,
                 value k, value v)
{
    p9fs fs = bound(fs);
    tuple other_c = bound(other_c);
    if (!other_c || !get_tuple(other_c, k)) {
        p9_dentry dentry = p9_get_dentry_from_md(fs, v);
        if (dentry) {
            fs_notify_release(dentry->md, false);
            p9_dentry_delete(fs, dentry);
        } else {
            deallocate_value(v);
        }
    }
    return true;
}

static int p9_readdir(p9fs fs, u32 fid, tuple md)
{
    p9_debug("readdir: fid %d, md %p\n", fid, md);
    u64 qid;
    u32 iounit;
    int s = v9p_lopen(fs->transport, fid, O_RDONLY, &qid, &iounit);
    if (s == -EINVAL)   /* this happens if fid has been already opened */
        s = 0;
    else if (s != 0)
        return s;
    const int iobuf_size = PAGESIZE;
    u8 *buf = v9p_get_iobuf(fs->transport, iobuf_size);
    if (buf == INVALID_ADDRESS)
        return -ENOMEM;
    tuple old_c = children(md);
    tuple new_c = allocate_tuple();
    u64 offset = 0;
    u32 count;
    p9_readdir_entry entry;
    do {
        s = v9p_readdir(fs->transport, fid, offset, buf, iobuf_size, &count);
        if (s != 0)
            break;
        u64 buf_offset = 0;
        while (count > buf_offset + sizeof(*entry)) {
            entry = (void *)buf + buf_offset;
            if ((entry->name.length > NAME_MAX) ||
                (buf_offset + sizeof(*entry) + entry->name.length > count)) {
                s = -EIO;
                break;
            }
            if (p9_strcmp(&entry->name, ss(".")) && p9_strcmp(&entry->name, ss(".."))) {
                symbol name_sym = p9_sym(&entry->name);
                tuple t;
                if (old_c)
                    t = get_tuple(old_c, name_sym);
                else
                    t = 0;
                p9_dentry dentry;
                if (t) {
                    dentry = p9_get_dentry_from_md(fs, t);
                } else {
                    t = allocate_tuple();
                    dentry = 0;
                }
                p9_debug("  dir entry '%b', type 0x%x, md %p\n", symbol_string(name_sym),
                         entry->type, t);
                if (!dentry) {
                    dentry = p9_dentry_new(fs, P9_NOFID, entry->qid.path, t);
                    if (!dentry) {
                        deallocate_value(t);
                        s = -ENOMEM;
                        break;
                    }
                }
                symbol attr;
                switch (entry->type) {
                case DT_DIR:
                    attr = sym(children);
                    if (!get(t, attr))
                        set(t, attr, allocate_tuple());
                    set(t, sym(..), md);
                    break;
                case DT_LNK:
                    attr = sym(linktarget);
                    if (!get(t, attr))
                        set(t, attr, null_value);
                    break;
                case DT_SOCK:
                    attr = sym(socket);
                    if (!get(t, attr))
                    set(t, attr, null_value);
                    break;
                }
                set(new_c, name_sym, t);
            }
            offset = entry->offset;
            buf_offset += sizeof(*entry) + entry->name.length;
        }
        if (s != 0)
            break;
    } while (count > sizeof(*entry));
    v9p_put_iobuf(fs->transport, buf, iobuf_size);
    if (s == 0) {
        if (old_c) {
            iterate(old_c, stack_closure(p9_dir_cleanup, fs, new_c));
            deallocate_value(old_c);
        }
        set(md, sym(children), new_c);
    } else {
        iterate(new_c, stack_closure(p9_dir_cleanup, fs, old_c));
        deallocate_value(new_c);
    }
    return s;
}

static int p9_readlink(p9fs fs, u32 fid, tuple md)
{
    buffer target = allocate_buffer(fs->fs.h, PATH_MAX);
    if (target == INVALID_ADDRESS)
        return -ENOMEM;
    int s = v9p_readlink(fs->transport, fid, target);
    if (s != 0) {
        deallocate_buffer(target);
        return s;
    }
    symbol target_sym = sym(linktarget);
    buffer old_target = get_string(md, target_sym);
    if (old_target && (old_target != null_value))
        deallocate_buffer(old_target);
    set(md, target_sym, target);
    return 0;
}

static int p9_rename(filesystem fs, tuple old_parent, string old_name, tuple old_md,
                           tuple new_parent, string new_name, tuple new_md, boolean exchange,
                           boolean *destruct_md)
{
    if (exchange)
        return -EINVAL; /* not supported */
    p9fs p9fs = (struct p9fs *)fs;
    p9_dentry oldp_dentry = p9_get_dentry_from_md(p9fs, old_parent);
    if (!oldp_dentry)
        return -ENOENT;
    p9_dentry newp_dentry = p9_get_dentry_from_md(p9fs, new_parent);
    if (!newp_dentry)
        return -ENOENT;
    int s = v9p_renameat(p9fs->transport, oldp_dentry->fid, old_name,
                               newp_dentry->fid, new_name);
    if ((s == 0) && new_md) {
        p9_dentry dentry = p9_get_dentry_from_md(p9fs, new_md);
        if (dentry) {
            dentry->md = 0;
        }
        *destruct_md = true;
    }
    return s;
}

static int p9_unlink(filesystem fs, tuple parent, string name, tuple md, boolean *destruct_md)
{
    p9fs p9fs = (struct p9fs *)fs;
    p9_dentry parent_dentry = p9_get_dentry_from_md(p9fs, parent);
    if (!parent_dentry)
        return -ENOENT;
    int s = v9p_unlinkat(p9fs->transport, parent_dentry->fid, name,
                               is_dir(md) ? P9_DOTL_AT_REMOVEDIR : 0);
    if (s == 0) {
        p9_dentry dentry = p9_get_dentry_from_md(p9fs, md);
        if (dentry) {
            dentry->md = 0;
        }
        *destruct_md = true;
    }
    return s;
}

static int p9_get_fsfile(filesystem fs, tuple md, fsfile *f)
{
    p9_debug("get fsfile, md %p\n", md);
    p9fs p9fs = (struct p9fs *)fs;
    list_foreach(&p9fs->fsfiles, e) {
        p9_fsfile fsf = struct_from_list(e, p9_fsfile, l);
        if (fsf->f.md == md) {
            p9_fsfile_cache_hit(p9fs, fsf);
            fsfile_reserve(&fsf->f);
            *f = &fsf->f;
            return 0;
        }
    }
    p9_dentry dentry = p9_get_dentry_from_md(p9fs, md);
    if (!dentry)
        return -ENOENT;
    p9_fsfile fsf = p9_fsfile_new(p9fs, dentry);
    if (!fsf)
        return -ENOMEM;
    struct p9_getattr_resp resp;
    int s = v9p_getattr(p9fs->transport, dentry->fid, P9_GETATTR_BASIC, &resp);
    if ((s == 0) && ((resp.valid & P9_GETATTR_BASIC) != P9_GETATTR_BASIC))
        s = -EIO;
    if (s == 0)
        s = v9p_lopen(p9fs->transport, dentry->fid, O_RDWR, &dentry->qid, &fsf->iounit);
    if (s == -EINVAL) { /* this happens if fid has been already opened */
        s = 0;
    } else if (s != 0) {
        p9_fsfile_delete(p9fs, fsf);
        return s;
    }
    fsf->blocks = resp.blocks;
    filesystem_set_atime(fs, md, resp.atime);
    filesystem_set_mtime(fs, md, resp.mtime);
    if (fsf->iounit == 0)
        fsf->iounit = p9fs->msize - P9_IOHDR_SIZE;
    fsfile_set_length(&fsf->f, resp.size);
    *f = &fsf->f;
    return 0;
}


static inode p9_get_inode(filesystem fs, tuple md) {
    p9fs p9fs = (struct p9fs *)fs;
    p9_dentry dentry = p9_get_dentry_from_md(p9fs, md);
    if (dentry)
        return dentry->qid;
    return 0;
}

static tuple p9_get_meta(filesystem fs, inode n)
{
    p9fs p9fs = (struct p9fs *)fs;
    p9_dentry dentry = p9_get_dentry_from_qid(p9fs, n);
    if (dentry)
        return dentry->md;
    return 0;
}

static tuple p9_lookup(filesystem fs, tuple parent, string name)
{
    p9_debug("lookup %p '%b'\n", parent, name);
    p9fs p9fs = (struct p9fs *)fs;
    p9_dentry parent_dentry = p9_get_dentry_from_md(p9fs, parent);
    if (!parent_dentry)
        return 0;
    if (!buffer_strcmp(name, "."))
        return (p9_readdir(p9fs, parent_dentry->fid, parent) == 0) ? parent : 0;
    parent_dentry->pinned = true;
    u32 fid = p9_fid_new(p9fs);
    parent_dentry->pinned = false;
    struct p9_qid qid;
    if (v9p_walk(p9fs->transport, parent_dentry->fid, fid, name, &qid) != 0) {
        deallocate_u64(p9fs->fid_h, fid, 1);
        return 0;
    }
    tuple md;
    p9_dentry dentry = p9_get_dentry_from_qid(p9fs, qid.path);
    if (dentry) {
        if (dentry->fid != P9_NOFID) {
            p9_fid_release(p9fs, fid);
            fid = dentry->fid;
        } else {
            dentry->fid = fid;
        }
        md = dentry->md;
    } else {
        md = allocate_tuple();
        if (qid.type == P9_QID_TYPE_DIR)
            set(md, sym(..), parent);
    }
    switch (qid.type) {
    case P9_QID_TYPE_DIR:
        if (p9_readdir(p9fs, fid, md) != 0)
            goto error;
        break;
    case P9_QID_TYPE_SYMLINK:
        if (p9_readlink(p9fs, fid, md) != 0)
            goto error;
        break;
    }
    if (!dentry) {
        dentry = p9_dentry_new(p9fs, fid, qid.path, md);
        if (!dentry)
            goto error;
    }
    return md;
  error:
    if (!dentry) {
        p9_md_cleanup(md);
        p9_fid_release(p9fs, fid);
        md = 0;
    }
    return md;
}

static int p9_create(filesystem fs, tuple parent, string name, tuple md, fsfile *f)
{
    if (!name)
        return -EOPNOTSUPP;
    p9_debug("create parent %p name '%b' md %p f %p\n", parent, name, md, f);
    p9fs p9fs = (struct p9fs *)fs;
    p9_dentry parent_dentry = p9_get_dentry_from_md(p9fs, parent);
    if (!parent_dentry)
        return -ENOENT;
    p9_dentry dentry = p9_dentry_new(p9fs, P9_NOFID, 0, md);
    if (!dentry)
        return -ENOMEM;
    int ret;
    if (is_dir(md)) {
        ret = v9p_mkdir(p9fs->transport, parent_dentry->fid, name, 0777, &dentry->qid);
    } else if (is_symlink(md)) {
        ret = v9p_symlink(p9fs->transport, parent_dentry->fid, name, linktarget(md), &dentry->qid);
    } else {
        boolean mknod;
        u32 mode;
        u32 major = 0, minor = 0;
        if (is_socket(md)) {
            mknod = true;
            mode = S_IFSOCK;
        } else {    /* regular file */
            if (!f) {
                mknod = true;
                mode = S_IFREG;
            } else {
                mknod = false;
            }
        }
        if (mknod) {
            ret = v9p_mknod(p9fs->transport, parent_dentry->fid, name, mode | 0644, major, minor,
                          &dentry->qid);
        } else {
            p9_fsfile fsf = p9_fsfile_new(p9fs, dentry);
            if (!fsf) {
                ret = -ENOMEM;
                goto out;
            }
            parent_dentry->pinned = true;
            dentry->fid = p9_fid_new(p9fs);
            parent_dentry->pinned = false;
            ret = v9p_walk(p9fs->transport, parent_dentry->fid, dentry->fid, 0, 0);
            if (ret == 0)
                ret = v9p_lcreate(p9fs->transport, dentry->fid, name, O_RDWR, 0644, &dentry->qid,
                                  &fsf->iounit);
            if (ret == 0) {
                if (fsf->iounit == 0)
                    fsf->iounit = p9fs->msize - P9_IOHDR_SIZE;
                *f = &fsf->f;
            } else {
                p9_fsfile_delete(p9fs, fsf);
            }
        }
    }
  out:
    if (ret != 0) {
        dentry->md = 0;
        p9_dentry_delete(p9fs, dentry);
    }
    return ret;
}

static int p9_truncate(filesystem fs, fsfile f, u64 len)
{
    p9_dentry dentry = ((p9_fsfile)f)->dentry;
    int s = v9p_setattr(((p9fs)fs)->transport, dentry->fid, P9_SETATTR_SIZE, 0, 0, 0, len,
                              0, 0);
    if (s != 0)
        return s;
    return 0;
}

static status_handler p9_get_sync_handler(filesystem fs, fsfile fsf, boolean datasync,
                                           status_handler completion)
{
    return closure(fs->h, p9_cache_sync_complete, fs, fsf, datasync, completion);
}

void p9_create_fs(heap h, void *transport, boolean readonly, filesystem_complete complete)
{
    p9fs fs = allocate(h, sizeof(*fs));
    if (fs == INVALID_ADDRESS) {
        apply(complete, INVALID_ADDRESS, timm("result", "failed to allocate fs"));
        return;
    }
    fs->fid_h = (heap)create_id_heap(h, h, 0, P9_NOFID, 1, false);
    status s;
    if (fs->fid_h == INVALID_ADDRESS) {
        s = timm("result", "failed to allocate fid heap");
        goto dealloc_fs;
    }
    fs->root.fid = p9_fid_new(fs);
    int fss = v9p_version(transport, 64 * MB, ss("9P2000.L"), &fs->msize);
    if (fss != 0) {
        s = timm("result", "failed to negotiate protocol version (%d)", fss);
        goto dealloc_fid_h;
    }
    fss = v9p_attach(transport, fs->root.fid, &fs->root.qid);
    if (fss != 0) {
        s = timm("result", "failed to establish connection (%d)", fss);
        goto dealloc_fid_h;
    }
    struct p9_statfs_resp stat_fs;
    fss = v9p_statfs(transport, fs->root.fid, &stat_fs);
    if (fss != 0) {
        s = timm("result", "failed to get filesystem information (%d)", fss);
        goto clunk_root;
    }
    s = filesystem_init(&fs->fs, h, stat_fs.blocks * stat_fs.bsize, 1, readonly);
    if (!is_ok(s)) {
        s = timm_up(s, "result", "failed to init fs");
        goto clunk_root;
    }
    fs->fs.root = fs->root.md = allocate_tuple();
    set(fs->root.md, sym_this(".."), fs->root.md);
    fs->fs.lookup = p9_lookup;
    fs->fs.create = p9_create;
    fs->fs.unlink = p9_unlink;
    fs->fs.rename = p9_rename;
    fs->fs.truncate = p9_truncate;
    fs->fs.get_fsfile = p9_get_fsfile;
    fs->fs.get_inode = p9_get_inode;
    fs->fs.file_read = p9_fsf_read;
    fs->fs.file_write = p9_fsf_write;
    fs->fs.get_meta = p9_get_meta;
    fs->fs.get_sync_handler = p9_get_sync_handler;
    list_init(&fs->dentries);
    list_init(&fs->fsfiles);
    fs->transport = transport;
    apply(complete, &fs->fs, STATUS_OK);
    return;
  clunk_root:
    v9p_clunk(transport, fs->root.fid);
  dealloc_fid_h:
    destroy_heap(fs->fid_h);
  dealloc_fs:
    deallocate(h, fs, sizeof(*fs));
    apply(complete, INVALID_ADDRESS, s);
}

void p9_strcpy(struct p9_string *dest, sstring str)
{
    int len = str.len;
    dest->length = len;
    runtime_memcpy(dest->str, str.ptr, len);
}

void p9_bufcpy(struct p9_string *dest, buffer b)
{
    int len = buffer_length(b);
    dest->length = len;
    buffer_read_at(b, 0, dest->str, len);
}

int p9_strcmp(struct p9_string *s1, sstring s2)
{
    int len = MIN(s1->length, s2.len);
    int res = runtime_memcmp(s1->str, s2.ptr, len);
    if (res)
        return res;
    return (int)(s1->length - s2.len);
}

int p9_parse_minimal_resp(u8 req_type, union p9_minimal_resp *resp, u32 resp_len)
{
    if (resp_len < sizeof(resp->hdr))
        return -EIO;
    if (resp->hdr.type == req_type + 1)
        return 0;
    return -resp->err.ecode;
}

int p9_parse_qid_resp(u8 req_type, union p9_qid_resp *resp, u32 resp_len, u64 *qid)
{
    if (resp_len < sizeof(struct p9_lerror))
        return -EIO;
    if (resp->hdr.type == req_type + 1) {
        *qid = resp->qid.path;
        return 0;
    }
    return -resp->err.ecode;
}
