#include <kernel.h>
#include <pagecache.h>
#include <fs.h>
#include <9p.h>
#include <errno.h>
#include <storage.h>

#include "virtio_internal.h"
#include "virtio_pci.h"

//#define V9P_DEBUG
#ifdef V9P_DEBUG
#define v9p_debug(x, ...) do {tprintf(sym(v9p), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define v9p_debug(x, ...)
#endif

/* VirtIO feature flags */
#define VIRTIO_9P_MOUNT_TAG 0x0001  /* mount tag is present in device configuration */

typedef struct virtio_9p {
    heap general;
    backed_heap backed;
    closure_struct(fs_init_handler, fs_init);
    virtqueue vq;
    u16 next_tag;
    struct spinlock lock;
} *virtio_9p;

#define v9p_fill_hdr(v9p, hdr, s, t)        p9_fill_hdr(hdr, s, t, v9p_get_next_tag(v9p))
#define v9p_fill_req_hdr(v9p, xaction, t)   p9_fill_req_hdr(xaction, t, v9p_get_next_tag(v9p))

static u16 v9p_get_next_tag(virtio_9p v9p)
{
    spin_lock(&v9p->lock);
    if (++v9p->next_tag == P9_NOTAG)
        ++v9p->next_tag;
    u16 tag = v9p->next_tag;
    spin_unlock(&v9p->lock);
    return tag;
}

closure_function(2, 1, void, v9p_req_complete,
                 context, ctx, u32 *, ret_len,
                 u64 len)
{
    *bound(ret_len) = len;
    context_schedule_return(bound(ctx));
    closure_finish();
}

static u32 v9p_request(virtio_9p v9p, u64 req_phys, u32 req_len, u64 resp_phys, u32 resp_len)
{
    context ctx = get_current_context(current_cpu());
    u32 ret_len;
    vqfinish finish = closure(v9p->general, v9p_req_complete, ctx, &ret_len);
    if (finish == INVALID_ADDRESS)
        return 0;
    vqmsg m = allocate_vqmsg(v9p->vq);
    if (m == INVALID_ADDRESS) {
        deallocate_closure(finish);
        return 0;
    }
    vqmsg_push(v9p->vq, m, req_phys, req_len, false);
    vqmsg_push(v9p->vq, m, resp_phys, resp_len, true);
    context_pre_suspend(ctx);
    vqmsg_commit(v9p->vq, m, finish);
    context_suspend();
    return ret_len;
}

closure_func_basic(fs_init_handler, void, v9p_fs_init,
                   boolean readonly, filesystem_complete complete)
{
    v9p_debug("%s read-%s (%F)\n", func_ss, readonly ? ss("only") : ss("write"), complete);
    virtio_9p v9p = struct_from_field(closure_self(), virtio_9p, fs_init);
    p9_create_fs(v9p->general, v9p, readonly, complete);
}

static boolean v9p_dev_attach(heap general, backed_heap backed, vtdev dev)
{
    v9p_debug("dev_features 0x%lx, features 0x%lx\n", dev->dev_features, dev->features);
    virtio_9p v9p = allocate(general, sizeof(*v9p));
    if (v9p == INVALID_ADDRESS)
        return false;
    u64 attach_id = -1ull;
    if (dev->features & VIRTIO_9P_MOUNT_TAG) {
        u16 tag_len = vtdev_cfg_read_2(dev, 0);
        if (tag_len != 0) {
            buffer b = allocate_buffer(general, tag_len);
            if (b != INVALID_ADDRESS) {
                vtdev_cfg_read_mem(dev, sizeof(tag_len), buffer_ref(b, 0), tag_len);
                buffer_produce(b, tag_len);
                parse_int(b, 10, &attach_id);
                deallocate_buffer(b);
            }
        }
    }
    v9p_debug("  attachment ID %ld\n", attach_id);
    status s = virtio_alloc_virtqueue(dev, ss("virtio 9p"), 0, &v9p->vq);
    if (!is_ok(s)) {
        msg_err("failed to allocate virtqueue: %v\n", s);
        goto err;
    }
    spin_lock_init(&v9p->lock);
    v9p->general = general;
    v9p->backed = backed;
    vtdev_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);
    u8 uuid[UUID_LEN];
    char label[VOLUME_LABEL_MAX_LEN];
    rsnprintf(label, sizeof(label), "virtfs%ld", attach_id);
    if (!volume_add(uuid, label, v9p,
                    init_closure_func(&v9p->fs_init, fs_init_handler, v9p_fs_init),
                    (int)attach_id)) {
        msg_err("failed to add volume\n");
        goto err;
    }
    return true;
  err:
    deallocate(general, v9p, sizeof(*v9p));
    return false;
}

closure_function(2, 1, boolean, vtpci_9p_probe,
                 heap, general, backed_heap, backed,
                 pci_dev d)
{
    if (!vtpci_probe(d, VIRTIO_ID_9P))
        return false;
    vtdev v = (vtdev)attach_vtpci(bound(general), bound(backed), d, VIRTIO_9P_MOUNT_TAG);
    return v9p_dev_attach(bound(general), bound(backed), v);
}

void init_virtio_9p(kernel_heaps kh)
{
    heap h = heap_locked(kh);
    pci_probe probe = closure(h, vtpci_9p_probe, h, heap_linear_backed(kh));
    assert(probe != INVALID_ADDRESS);
    register_pci_driver(probe, 0);
}

void *v9p_get_iobuf(void *priv, u64 size)
{
    virtio_9p v9p = priv;
    return allocate((heap)v9p->backed, size);
}

void v9p_put_iobuf(void *priv, void *buf, u64 size)
{
    virtio_9p v9p = priv;
    deallocate((heap)v9p->backed, buf, size);
}

int v9p_statfs(void *priv, u32 fid, struct p9_statfs_resp *resp)
{
    v9p_debug("statfs fid %d\n", fid);
    virtio_9p v9p = priv;
    u64 phys;
    struct p9_statfs *xaction = alloc_map(v9p->backed, sizeof(*xaction), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_req_hdr(v9p, xaction, P9_TSTATFS);
    xaction->req.fid = fid;
    u32 ret_len = v9p_request(v9p, phys, sizeof(xaction->req),
                              phys + sizeof(xaction->req), sizeof(xaction->resp));
    int s;
    if (ret_len < sizeof(xaction->resp.hdr)) {
        s = -EIO;
        goto out;
    }
    if (xaction->resp.hdr.type == P9_RSTATFS) {
        resp->type = xaction->resp.type;
        resp->bsize = xaction->resp.bsize;
        resp->blocks = xaction->resp.blocks;
        resp->bfree = xaction->resp.bfree;
        resp->bavail = xaction->resp.bavail;
        resp->files = xaction->resp.files;
        resp->ffree = xaction->resp.ffree;
        resp->fsid = xaction->resp.fsid;
        resp->namelen = xaction->resp.namelen;
        s = 0;
    } else {
        s = -xaction->resp.err.ecode;
    }
  out:
    dealloc_unmap(v9p->backed, xaction, phys, sizeof(*xaction));
    return s;
}

int v9p_lopen(void *priv, u32 fid, u32 flags, u64 *qid, u32 *iounit)
{
    v9p_debug("lopen fid %d flags 0x%x\n", fid, flags);
    virtio_9p v9p = priv;
    u64 phys;
    struct p9_lopen *xaction = alloc_map(v9p->backed, sizeof(*xaction), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_req_hdr(v9p, xaction, P9_TLOPEN);
    xaction->req.fid = fid;
    xaction->req.flags = flags;
    u32 ret_len = v9p_request(v9p, phys, sizeof(xaction->req),
                              phys + sizeof(xaction->req), sizeof(xaction->resp));
    int s;
    if (ret_len < sizeof(xaction->resp.hdr)) {
        s = -EIO;
        goto out;
    }
    if (xaction->resp.hdr.type == P9_RLOPEN) {
        *qid = xaction->resp.qid.path;
        *iounit = xaction->resp.iounit;
        s = 0;
    } else {
        s = -xaction->resp.err.ecode;
    }
  out:
    dealloc_unmap(v9p->backed, xaction, phys, sizeof(*xaction));
    return s;
}

int v9p_lcreate(void *priv, u32 fid, string name, u32 flags, u32 mode, u64 *qid, u32 *iounit)
{
    v9p_debug("lcreate fid %d name '%b' flags 0x%x mode 0x%x\n", fid, name, flags, mode);
    virtio_9p v9p = priv;
    u64 name_len = p9_buflen(name);
    u64 req_len = sizeof(struct p9_msg_hdr) + 4 /* fid */ + name_len + 4 /* flags */ +
                  4 /* mode */ + 4 /* gid */;
    union p9_lcreate_resp *resp;
    u64 phys;
    struct p9_msg_hdr *xaction = alloc_map(v9p->backed, req_len + sizeof(*resp), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_hdr(v9p, xaction, req_len, P9_TLCREATE);
    void *req_body = xaction + 1;
    *(u32 *)req_body = fid;
    p9_bufcpy(req_body + 4, name);
    *(u32 *)(req_body + 4 + name_len) = flags;
    *(u32 *)(req_body + 4 + name_len + 4) = mode;
    *(u32 *)(req_body + 4 + name_len + 8) = 0;  /* gid */
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, sizeof(*resp));
    resp = (void *)xaction + req_len;
    int s;
    if (ret_len < sizeof(resp->hdr)) {
        s = -EIO;
        goto out;
    }
    if (resp->hdr.type == P9_RLCREATE) {
        *qid = resp->qid.path;
        *iounit = resp->iounit;
        s = 0;
    } else {
        s = -resp->err.ecode;
    }
  out:
    dealloc_unmap(v9p->backed, xaction, phys, req_len + sizeof(*resp));
    return s;
}

int v9p_symlink(void *priv, u32 dfid, string name, string target, u64 *qid)
{
    v9p_debug("symlink dfid %d name '%b' target '%b'\n", dfid, name, target);
    virtio_9p v9p = priv;
    u64 name_len = p9_buflen(name);
    u64 target_len = p9_buflen(target);
    u64 req_len = sizeof(struct p9_msg_hdr) + 4 /* dfid */ + name_len + target_len + 4 /* gid */;
    p9_symlink_resp resp;
    u64 phys;
    struct p9_msg_hdr *xaction = alloc_map(v9p->backed, req_len + sizeof(*resp), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_hdr(v9p, xaction, req_len, P9_TSYMLINK);
    void *req_body = xaction + 1;
    *(u32 *)req_body = dfid;
    p9_bufcpy(req_body + 4, name);
    p9_bufcpy(req_body + 4 + name_len, target);
    *(u32 *)(req_body + 4 + name_len + target_len) = 0; /* gid */
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, sizeof(*resp));
    resp = (void *)xaction + req_len;
    int s = p9_parse_qid_resp(P9_TSYMLINK, resp, ret_len, qid);
    dealloc_unmap(v9p->backed, xaction, phys, req_len + sizeof(*resp));
    return s;
}

int v9p_mknod(void *priv, u32 dfid, string name, u32 mode, u32 major, u32 minor, u64 *qid)
{
    v9p_debug("mknod dfid %d name '%b' mode 0x%x major %d minor %d\n", dfid, name, mode,
              major, minor);
    virtio_9p v9p = priv;
    u64 name_len = p9_buflen(name);
    u64 req_len = sizeof(struct p9_msg_hdr) + 4 /* dfid */ + name_len + 4 /* mode */ +
                  4 /* major */ + 4 /* minor */ + 4 /* gid */;
    p9_mknod_resp resp;
    u64 phys;
    struct p9_msg_hdr *xaction = alloc_map(v9p->backed, req_len + sizeof(*resp), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_hdr(v9p, xaction, req_len, P9_TMKNOD);
    void *req_body = xaction + 1;
    *(u32 *)req_body = dfid;
    p9_bufcpy(req_body + 4, name);
    *(u32 *)(req_body + 4 + name_len) = mode;
    *(u32 *)(req_body + 4 + name_len + 4) = major;
    *(u32 *)(req_body + 4 + name_len + 8) = minor;
    *(u32 *)(req_body + 4 + name_len + 12) = 0; /* gid */
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, sizeof(*resp));
    resp = (void *)xaction + req_len;
    int s = p9_parse_qid_resp(P9_TMKNOD, resp, ret_len, qid);
    dealloc_unmap(v9p->backed, xaction, phys, req_len + sizeof(*resp));
    return s;
}

int v9p_readlink(void *priv, u32 fid, buffer target)
{
    v9p_debug("readlink fid %d\n", fid);
    virtio_9p v9p = priv;
    u64 phys;
    struct p9_readlink *xaction;
    u64 xaction_len = sizeof(*xaction) + buffer_space(target);
    xaction = alloc_map(v9p->backed, xaction_len, &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_req_hdr(v9p, xaction, P9_TREADLINK);
    xaction->req.fid = fid;
    u32 ret_len = v9p_request(v9p, phys, sizeof(xaction->req),
                              phys + offsetof(struct p9_readlink *, resp),
                              sizeof(xaction->resp) + buffer_space(target));
    int s;
    if (ret_len < sizeof(xaction->resp.hdr)) {
        s = -EIO;
        goto out;
    }
    if (xaction->resp.hdr.type == P9_RREADLINK) {
        if (xaction->resp.target.length <= buffer_space(target)) {
            buffer_write(target, xaction->resp.target.str, xaction->resp.target.length);
            s = 0;
        } else {
            s = -EIO;
        }
    } else {
        s = -xaction->resp.err.ecode;
    }
  out:
    dealloc_unmap(v9p->backed, xaction, phys, xaction_len);
    return s;
}

int v9p_getattr(void *priv, u32 fid, u64 req_mask, struct p9_getattr_resp *resp)
{
    v9p_debug("getattr fid %d req_mask 0x%lx\n", fid, req_mask);
    virtio_9p v9p = priv;
    u64 phys;
    struct p9_getattr *xaction = alloc_map(v9p->backed, sizeof(*xaction), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_req_hdr(v9p, xaction, P9_TGETATTR);
    xaction->req.fid = fid;
    xaction->req.request_mask = req_mask;
    u32 ret_len = v9p_request(v9p, phys, sizeof(xaction->req),
                              phys + offsetof(struct p9_getattr *, resp), sizeof(xaction->resp));
    int s;
    if (ret_len < sizeof(xaction->resp.hdr)) {
        s = -EIO;
        goto out;
    }
    if (xaction->resp.hdr.type == P9_RGETATTR) {
        resp->valid = xaction->resp.valid;
        runtime_memcpy(&resp->qid, &xaction->resp.qid, sizeof(struct p9_qid));
        resp->mode = xaction->resp.mode;
        resp->uid = xaction->resp.uid;
        resp->gid = xaction->resp.gid;
        resp->nlink = xaction->resp.nlink;
        resp->rdev = xaction->resp.rdev;
        resp->size = xaction->resp.size;
        resp->blksize = xaction->resp.blksize;
        resp->blocks = xaction->resp.blocks;
        resp->atime = seconds(xaction->resp.atime_sec) + nanoseconds(xaction->resp.atime_nsec);
        resp->mtime = seconds(xaction->resp.mtime_sec) + nanoseconds(xaction->resp.mtime_nsec);
        resp->ctime = seconds(xaction->resp.ctime_sec) + nanoseconds(xaction->resp.ctime_nsec);
        s = 0;
    } else {
        s = -xaction->resp.err.ecode;
    }
  out:
    dealloc_unmap(v9p->backed, xaction, phys, sizeof(*xaction));
    return s;
}

int v9p_setattr(void *priv, u32 fid, u32 valid, u32 mode, u32 uid, u32 gid, u64 size,
                      timestamp atime, timestamp mtime)
{
    v9p_debug("setattr fid %d valid 0x%x\n", fid, valid);
    virtio_9p v9p = priv;
    u64 phys;
    struct p9_setattr *xaction = alloc_map(v9p->backed, sizeof(*xaction), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_req_hdr(v9p, xaction, P9_TSETATTR);
    xaction->req.fid = fid;
    xaction->req.valid = valid;
    xaction->req.mode = mode;
    xaction->req.uid = uid;
    xaction->req.gid = gid;
    xaction->req.size = size;
    xaction->req.atime_sec = sec_from_timestamp(atime);
    xaction->req.atime_nsec = (truncate_seconds(atime) * BILLION) / TIMESTAMP_SECOND;
    xaction->req.mtime_sec = sec_from_timestamp(mtime);
    xaction->req.mtime_nsec = (truncate_seconds(mtime) * BILLION) / TIMESTAMP_SECOND;
    u32 ret_len = v9p_request(v9p, phys, sizeof(xaction->req),
                              phys + offsetof(struct p9_setattr *, resp), sizeof(xaction->resp));
    int s = p9_parse_minimal_resp(P9_TSETATTR, &xaction->resp, ret_len);
    dealloc_unmap(v9p->backed, xaction, phys, sizeof(*xaction));
    return s;
}

int v9p_readdir(void *priv, u32 fid, u64 offset, void *buf, u32 count, u32 *ret_count)
{
    v9p_debug("readdir fid %d offset %ld count %d\n", fid, offset, count);
    virtio_9p v9p = priv;
    u64 phys;
    struct p9_readdir *xaction = alloc_map(v9p->backed, sizeof(*xaction), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_req_hdr(v9p, xaction, P9_TREADDIR);
    xaction->req.fid = fid;
    xaction->req.offset = offset;
    xaction->req.count = count;
    int s;
    context ctx = get_current_context(current_cpu());
    u32 ret_len;
    vqfinish finish = closure(v9p->general, v9p_req_complete, ctx, &ret_len);
    if (finish == INVALID_ADDRESS) {
        s = -ENOMEM;
        goto out;
    }
    vqmsg m = allocate_vqmsg(v9p->vq);
    if (m == INVALID_ADDRESS) {
        deallocate_closure(finish);
        s = -ENOMEM;
        goto out;
    }
    vqmsg_push(v9p->vq, m, phys, sizeof(xaction->req), false);
    vqmsg_push(v9p->vq, m, phys + offsetof(struct p9_readdir *, resp), sizeof(xaction->resp), true);
    vqmsg_push(v9p->vq, m, physical_from_virtual(buf), count, true);
    context_pre_suspend(ctx);
    vqmsg_commit(v9p->vq, m, finish);
    context_suspend();
    if (ret_len < sizeof(xaction->resp.hdr)) {
        s = -EIO;
        goto out;
    }
    if (xaction->resp.hdr.type == P9_RREADDIR) {
        *ret_count = xaction->resp.count;
        s = 0;
    } else {
        s = -xaction->resp.err.ecode;
    }
  out:
    dealloc_unmap(v9p->backed, xaction, phys, sizeof(*xaction));
    return s;
}

int v9p_fsync(void *priv, u32 fid, u32 datasync)
{
    v9p_debug("fsync fid %d datasync %d\n", fid, datasync);
    virtio_9p v9p = priv;
    u64 phys;
    struct p9_fsync *xaction = alloc_map(v9p->backed, sizeof(*xaction), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_req_hdr(v9p, xaction, P9_TFSYNC);
    xaction->req.fid = fid;
    xaction->req.datasync = datasync;
    u32 ret_len = v9p_request(v9p, phys, sizeof(xaction->req),
                              phys + offsetof(struct p9_fsync *, resp), sizeof(xaction->resp));
    int s = p9_parse_minimal_resp(P9_TFSYNC, &xaction->resp, ret_len);
    dealloc_unmap(v9p->backed, xaction, phys, sizeof(*xaction));
    return s;
}

int v9p_mkdir(void *priv, u32 dfid, string name, u32 mode, u64 *qid)
{
    v9p_debug("mkdir dfid %d name '%b'\n", dfid, name);
    virtio_9p v9p = priv;
    u64 name_len = p9_buflen(name);
    u64 req_len = sizeof(struct p9_msg_hdr) + 4 /* dfid */ + name_len + 4 /* mode */ + 4 /* gid */;
    p9_mkdir_resp resp;
    u64 phys;
    struct p9_msg_hdr *xaction = alloc_map(v9p->backed, req_len + sizeof(*resp), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_hdr(v9p, xaction, req_len, P9_TMKDIR);
    void *req_body = xaction + 1;
    *(u32 *)req_body = dfid;
    p9_bufcpy(req_body + 4, name);
    *(u32 *)(req_body + 4 + name_len) = mode;
    *(u32 *)(req_body + 4 + name_len + 4) = 0;  /* gid */
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, sizeof(*resp));
    resp = (void *)xaction + req_len;
    int s = p9_parse_qid_resp(P9_TMKDIR, resp, ret_len, qid);
    dealloc_unmap(v9p->backed, xaction, phys, req_len + sizeof(*resp));
    return s;
}

int v9p_renameat(void *priv, u32 old_dfid, string old_name, u32 new_dfid, string new_name)
{
    v9p_debug("renameat old_dfid %d old_name '%b' new_dfid %d new_name '%b'\n", old_dfid, old_name,
              new_dfid, new_name);
    virtio_9p v9p = priv;
    u64 old_len = p9_buflen(old_name);
    u64 new_len = p9_buflen(new_name);
    u64 req_len = sizeof(struct p9_msg_hdr) + 4 /* old_dfid */ + old_len +
                  4 /* new_dfid */ + new_len;
    p9_renameat_resp resp;
    u64 phys;
    struct p9_msg_hdr *xaction = alloc_map(v9p->backed, req_len + sizeof(*resp), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_hdr(v9p, xaction, req_len, P9_TRENAMEAT);
    void *req_body = xaction + 1;
    *(u32 *)req_body = old_dfid;
    p9_bufcpy(req_body + 4, old_name);
    *(u32 *)(req_body + 4 + old_len) = new_dfid;
    p9_bufcpy(req_body + 4 + old_len + 4, new_name);
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, sizeof(*resp));
    resp = (void *)xaction + req_len;
    int s = p9_parse_minimal_resp(P9_TRENAMEAT, resp, ret_len);
    dealloc_unmap(v9p->backed, xaction, phys, req_len + sizeof(*resp));
    return s;
}

int v9p_unlinkat(void *priv, u32 dfid, string name, u32 flags)
{
    v9p_debug("unlinkat dfid %d name '%b' flags 0x%x\n", dfid, name, flags);
    virtio_9p v9p = priv;
    u64 name_len = p9_buflen(name);
    u64 req_len = sizeof(struct p9_msg_hdr) + 4 /* dfid */ + name_len + 4 /* flags */;
    p9_unlinkat_resp resp;
    u64 phys;
    struct p9_msg_hdr *xaction = alloc_map(v9p->backed, req_len + sizeof(*resp), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_hdr(v9p, xaction, req_len, P9_TUNLINKAT);
    void *req_body = xaction + 1;
    *(u32 *)req_body = dfid;
    p9_bufcpy(req_body + 4, name);
    *(u32 *)(req_body + 4 + name_len) = flags;
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, sizeof(*resp));
    resp = (void *)xaction + req_len;
    int s = p9_parse_minimal_resp(P9_TUNLINKAT, resp, ret_len);
    dealloc_unmap(v9p->backed, xaction, phys, req_len + sizeof(*resp));
    return s;
}

int v9p_version(void *priv, u32 msize, sstring version, u32 *ret_msize)
{
    v9p_debug("version %s msize 0x%x\n", version, msize);
    virtio_9p v9p = priv;
    u64 version_len = version.len;
    struct p9_version_req *req;
    union p9_version_resp *resp;
    u64 req_len = sizeof(*req) + version_len;
    u64 resp_len = sizeof(*resp) + version_len;
    u64 phys;
    req = alloc_map(v9p->backed, req_len + resp_len, &phys);
    if (req == INVALID_ADDRESS)
        return -ENOMEM;
    p9_fill_hdr(&req->hdr, req_len, P9_TVERSION, P9_NOTAG);
    req->msize = msize;
    p9_strcpy(&req->version, version);
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, resp_len);
    int s;
    if (ret_len < sizeof(resp->hdr)) {
        s = -EIO;
        goto out;
    }
    resp = (void *)req + req_len;
    if (resp->hdr.type == P9_RVERSION) {
        if (!p9_strcmp(&resp->version, version)) {
            *ret_msize = resp->msize;
            s = 0;
        } else {
            msg_err("version %s not supported\n", version);
            s = -EINVAL;
        }
    } else {
        s = -resp->err.ecode;
    }
  out:
    dealloc_unmap(v9p->backed, req, phys, req_len + resp_len);
    return s;
}

int v9p_attach(void *priv, u32 root_fid, u64 *root_qid)
{
    v9p_debug("attach\n");
    virtio_9p v9p = priv;
    sstring uname = ss("root");
    sstring aname = ss(".");
    u64 uname_len = p9_strlen(uname);
    u64 aname_len = p9_strlen(aname);
    u64 req_len = sizeof(struct p9_msg_hdr) + 4 /* fid */ + 4 /* afid */ + uname_len + aname_len +
                  4 /* n_uname*/;
    p9_attach_resp resp;
    u64 phys;
    struct p9_msg_hdr *xaction = alloc_map(v9p->backed, req_len + sizeof(*resp), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_hdr(v9p, xaction, req_len, P9_TATTACH);
    void *req_body = xaction + 1;
    *(u32 *)req_body = root_fid;
    *(u32 *)(req_body + 4) = P9_NOFID;
    p9_strcpy(req_body + 8, uname);
    p9_strcpy(req_body + 8 + uname_len, aname);
    *(u32 *)(req_body + 8 + uname_len + aname_len) = P9_NONUNAME;
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, sizeof(*resp));
    resp = (void *)xaction + req_len;
    int s = p9_parse_qid_resp(P9_TATTACH, resp, ret_len, root_qid);
    dealloc_unmap(v9p->backed, xaction, phys, req_len + sizeof(*resp));
    return s;
}

int v9p_walk(void *priv, u32 fid, u32 newfid, string wname, struct p9_qid *qid)
{
    v9p_debug("walk fid %d newfid %d\n", fid, newfid);
    virtio_9p v9p = priv;
    u64 name_len = wname ? p9_buflen(wname) : 0;
    struct p9_walk_req *req;
    union p9_walk_resp *resp;
    u64 req_len = sizeof(*req) + name_len;
    u64 resp_len = sizeof(*resp) + (wname ? sizeof(struct p9_qid) : 0);
    u64 phys;
    req = alloc_map(v9p->backed, req_len + resp_len, &phys);
    if (req == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_hdr(v9p, &req->hdr, req_len, P9_TWALK);
    req->fid = fid;
    req->newfid = newfid;
    req->nwname = wname ? 1 : 0;
    if (wname)
        p9_bufcpy((void *)(req + 1), wname);
    u32 ret_len = v9p_request(v9p, phys, req_len, phys + req_len, resp_len);
    int s;
    if (ret_len < sizeof(resp->hdr)) {
        s = -EIO;
        goto out;
    }
    resp = (void *)req + req_len;
    if (resp->hdr.type == P9_RWALK) {
        if (resp->nwqid)
            runtime_memcpy(qid, resp->wqid, sizeof(struct p9_qid));
        s = 0;
    } else {
        s = -resp->err.ecode;
    }
  out:
    dealloc_unmap(v9p->backed, req, phys, req_len + resp_len);
    return s;
}

int v9p_clunk(void *priv, u32 fid)
{
    v9p_debug("clunk fid %d\n", fid);
    virtio_9p v9p = priv;
    u64 phys;
    struct p9_clunk *xaction = alloc_map(v9p->backed, sizeof(*xaction), &phys);
    if (xaction == INVALID_ADDRESS)
        return -ENOMEM;
    v9p_fill_req_hdr(v9p, xaction, P9_TCLUNK);
    xaction->req.fid = fid;
    u32 ret_len = v9p_request(v9p, phys, sizeof(xaction->req),
                              phys + offsetof(struct p9_clunk *, resp), sizeof(xaction->resp));
    int s = p9_parse_minimal_resp(P9_TCLUNK, &xaction->resp, ret_len);
    dealloc_unmap(v9p->backed, xaction, phys, sizeof(*xaction));
    return s;
}

closure_function(4, 1, void, v9p_read_complete,
                 virtio_9p, v9p, struct p9_read *, xaction, u64, phys, status_handler, complete,
                 u64 len)
{
    v9p_debug("read complete, len %ld\n", len);
    struct p9_read *xaction = bound(xaction);
    status s;
    if (len == sizeof(xaction->resp) + xaction->req.count) {
        if (xaction->resp.hdr.type == P9_RREAD)
            s = STATUS_OK;
        else
            s = timm("result", "failed to read %d bytes, error %d", xaction->req.count,
                     xaction->resp.err.ecode);
    } else {
        s = timm("result", "failed to read %d bytes, read %ld", xaction->req.count,
                 len - sizeof(xaction->resp));
    }
    dealloc_unmap(bound(v9p)->backed, xaction, bound(phys), sizeof(*xaction));
    apply(bound(complete), s);
    closure_finish();
}

void v9p_read(void *priv, u32 fid, u64 offset, u32 count, void *dest, status_handler complete)
{
    v9p_debug("read fid %d, offset %ld, count %d, complete %F\n", fid, offset, count, complete);
    virtio_9p v9p = priv;
    u64 phys;
    status s;
    struct p9_read *xaction = alloc_map(v9p->backed, sizeof(*xaction), &phys);
    if (xaction == INVALID_ADDRESS) {
        s = timm("result", "failed to allocate request");
        goto error;
    }
    v9p_fill_req_hdr(v9p, xaction, P9_TREAD);
    xaction->req.fid = fid;
    xaction->req.offset = offset;
    xaction->req.count = count;
    vqfinish finish = closure(v9p->general, v9p_read_complete, v9p, xaction, phys, complete);
    if (finish == INVALID_ADDRESS) {
        s = timm("result", "failed to allocate vqfinish");
        goto dealloc_req;
    }
    vqmsg m = allocate_vqmsg(v9p->vq);
    if (m == INVALID_ADDRESS) {
        s = timm("result", "failed to allocate vqmsg");
        deallocate_closure(finish);
        goto dealloc_req;
    }
    vqmsg_push(v9p->vq, m, phys, sizeof(xaction->req), false);
    vqmsg_push(v9p->vq, m, phys + sizeof(xaction->req), sizeof(xaction->resp), true);
    vqmsg_push(v9p->vq, m, physical_from_virtual(dest), count, true);
    vqmsg_commit(v9p->vq, m, finish);
    return;
  dealloc_req:
    dealloc_unmap(v9p->backed, xaction, phys, sizeof(*xaction));
  error:
    s = timm_append(s, "fsstatus", "%d", -ENOMEM);
    apply(complete, s);
}

closure_function(4, 1, void, v9p_write_complete,
                 virtio_9p, v9p, struct p9_write_req *, req, u64, phys, status_handler, complete,
                 u64 len)
{
    v9p_debug("write complete, len %ld\n", len);
    struct p9_write_req *req = bound(req);
    union p9_write_resp *resp = (void *)(req + 1);
    status s;
    if (len == sizeof(*resp)) {
        if (resp->hdr.type == P9_RWRITE) {
            if (resp->count == req->count)
                s = STATUS_OK;
            else
                s = timm("result", "failed to write %d bytes, written %d", req->count, resp->count);
        } else {
            s = timm("result", "failed to write %d bytes, error %d", req->count, resp->err.ecode);
        }
    } else {
        s = timm("result", "failed to write %d bytes, response length %ld", req->count, len);
    }
    dealloc_unmap(bound(v9p)->backed, req, bound(phys), sizeof(*req) + sizeof(*resp));
    apply(bound(complete), s);
    closure_finish();
}

void v9p_write(void *priv, u32 fid, u64 offset, u32 count, void *src, status_handler complete)
{
    v9p_debug("write fid %d, offset %ld, count %d, complete %F\n", fid, offset, count, complete);
    virtio_9p v9p = priv;
    u64 phys;
    status s;
    union p9_write_resp *resp;
    struct p9_write_req *req = alloc_map(v9p->backed, sizeof(*req) + sizeof(*resp), &phys);
    if (req == INVALID_ADDRESS) {
        s = timm("result", "failed to allocate request");
        goto error;
    }
    v9p_fill_hdr(v9p, &req->hdr, sizeof(*req) + count, P9_TWRITE);
    req->fid = fid;
    req->offset = offset;
    req->count = count;
    vqfinish finish = closure(v9p->general, v9p_write_complete, v9p, req, phys, complete);
    if (finish == INVALID_ADDRESS) {
        s = timm("result", "failed to allocate vqfinish");
        goto dealloc_req;
    }
    vqmsg m = allocate_vqmsg(v9p->vq);
    if (m == INVALID_ADDRESS) {
        s = timm("result", "failed to allocate vqmsg");
        deallocate_closure(finish);
        goto dealloc_req;
    }
    vqmsg_push(v9p->vq, m, phys, sizeof(*req), false);
    vqmsg_push(v9p->vq, m, physical_from_virtual(src), count, false);
    vqmsg_push(v9p->vq, m, phys + sizeof(*req), sizeof(*resp), true);
    vqmsg_commit(v9p->vq, m, finish);
    return;
  dealloc_req:
    dealloc_unmap(v9p->backed, req, phys, sizeof(*req) + sizeof(*resp));
  error:
    s = timm_append(s, "fsstatus", "%d", -ENOMEM);
    apply(complete, s);
}
