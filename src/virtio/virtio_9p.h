void *v9p_get_iobuf(void *priv, u64 size);
void v9p_put_iobuf(void *priv, void *buf, u64 size);

int v9p_statfs(void *priv, u32 fid, struct p9_statfs_resp *resp);
int v9p_lopen(void *priv, u32 fid, u32 flags, u64 *qid, u32 *iounit);
int v9p_lcreate(void *priv, u32 fid, string name, u32 flags, u32 mode, u64 *qid, u32 *iounit);
int v9p_symlink(void *priv, u32 dfid, string name, string target, u64 *qid);
int v9p_mknod(void *priv, u32 dfid, string name, u32 mode, u32 major, u32 minor, u64 *qid);
int v9p_readlink(void *priv, u32 fid, buffer target);
int v9p_getattr(void *priv, u32 fid, u64 req_mask, struct p9_getattr_resp *resp);
int v9p_setattr(void *priv, u32 fid, u32 valid, u32 mode, u32 uid, u32 gid, u64 size,
                      timestamp atime, timestamp mtime);
int v9p_readdir(void *priv, u32 fid, u64 offset, void *buf, u32 count, u32 *ret_count);
int v9p_fsync(void *priv, u32 fid, u32 datasync);
int v9p_mkdir(void *priv, u32 dfid, string name, u32 mode, u64 *qid);
int v9p_renameat(void *priv, u32 old_dfid, string old_name, u32 new_dfid, string new_name);
int v9p_unlinkat(void *priv, u32 dfid, string name, u32 flags);
int v9p_version(void *priv, u32 msize, sstring version, u32 *ret_msize);
int v9p_attach(void *priv, u32 root_fid, u64 *root_qid);
int v9p_walk(void *priv, u32 fid, u32 newfid, string wname, struct p9_qid *qid);
int v9p_clunk(void *priv, u32 fid);

void v9p_read(void *priv, u32 fid, u64 offset, u32 count, void *dest, status_handler complete);
void v9p_write(void *priv, u32 fid, u64 offset, u32 count, void *src, status_handler complete);
