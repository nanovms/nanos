typedef struct filesystem *filesystem;

typedef u64 inode;

typedef closure_type(filesystem_complete, void, filesystem, status);

typedef struct fsfile *fsfile;

u64 fsfile_get_length(fsfile f);
void fsfile_set_length(fsfile f, u64 length);
sg_io fsfile_get_reader(fsfile f);
sg_io fsfile_get_writer(fsfile f);
pagecache_node fsfile_get_cachenode(fsfile f);

// turn these into method gets rather than call
void filesystem_read_sg(fsfile f, sg_list sg, range q, status_handler completion);

void filesystem_write_sg(fsfile f, sg_list sg, range q, status_handler completion);

/* deprecate these if we can */
void filesystem_read_linear(fsfile f, void *dest, range q, io_status_handler completion);
void filesystem_write_linear(fsfile f, void *src, range q, io_status_handler completion);

void filesystem_flush(filesystem fs, status_handler completion);

void filesystem_reserve(filesystem fs);
void filesystem_release(filesystem fs);

timestamp filesystem_get_atime(filesystem fs, tuple t);
timestamp filesystem_get_mtime(filesystem fs, tuple t);
void filesystem_set_atime(filesystem fs, tuple t, timestamp tim);
void filesystem_set_mtime(filesystem fs, tuple t, timestamp tim);

#define filesystem_update_atime(fs, t) \
    filesystem_set_atime(fs, t, now(CLOCK_ID_REALTIME))
#define filesystem_update_mtime(fs, t) \
    filesystem_set_mtime(fs, t, now(CLOCK_ID_REALTIME))

u64 filesystem_get_rdev(filesystem fs, tuple t);
void filesystem_set_rdev(filesystem fs, tuple t, u64 rdev);

void filesystem_read_entire(filesystem fs, tuple t, heap bufheap, buffer_handler c, status_handler s);
void fsfile_reserve(fsfile f);
void fsfile_release(fsfile f);
void fsfile_flush(fsfile f, boolean datasync, status_handler completion);

#define fsfile_get_blocks(f)    (f)->get_blocks(f)  /* returns the number of allocated blocks */

typedef enum {
    FS_STATUS_OK = 0,
    FS_STATUS_NOSPACE,
    FS_STATUS_IOERR,
    FS_STATUS_NOENT,
    FS_STATUS_EXIST,
    FS_STATUS_INVAL,
    FS_STATUS_NOTDIR,
    FS_STATUS_ISDIR,
    FS_STATUS_NOTEMPTY,
    FS_STATUS_NOMEM,
    FS_STATUS_LINKLOOP,
    FS_STATUS_NAMETOOLONG,
    FS_STATUS_XDEV,
    FS_STATUS_FAULT,
    FS_STATUS_READONLY,
} fs_status;

sstring string_from_fs_status(fs_status s);

typedef closure_type(fs_status_handler, void, fsfile, fs_status);

void filesystem_alloc(fsfile f, long offset, long len,
        boolean keep_size, fs_status_handler completion);
void filesystem_dealloc(fsfile f, long offset, long len,
        fs_status_handler completion);
fs_status filesystem_truncate(filesystem fs, fsfile f, u64 len);
fs_status filesystem_truncate_locked(filesystem fs, fsfile f, u64 len);

fs_status fsfile_init(filesystem fs, fsfile f, tuple md, sg_io fs_read, sg_io fs_write,
                      pagecache_node_reserve fs_reserve, thunk fs_free);

declare_closure_struct(1, 0, void, fs_sync,
                       filesystem, fs);
declare_closure_struct(1, 1, void, fs_free,
                       filesystem, fs,
                       status, s);
struct filesystem {
    u64 size;
    heap h;
    int blocksize_order;
    boolean ro; /* true for read-only filesystem */
    pagecache_volume pv;
    tuple (*lookup)(filesystem fs, tuple parent, string name);
    fs_status (*create)(filesystem fs, tuple parent, string name, tuple md, fsfile *f);
    fs_status (*unlink)(filesystem fs, tuple parent, string name, tuple md, boolean *destruct_md);
    fs_status (*rename)(filesystem fs, tuple old_parent, string old_name, tuple old_md,
                        tuple new_parent, string new_name, tuple new_md, boolean exchange,
                        boolean *destruct_md);
    fs_status (*truncate)(filesystem fs, fsfile f, u64 len);
    fs_status (*get_fsfile)(filesystem fs, tuple md, fsfile *f);
    inode (*get_inode)(filesystem fs, tuple md);
    tuple (*get_meta)(filesystem fs, inode n);
    u64 (*get_freeblocks)(filesystem fs);
    status_handler (*get_sync_handler)(filesystem fs, fsfile fsf, boolean datasync,
                                       status_handler completion);
    void (*destroy_fs)(filesystem fs);
    tuple root;
#ifdef KERNEL
    struct mutex lock;
#endif
    struct refcount refcount;
    closure_struct(fs_sync, sync);
    thunk sync_complete;
    closure_struct(fs_free, free);
};

declare_closure_struct(1, 1, void, fsf_sync_complete,
                       fsfile, f,
                       status, s);
struct fsfile {
    filesystem fs;
    pagecache_node cache_node;
    u64 length;
    tuple md;
    sg_io read;
    sg_io write;
    s64 (*get_blocks)(fsfile f);
    struct refcount refcount;
    closure_struct(fsf_sync_complete, sync_complete);
    u8 status;
};

/* fsfile status flags */
#define FSF_DIRTY_DATASYNC  (1 << 0)    /* metadata needed for retrieving file data */
#define FSF_DIRTY_OTHER     (1 << 1)    /* any other metadata */
#define FSF_DIRTY           (FSF_DIRTY_DATASYNC | FSF_DIRTY_OTHER)

status filesystem_init(filesystem fs, heap h, u64 size, u64 blocksize, boolean ro);
void filesystem_deinit(filesystem fs);

static inline u64 bytes_from_sectors(filesystem fs, u64 sectors)
{
    return sectors << fs->blocksize_order;
}

static inline u64 sector_from_offset(filesystem fs, bytes b)
{
    return b >> fs->blocksize_order;
}

#ifdef KERNEL

#define filesystem_lock_init(fs)    mutex_init(&(fs)->lock, 0)
#define filesystem_lock(fs)         mutex_lock(&(fs)->lock)
#define filesystem_unlock(fs)       mutex_unlock(&(fs)->lock)

#else

#define filesystem_lock_init(fs)
#define filesystem_lock(fs)         ((void)fs)
#define filesystem_unlock(fs)       ((void)fs)

#endif

tuple fs_new_entry(filesystem fs);

boolean file_tuple_is_ancestor(tuple t1, tuple t2, tuple p2);

fs_status filesystem_mkdir(filesystem fs, inode cwd, sstring path);
fs_status filesystem_get_node(filesystem *fs, inode cwd, sstring path, boolean nofollow,
                              boolean create, boolean exclusive, boolean truncate, tuple *n,
                              fsfile *f);
void filesystem_put_node(filesystem fs, tuple n);
tuple filesystem_get_meta(filesystem fs, inode n);
void filesystem_put_meta(filesystem fs, tuple n);
fs_status filesystem_creat_unnamed(filesystem fs, fsfile *f);
fs_status filesystem_symlink(filesystem fs, inode cwd, sstring path, sstring target);
fs_status filesystem_delete(filesystem fs, inode cwd, sstring path, boolean directory);
fs_status filesystem_rename(filesystem oldfs, inode oldwd, sstring oldpath,
                            filesystem newfs, inode newwd, sstring newpath,
                            boolean noreplace);
fs_status filesystem_exchange(filesystem fs1, inode wd1, sstring path1,
                              filesystem fs2, inode wd2, sstring path2);

fs_status filesystem_mk_socket(filesystem *fs, inode cwd, sstring path, void *s, inode *n);
fs_status filesystem_get_socket(filesystem *fs, inode cwd, sstring path, tuple *n, void **s);
fs_status filesystem_clear_socket(filesystem fs, inode n);

fs_status filesystem_mount(filesystem parent, inode mount_dir, filesystem child);
void filesystem_unmount(filesystem parent, inode mount_dir, filesystem child, thunk complete);

tuple filesystem_getroot(filesystem fs);
boolean filesystem_is_readonly(filesystem fs);
void filesystem_set_readonly(filesystem fs);

u64 fs_blocksize(filesystem fs);
u64 fs_totalblocks(filesystem fs);
u64 fs_usedblocks(filesystem fs);
u64 fs_freeblocks(filesystem fs);

extern const sstring gitversion;

#define NAME_MAX 255
#define PATH_MAX 4096

static inline buffer linktarget(tuple x)
{
    return get_string(x, sym(linktarget));
}

static inline boolean is_dir(tuple n)
{
    return children(n) ? true : false;
}

static inline boolean is_symlink(tuple n)
{
    return linktarget(n) ? true : false;
}

static inline boolean is_socket(tuple n)
{
    return get(n, sym(socket)) ? true : false;
}

static inline boolean is_special(tuple n)
{
    return get(n, sym(special)) ? true : false;
}

static inline boolean is_regular(tuple n)
{
    return (!is_dir(n) && !is_symlink(n) && !is_socket(n) && !is_special(n));
}

static inline char *path_find_last_delim(sstring path)
{
    return (char *)utf8_find_r(path, '/');
}

static inline sstring filename_from_path(sstring path)
{
    char *filename = path_find_last_delim(path);
    if (!filename) {
        filename = path.ptr;
    } else {
        filename++;
    }
    return isstring(filename, path.len - (filename - path.ptr));
}

/* Expects an empty buffer, and never resizes the buffer. */
boolean dirname_from_path(buffer dest, sstring path);

void fs_set_path_helper(filesystem (*get_root_fs)(), inode (*get_mountpoint)(tuple, filesystem *));

int filesystem_resolve_sstring(filesystem *fs, tuple cwd, sstring f, tuple *entry,
                    tuple *parent);

/* Same as filesystem_resolve_sstring(), except that if the entry is a symbolic link this
 * function follows the link (recursively). */
int filesystem_resolve_sstring_follow(filesystem *fs, tuple cwd, sstring f, tuple *entry,
        tuple *parent);

int filesystem_follow_links(filesystem *fs, tuple link, tuple parent,
                            tuple *target);

int file_get_path(filesystem fs, inode ino, char *buf, u64 len);

#ifdef KERNEL

/* Functions called by filesystem code to notify filesystem operations */
void fs_notify_create(tuple t, tuple parent, symbol name);
void fs_notify_move(tuple t, tuple old_parent, symbol old_name, tuple new_parent, symbol new_name);
void fs_notify_delete(tuple t, tuple parent, symbol name);
void fs_notify_modify(tuple t);
void fs_notify_release(tuple t, boolean unmounted);

#else

#define fs_notify_create(t, p, n)
#define fs_notify_move(t, op, on, np, nn)
#define fs_notify_delete(t, p, n)
#define fs_notify_modify(t)
#define fs_notify_release(t, u)             (void)(t)

#endif

boolean fs_file_is_busy(filesystem fs, tuple md);
