typedef struct filesystem *filesystem;

typedef closure_type(filesystem_complete, void, filesystem, status);

typedef struct fsfile *fsfile;

pagecache_volume filesystem_get_pagecache_volume(filesystem fs);

u64 fsfile_get_length(fsfile f);
void fsfile_set_length(fsfile f, u64 length);
tuple fsfile_get_meta(fsfile f);
sg_io fsfile_get_reader(fsfile f);
sg_io fsfile_get_writer(fsfile f);
pagecache_node fsfile_get_cachenode(fsfile f);

extern io_status_handler ignore_io_status;

#define MIN_EXTENT_SIZE PAGESIZE
#define MAX_EXTENT_SIZE (1 * MB)

boolean filesystem_probe(u8 *first_sector, u8 *uuid);
void filesystem_get_uuid(filesystem fs, u8 *uuid);

void create_filesystem(heap h,
                       u64 blocksize,
                       u64 size,
                       block_io read,
                       block_io write,
                       boolean initialize,
                       filesystem_complete complete);
void destroy_filesystem(filesystem fs);

// there is a question as to whether tuple->fs file should be mapped inside out outside the filesystem
// status

// turn these into method gets rather than call
void filesystem_read_sg(fsfile f, sg_list sg, range q, status_handler completion);

void filesystem_write_sg(fsfile f, sg_list sg, range q, status_handler completion);

/* deprecate these if we can */
void filesystem_read_linear(fsfile f, void *dest, range q, io_status_handler completion);
void filesystem_write_linear(fsfile f, void *src, range q, io_status_handler completion);

void filesystem_flush(filesystem fs, status_handler completion);

timestamp filesystem_get_atime(filesystem fs, tuple t);
timestamp filesystem_get_mtime(filesystem fs, tuple t);
void filesystem_set_atime(filesystem fs, tuple t, timestamp tim);
void filesystem_set_mtime(filesystem fs, tuple t, timestamp tim);

#define filesystem_update_atime(fs, t) \
    filesystem_set_atime(fs, t, now(CLOCK_ID_REALTIME))
#define filesystem_update_mtime(fs, t) \
    filesystem_set_mtime(fs, t, now(CLOCK_ID_REALTIME))

u64 fsfile_get_length(fsfile f);
void fsfile_set_length(fsfile f, u64);
fsfile fsfile_from_node(filesystem fs, tuple n);
fsfile file_lookup(filesystem fs, vector v);
void filesystem_read_entire(filesystem fs, tuple t, heap bufheap, buffer_handler c, status_handler s);
fsfile allocate_fsfile(filesystem fs, tuple md);
// XXX per-file flush

typedef enum {
    FS_STATUS_OK = 0,
    FS_STATUS_NOSPACE,
    FS_STATUS_IOERR,
    FS_STATUS_NOENT,
    FS_STATUS_EXIST,
    FS_STATUS_NOTDIR,
    FS_STATUS_NOMEM,
} fs_status;

fs_status filesystem_write_tuple(filesystem fs, tuple t);
fs_status filesystem_write_eav(filesystem fs, tuple t, symbol a, value v);

typedef closure_type(fs_status_handler, void, fsfile, fs_status);

void filesystem_alloc(filesystem fs, tuple t, long offset, long len,
        boolean keep_size, fs_status_handler completion);
void filesystem_dealloc(filesystem fs, tuple t, long offset, long len,
        fs_status_handler completion);
fs_status filesystem_truncate(filesystem fs, fsfile f, u64 len);

fs_status do_mkentry(filesystem fs, tuple parent, const char *name, tuple entry,
        boolean persistent);

fs_status filesystem_mkentry(filesystem fs, tuple cwd, const char *fp, tuple entry,
    boolean persistent, boolean recursive);
fs_status filesystem_mkdirpath(filesystem fs, tuple cwd, const char *fp,
        boolean persistent);
tuple filesystem_mkdir(filesystem fs, tuple parent, const char *name);
tuple filesystem_creat(filesystem fs, tuple parent, const char *name);
tuple filesystem_symlink(filesystem fs, tuple parent, const char *name,
                         const char *target);
fs_status filesystem_delete(filesystem fs, tuple parent, symbol sym);
fs_status filesystem_rename(filesystem fs, tuple oldparent, symbol oldsym,
                       tuple newparent, const char *newname);
fs_status filesystem_exchange(filesystem fs, tuple parent1, symbol sym1,
                         tuple parent2, symbol sym2);

tuple filesystem_getroot(filesystem fs);

u64 fs_blocksize(filesystem fs);
u64 fs_totalblocks(filesystem fs);
u64 fs_freeblocks(filesystem fs);

extern const char *gitversion;
