typedef struct filesystem *filesystem;
typedef struct fsfile *fsfile;

typedef closure_type(filesystem_complete, void, filesystem, status);

extern io_status_handler ignore_io_status;

#define SECTOR_OFFSET 9ULL
#define SECTOR_SIZE (1ULL << SECTOR_OFFSET)
#define MIN_EXTENT_SIZE PAGESIZE
#define MAX_EXTENT_SIZE (1 * MB)

void create_filesystem(heap h,
                       u64 alignment,
                       u64 blocksize,
                       u64 size,
                       heap dma,
                       sg_block_io read,
                       block_io write,
                       tuple root,
                       boolean initialize,
                       filesystem_complete complete);

// there is a question as to whether tuple->fs file should be mapped inside out outside the filesystem
// status
void filesystem_read_sg(filesystem fs, tuple t, sg_list sg, u64 length, u64 offset, status_handler sh);
void filesystem_read_linear(filesystem fs, tuple t, void *dest, u64 offset, u64 length, io_status_handler completion);
void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, io_status_handler completion);
boolean filesystem_truncate(filesystem fs, fsfile f, u64 len,
        status_handler completion);
void filesystem_flush(filesystem fs, tuple t, status_handler completion);

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
// need to provide better/more symmetric access to metadata, but ...
void filesystem_write_tuple(filesystem fs, tuple t, status_handler sh);
void filesystem_write_eav(filesystem fs, tuple t, symbol a, value v, status_handler sh);
fsfile allocate_fsfile(filesystem fs, tuple md);
// per-file flush

typedef enum {
    FS_STATUS_OK = 0,
    FS_STATUS_NOSPACE,
    FS_STATUS_IOERR,
    FS_STATUS_NOENT,
    FS_STATUS_EXIST,
    FS_STATUS_NOTDIR,
} fs_status;

typedef closure_type(fs_status_handler, void, fsfile, fs_status);

void filesystem_alloc(filesystem fs, tuple t, long offset, long len,
        boolean keep_size, fs_status_handler completion);
void filesystem_dealloc(filesystem fs, tuple t, long offset, long len,
        fs_status_handler completion);

void do_mkentry(filesystem fs, tuple parent, const char *name, tuple entry,
        boolean persistent);

fs_status filesystem_mkentry(filesystem fs, tuple cwd, const char *fp, tuple entry,
    boolean persistent, boolean recursive);
fs_status filesystem_mkdirpath(filesystem fs, tuple cwd, const char *fp,
        boolean persistent);
tuple filesystem_mkdir(filesystem fs, tuple parent, const char *name,
        status_handler completion);
tuple filesystem_creat(filesystem fs, tuple parent, const char *name,
        status_handler completion);
tuple filesystem_symlink(filesystem fs, tuple parent, const char *name,
        const char *target, status_handler completion);
void filesystem_delete(filesystem fs, tuple parent, symbol sym,
    status_handler completion);
void filesystem_rename(filesystem fs, tuple oldparent, symbol oldsym,
        tuple newparent, const char *newname, status_handler completion);
void filesystem_exchange(filesystem fs, tuple parent1, symbol sym1,
        tuple parent2, symbol sym2, status_handler completion);

tuple filesystem_getroot(filesystem fs);

u64 fs_blocksize(filesystem fs);
u64 fs_totalblocks(filesystem fs);
u64 fs_freeblocks(filesystem fs);

extern const char *gitversion;
