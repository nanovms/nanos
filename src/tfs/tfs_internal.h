#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif
#include <pagecache.h>
#include <storage.h>
#include <tfs.h>

#define TFS_VERSION 0x00000004

#ifdef KERNEL

#define filesystem_lock_init(fs)    spin_lock_init(&(fs)->lock)
#define filesystem_lock(fs)         spin_lock(&(fs)->lock)
#define filesystem_unlock(fs)       spin_unlock(&(fs)->lock)

#else

#define filesystem_lock_init(fs)
#define filesystem_lock(fs)         ((void)fs)
#define filesystem_unlock(fs)       ((void)fs)

#endif

typedef struct log *log;

declare_closure_struct(1, 0, void, fs_sync,
                       struct filesystem *, fs);
declare_closure_struct(1, 1, void, fs_free,
                       struct filesystem *, fs,
                       status, s);

typedef struct filesystem {
    rangemap storage;
    u64 size;
    heap h;
    int blocksize_order;
    int alignment_order;        /* in blocks */
    int page_order;
    u8 uuid[UUID_LEN];
    char label[VOLUME_LABEL_MAX_LEN];
    table files; // maps tuple to fsfile
    closure_type(log, void, tuple);
    heap dma;
    void *zero_page;
    storage_req_handler req_handler;
    boolean ro; /* true for read-only filesystem */
    pagecache_volume pv;
    log tl;
    log temp_log;
    u64 next_extend_log_offset;
    u64 next_new_log_offset;
    tuple root;
#ifdef KERNEL
    struct spinlock lock;
#endif
    struct refcount refcount;
    closure_struct(fs_sync, sync);
    thunk sync_complete;
    closure_struct(fs_free, free);
} *filesystem;

/* fsfile status flags */
#define FSF_DIRTY_DATASYNC  (1 << 0)    /* metadata needed for retrieving file data */
#define FSF_DIRTY_OTHER     (1 << 1)    /* any other metadata */
#define FSF_DIRTY           (FSF_DIRTY_DATASYNC | FSF_DIRTY_OTHER)

declare_closure_struct(1, 1, void, fsf_sync_complete,
                       struct fsfile *, f,
                       status, s);

typedef struct fsfile {
    rangemap extentmap;
    filesystem fs;
    pagecache_node cache_node;
    u64 length;
    tuple md;
    sg_io read;
    sg_io write;
    struct refcount refcount;
    closure_struct(fsf_sync_complete, sync_complete);
    u8 status;
} *fsfile;

typedef struct uninited_queued_op {
    sg_list sg;
    merge m;
    range blocks;
    boolean write;
} *uninited_queued_op;

declare_closure_struct(2, 0, void, free_uninited,
                       heap, h, struct uninited *, u);

declare_closure_struct(2, 1, void, uninited_complete,
                       struct uninited *, u, status_handler, complete,
                       status, s);

typedef struct uninited {
    filesystem fs;
#ifdef KERNEL
    struct spinlock lock;
#endif
    struct refcount refcount;
    buffer op_queue;
    boolean initialized;
    closure_struct(uninited_complete, complete);
    closure_struct(free_uninited, free);
} *uninited;

typedef struct extent {
    /* these are in block units */
    struct rmnode node;         /* must be first */
    u64 start_block;
    u64 allocated;
    tuple md;                   /* shortcut to extent meta */
    uninited uninited;
} *extent;

void ingest_extent(fsfile f, symbol foff, tuple value);

log log_create(heap h, filesystem fs, boolean initialize, status_handler sh);
boolean log_write(log tl, tuple t);
boolean log_write_eav(log tl, tuple e, symbol a, value v);
void log_flush(log tl, status_handler completion);
void log_destroy(log tl);
void flush(filesystem fs, status_handler);
u64 filesystem_allocate_storage(filesystem fs, u64 nblocks);
boolean filesystem_reserve_storage(filesystem fs, range storage_blocks);
boolean filesystem_free_storage(filesystem fs, range storage_blocks);
void filesystem_storage_op(filesystem fs, sg_list sg, range blocks, boolean write,
                           status_handler completion);
    
void filesystem_log_rebuild(filesystem fs, log new_tl, status_handler sh);
void filesystem_log_rebuild_done(filesystem fs, log new_tl);

boolean filesystem_reserve_log_space(filesystem fs, u64 *next_offset, u64 *offset, u64 size);

typedef closure_type(buffer_status, buffer, status);
fsfile allocate_fsfile(filesystem fs, tuple md);

boolean file_tuple_is_ancestor(tuple t1, tuple t2, tuple p2);

#define filesystem_log_blocks(fs) (TFS_LOG_DEFAULT_EXTENSION_SIZE >> (fs)->blocksize_order)

static inline u64 bytes_from_sectors(filesystem fs, u64 sectors)
{
    return sectors << fs->blocksize_order;
}

static inline u64 sector_from_offset(filesystem fs, bytes b)
{
    return b >> fs->blocksize_order;
}
