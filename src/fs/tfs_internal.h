#ifdef KERNEL
#include <kernel.h>
#include <pagecache.h>
#else
#include <runtime.h>
#endif
#include <storage.h>
#include <tfs.h>

#define TFS_VERSION 0x00000005

typedef struct log *log;

typedef struct tfs {
    struct filesystem fs;   /* must be first */
    rangemap storage;
#ifdef KERNEL
    struct spinlock storage_lock;
#endif
    int alignment_order;        /* in blocks */
    int page_order;
    u8 uuid[UUID_LEN];
    char label[VOLUME_LABEL_MAX_LEN];
    table files; // maps tuple to fsfile
    heap dma;
    void *zero_page;
    storage_req_handler req_handler;
    log tl;
    log temp_log;
    u64 next_extend_log_offset;
    u64 next_new_log_offset;
} *tfs;

typedef struct tfsfile {
    struct fsfile f;    /* must be first */
    rangemap extentmap;
} *tfsfile;

declare_closure_struct(2, 0, void, free_uninited,
                       heap, h, struct uninited *, u);

declare_closure_struct(2, 1, void, uninited_complete,
                       struct uninited *, u, status_handler, complete,
                       status s);

typedef struct uninited {
    tfs fs;
    struct refcount refcount;
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

void ingest_extent(tfsfile f, symbol foff, tuple value);

log log_create(heap h, tfs fs, boolean initialize, status_handler sh);
boolean log_write(log tl, tuple t);
boolean log_write_eav(log tl, tuple e, symbol a, value v);
void log_flush(log tl, status_handler completion);
void log_destroy(log tl);
u64 filesystem_allocate_storage(tfs fs, u64 nblocks);
boolean filesystem_reserve_storage(tfs fs, range storage_blocks);
boolean filesystem_free_storage(tfs fs, range storage_blocks);
void filesystem_storage_op(tfs fs, sg_list sg, range blocks, boolean write,
                           status_handler completion);

void filesystem_log_rebuild(tfs fs, log new_tl, status_handler sh);
void filesystem_log_rebuild_done(tfs fs, log new_tl);

boolean filesystem_reserve_log_space(tfs fs, u64 *next_offset, u64 *offset, u64 size);

tfsfile allocate_fsfile(tfs fs, tuple md);

#define filesystem_log_blocks(fs) (TFS_LOG_DEFAULT_EXTENSION_SIZE >> (fs)->fs.blocksize_order)
