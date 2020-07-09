#ifdef STAGE3
#include <kernel.h>
#else
#include <runtime.h>
#endif
#include <pagecache.h>
#include <tfs.h>

#define TFS_VERSION 0x00000002

typedef struct log *log;

typedef struct filesystem {
    id_heap storage;
    u64 size;
    heap h;
    int blocksize_order;
    int alignment_order;        /* in blocks */
    int page_order;
    table files; // maps tuple to fsfile
    table extents; // maps extents
    closure_type(log, void, tuple);
    heap dma;
    void *zero_page;
    block_io r;
    block_io w;
    pagecache pc;
    pagecache_volume pv;
    log tl;
    tuple root;
} *filesystem;

typedef struct fsfile {
    rangemap extentmap;
    filesystem fs;
    pagecache_node cache_node;
    u64 length;
    tuple md;
    sg_io read;
    sg_io write;
} *fsfile;

typedef struct extent {
    /* these are in block units */
    struct rmnode node;         /* must be first */
    u64 start_block;
    u64 allocated;
    tuple md;                   /* shortcut to extent meta */
    boolean uninited;
} *extent;

void ingest_extent(fsfile f, symbol foff, tuple value);

log log_create(heap h, filesystem fs, boolean initialize, status_handler sh);
void log_write(log tl, tuple t);
void log_write_eav(log tl, tuple e, symbol a, value v);
void log_flush(log tl, status_handler completion);
void log_destroy(log tl);
void flush(filesystem fs, status_handler);
boolean filesystem_reserve_storage(filesystem fs, range storage_blocks);
void filesystem_storage_op(filesystem fs, sg_list sg, merge m, range blocks, block_io op);
    
typedef closure_type(buffer_status, buffer, status);
fsfile allocate_fsfile(filesystem fs, tuple md);

static inline u64 bytes_from_sectors(filesystem fs, u64 sectors)
{
    return sectors << fs->blocksize_order;
}

static inline u64 sector_from_offset(filesystem fs, bytes b)
{
    return b >> fs->blocksize_order;
}
