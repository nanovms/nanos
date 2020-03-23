#include <runtime.h>
#include <tfs.h>

#define TFS_VERSION 0x00000001

// ok, we wanted to make the inode number extensional, but holes
// and random access writes make that difficult, so this is stateful
// with an inode

typedef struct log *log;

struct cbm {
    u8 *buffer;
    u64 capacity_in_bits;
};

typedef struct filesystem {
    id_heap storage;
    struct cbm *free;
    heap h;
    int alignment;
    table files; // maps tuple to fsfile
    table extents; // maps extents
    closure_type(log, void, tuple);
    heap dma;
    block_io r;
    block_io w;
    log tl;
    tuple root;
    int blocksize_order;
} *filesystem;

void ingest_extent(fsfile f, symbol foff, tuple value);

log log_create(heap h, filesystem fs, boolean initialize, status_handler sh);
void log_write(log tl, tuple t, status_handler sh);
void log_write_eav(log tl, tuple e, symbol a, value v, status_handler sh);
void read_log(log tl, status_handler sh);
void log_flush(log tl);
void log_flush_complete(log tl, status_handler completion);
void flush(filesystem fs, status_handler);
boolean filesystem_reserve_storage(filesystem fs, u64 start, u64 length);
    
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
