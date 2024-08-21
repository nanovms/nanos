#include "fs.h"

typedef struct tfs *tfs;
typedef struct tfsfile *tfsfile;

extern io_status_handler ignore_io_status;

#define MIN_EXTENT_SIZE PAGESIZE
#define MAX_EXTENT_SIZE (PAGECACHE_MAX_SG_ENTRIES * PAGESIZE)
#define MIN_EXTENT_ALLOC_SIZE   (1 * MB)

status filesystem_probe(u8 *first_sector, u8 *uuid, char *label);
sstring filesystem_get_label(filesystem fs);
void filesystem_get_uuid(filesystem fs, u8 *uuid);

void create_filesystem(heap h,
                       u64 blocksize,
                       u64 size,
                       storage_req_handler req_handler,
                       boolean ro,
                       sstring label,
                       filesystem_complete complete);
void destroy_filesystem(filesystem fs);

fsfile fsfile_from_node(filesystem fs, tuple n);
tfsfile allocate_fsfile(tfs fs, tuple md);

int filesystem_write_tuple(tfs fs, tuple t);
int filesystem_write_eav(tfs fs, tuple t, symbol a, value v, boolean cleanup);

int filesystem_mkentry(filesystem fs, tuple cwd, sstring fp, tuple entry,
    boolean persistent, boolean recursive);
int filesystem_mkdirpath(filesystem fs, tuple cwd, sstring fp,
        boolean persistent);
