#include "fs.h"

typedef struct tfs *tfs;
typedef struct tfsfile *tfsfile;

extern io_status_handler ignore_io_status;

#define MIN_EXTENT_SIZE PAGESIZE
#define MIN_EXTENT_ALLOC_SIZE   (1 * MB)

boolean filesystem_probe(u8 *first_sector, u8 *uuid, char *label);
const char *filesystem_get_label(filesystem fs);
void filesystem_get_uuid(filesystem fs, u8 *uuid);

void create_filesystem(heap h,
                       u64 blocksize,
                       u64 size,
                       storage_req_handler req_handler,
                       boolean ro,
                       const char *label,
                       filesystem_complete complete);
void destroy_filesystem(filesystem fs);

fsfile fsfile_from_node(filesystem fs, tuple n);
tfsfile allocate_fsfile(tfs fs, tuple md);

fs_status filesystem_write_tuple(tfs fs, tuple t);
fs_status filesystem_write_eav(tfs fs, tuple t, symbol a, value v);

fs_status filesystem_mkentry(filesystem fs, tuple cwd, const char *fp, tuple entry,
    boolean persistent, boolean recursive);
fs_status filesystem_mkdirpath(filesystem fs, tuple cwd, const char *fp,
        boolean persistent);
