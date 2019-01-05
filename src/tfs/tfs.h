#pragma once
typedef struct filesystem *filesystem;
typedef struct fsfile *fsfile;

typedef closure_type(filesystem_complete, void, filesystem, status);
typedef closure_type(io_status_handler, void, status, bytes);

extern io_status_handler ignore_io_status;

#define SECTOR_OFFSET 9ULL
#define SECTOR_SIZE (1ULL << SECTOR_OFFSET)

void create_filesystem(heap h,
                       u64 alignment,
                       u64 size,
                       block_read read,
                       block_write write,
                       tuple root,
                       filesystem_complete complete);

// there is a question as to whether tuple->fs file should be mapped inside out outside the filesystem
// status
void filesystem_read(filesystem fs, tuple t, void *dest, u64 offset, u64 length, io_status_handler completion);
void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, io_status_handler completion);
u64 fsfile_get_length(fsfile f);
void fsfile_set_length(fsfile f, u64);
fsfile fsfile_from_node(filesystem fs, tuple n);
fsfile file_lookup(filesystem fs, vector v);
void filesystem_read_entire(filesystem fs, tuple t, heap h, buffer_handler c, status_handler s);
// need to provide better/more symmetric access to metadata, but ...
void filesystem_write_tuple(filesystem fs, tuple t);
void filesystem_write_eav(filesystem fs, tuple t, symbol a, value v);
fsfile allocate_fsfile(filesystem fs, tuple md);
// per-file flush
void flush(filesystem fs, status_handler s);

typedef enum {
    FS_STATUS_OK = 0,
    FS_STATUS_NOENT,
    FS_STATUS_EXIST,
    FS_STATUS_NOTDIR,
} fs_status;

fs_status filesystem_mkentry(filesystem fs, tuple root, char *fp, tuple entry);
fs_status filesystem_mkdir(filesystem fs, tuple root, char *fp);
fs_status filesystem_creat(filesystem fs, char *fp);

tuple filesystem_getroot(filesystem fs);
