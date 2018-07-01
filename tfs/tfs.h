typedef struct filesystem *filesystem;
typedef struct fsfile *fsfile;
filesystem create_filesystem(heap h,
                             u64 alignment,
                             u64 size,
                             block_read read,
                             block_write write,
                             tuple root);
// there is a question as to whether tuple->fs file should be mapped inside out outside the filesystem
// status
void filesystem_read(filesystem fs, tuple t, void *dest, u64 offset, u64 length, status_handler completion);
void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, status_handler completion);
u64 file_length(fsfile f);
fsfile file_lookup(filesystem fs, vector v);
void filesystem_read_entire(filesystem fs, tuple t, heap h, buffer_handler c);
// need to provide better/more symmetric access to metadata, but ...
void filesystem_write_tuple(filesystem fs, tuple t);
void filesystem_write_eav(filesystem fs, tuple t, symbol a, value v);
fsfile allocate_fsfile(filesystem fs, tuple md);
// per-file flush
void flush(filesystem fs, status_handler s);
