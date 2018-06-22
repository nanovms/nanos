typedef struct filesystem *filesystem;
typedef struct fsfile *fsfile;
filesystem create_filesystem(heap h, u64 alignment, u64 size, block_read, block_write, tuple root);
// there is a question as to whether tuple->fs file should be mapped inside out outside the filesystem
// status
void filesystem_read(filesystem fs, tuple t, void *dest, u64 offset, u64 length, status_handler completion);
void filesystem_write(filesystem fs, tuple t, buffer b, u64 offset, status_handler completion);
u64 file_length(fsfile f);
fsfile file_lookup(filesystem fs, vector v);
tuple resolve_cstring(tuple root, char *f);
void filesystem_read_entire(filesystem fs, tuple t, heap h, buffer_handler c);

    

