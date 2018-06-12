typedef struct filesystem *filesystem;
typedef struct fsfile *fsfile;
typedef closure_type(fio, void, void *, u64, u64, thunk);
filesystem create_filesystem(heap h, u64 alignment, u64 size, fio read, fio write);
void fs_read(fsfile f, void *target, u64 offset, u64 length, thunk completion);
void fs_write(fsfile f, void *target, u64 offset, u64 length, thunk completion);
u64 file_length(fsfile f);
fsfile file_lookup(filesystem fs, vector v);


    
