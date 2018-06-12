#include <runtime.h>
#include <tfs.h>

// ok, we wanted to make the inode number extensional, but holes
// and random access writes make that difficult, so this is stateful
// with an inode

typedef struct filesystem {
    heap storage;
    heap h;
    int alignment;
    table files;
    closure_type(log, void, tuple);
    fio write, read;
    u64 inode_count;
} *filesystem;

