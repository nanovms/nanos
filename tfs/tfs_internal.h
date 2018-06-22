#include <runtime.h>
#include <tfs.h>

// ok, we wanted to make the inode number extensional, but holes
// and random access writes make that difficult, so this is stateful
// with an inode

typedef struct log *log;

typedef struct filesystem {
    heap storage;
    heap h;
    int alignment;
    table files; // maps tuple to fsfile
    closure_type(log, void, tuple);
    block_read r;
    block_write w;    
    log l;
} *filesystem;

void log_write_eav(log tl, tuple e, symbol a, value v, thunk complete);

