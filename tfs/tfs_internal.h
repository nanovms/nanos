#pragma once
#include <runtime.h>
#include <tfs.h>

// ok, we wanted to make the inode number extensional, but holes
// and random access writes make that difficult, so this is stateful
// with an inode

typedef struct log *log;

typedef struct filesystem {
    heap storage;
    rtrie free;
    heap h;
    int alignment;
    table files; // maps tuple to fsfile
    table extents; // maps extents
    closure_type(log, void, tuple);
    block_read r;
    block_write w;    
    log tl;
    tuple root;
    bytes blocksize;
} *filesystem;

void extent_update(fsfile f, symbol foff, tuple value);

log log_create(heap h, filesystem fs, status_handler sh);
void log_write(log tl, tuple t, thunk complete);
void log_write_eav(log tl, tuple e, symbol a, value v, thunk complete);

// xxx - tlog.c is using rolling to hold the staging buffer, which currently doesn't deal with multiple
// allocations properly - take this out of backed
#define INITIAL_LOG_SIZE (3*KB)
#define INITIAL_FS_SIZE (20 * MB)
void read_log(log tl, u64 offset, u64 size, status_handler sh);
void log_flush(log tl);
void flush(filesystem fs, status_handler);
    
typedef closure_type(buffer_status, buffer, status);
fsfile allocate_fsfile(filesystem fs, tuple md);
