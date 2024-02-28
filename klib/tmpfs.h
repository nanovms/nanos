#ifndef _TMPFS_H_
#define _TMPFS_H_

typedef struct tmpfs {
    struct filesystem fs;
    table files;
    int page_order;
} *tmpfs;

filesystem tmpfs_new(void);

#endif
