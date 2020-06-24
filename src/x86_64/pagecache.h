typedef struct pagecache *pagecache;

typedef struct pagecache_volume *pagecache_volume;

typedef struct pagecache_node *pagecache_node;

/* consider returning immediate result or status? */
void pagecache_read_sg(pagecache_node pn, sg_list sg, range q, status_handler sh);

void pagecache_write_sg(pagecache_node pn, sg_list sg, range q, status_handler sh);

void pagecache_write(pagecache_node pn, void *buf, range q, status_handler sh);

void pagecache_set_node_length(pagecache_node pn, u64 length);

void pagecache_sync_node(pagecache_node pn, status_handler sh);

void pagecache_sync_volume(pagecache_volume pv, status_handler sh);

void *pagecache_get_zero_page(pagecache pc);

int pagecache_get_page_order(pagecache pc);

// TODO - not clear yet, maybe for range?
void pagecache_invalidate_node(pagecache_node pn);

u64 pagecache_drain(pagecache pc, u64 drain_bytes);

pagecache_node pagecache_allocate_node(pagecache_volume pv, sg_io fs_read, sg_io fs_write);

// TODO - closure dealloc
void pagecache_deallocate_node(pagecache_node pn);

sg_io pagecache_node_get_reader(pagecache_node pn);

sg_io pagecache_node_get_writer(pagecache_node pn);

pagecache_volume pagecache_allocate_volume(pagecache pc, u64 length, int block_order);

pagecache allocate_pagecache(heap general, heap contiguous, u64 pagesize);

void deallocate_pagecache(pagecache pc);
