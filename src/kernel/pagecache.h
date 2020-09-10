typedef struct pagecache_volume *pagecache_volume;

typedef struct pagecache_node *pagecache_node;

void pagecache_set_node_length(pagecache_node pn, u64 length);

u64 pagecache_get_node_length(pagecache_node pn);

void pagecache_node_finish_pending_writes(pagecache_node pn, status_handler complete);

void pagecache_sync_node(pagecache_node pn, status_handler complete);

void pagecache_sync_volume(pagecache_volume pv, status_handler complete);

void *pagecache_get_zero_page();

int pagecache_get_page_order();

u64 pagecache_drain(u64 drain_bytes);

pagecache_node pagecache_allocate_node(pagecache_volume pv, sg_io fs_read, sg_io fs_write);

void pagecache_deallocate_node(pagecache_node pn);

sg_io pagecache_node_get_reader(pagecache_node pn);

sg_io pagecache_node_get_writer(pagecache_node pn);

void pagecache_map_page(pagecache_node pn, u64 node_offset, u64 vaddr, u64 flags,
                        status_handler complete);

boolean pagecache_map_page_if_filled(pagecache_node pn, u64 node_offset, u64 vaddr, u64 flags);

boolean pagecache_node_do_page_cow(pagecache_node pn, u64 node_offset, u64 vaddr, u64 flags);

void pagecache_node_fetch_pages(pagecache_node pn, range r /* bytes */);

void pagecache_node_scan_and_commit_shared_pages(pagecache_node pn, range q /* bytes */);

void pagecache_node_close_shared_pages(pagecache_node pn, range q /* bytes */);

void pagecache_node_unmap_pages(pagecache_node pn, range v /* bytes */, u64 node_offset);

void pagecache_node_add_shared_map(pagecache_node pn , range v /* bytes */, u64 node_offset);

pagecache_volume pagecache_allocate_volume(u64 length, int block_order);
void pagecache_dealloc_volume(pagecache_volume pv);

void init_pagecache(heap general, heap contiguous, heap physical, u64 pagesize);
