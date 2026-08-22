typedef struct pagecache_volume *pagecache_volume;

typedef struct pagecache_node *pagecache_node;

closure_type(pagecache_node_reserve, status, range r);
closure_type(pagecache_page_handler, void, range kvirt);

void pagecache_set_node_length(pagecache_node pn, u64 length);

u64 pagecache_get_node_length(pagecache_node pn);

void pagecache_node_finish_pending_writes(pagecache_node pn, status_handler complete);

void pagecache_sync_node(pagecache_node pn, status_handler complete);
void pagecache_purge_node(pagecache_node pn, status_handler complete);

void pagecache_node_ref(pagecache_node pn);
void pagecache_node_unref(pagecache_node pn);

void pagecache_nodelocked_pin(pagecache_node pn, range pages);
void pagecache_nodelocked_unpin(pagecache_node pn, range pages);
void pagecache_node_unpin(pagecache_node pn, range pages);

void pagecache_sync_volume(pagecache_volume pv, status_handler complete);

void *pagecache_get_zero_page(void);

int pagecache_get_page_order(void);

u64 pagecache_get_occupancy(void);

u64 pagecache_drain(u64 drain_bytes, u32 flags);

pagecache_node pagecache_allocate_node(pagecache_volume pv, sg_io fs_read, sg_io fs_write, pagecache_node_reserve fs_reserve);

void pagecache_deallocate_node(pagecache_node pn);

sg_io pagecache_node_get_reader(pagecache_node pn);

sg_io pagecache_node_get_writer(pagecache_node pn);

void pagecache_node_add_mapping(pagecache_node pn , range v /* bytes */, u64 node_offset,
                                boolean shared);

void pagecache_node_scan(pagecache_node pn, range q /* bytes */, status_handler complete);

boolean pagecache_node_do_page_cow(pagecache_node pn, u64 node_offset, u64 vaddr, pageflags flags);

void pagecache_node_fetch_pages(pagecache_node pn, range r /* bytes */, sg_list sg,
                                status_handler complete);

/* Gets the memory backing a node offset, and hands out the kernel virtual range it occupies.
   The size is what the caller would rather have: the cache may lay one contiguous block under a
   whole aligned window of its pages and answer with all of it, so that a mapping of the window
   can be described by a single entry. An empty range means the memory could not be had. */
void pagecache_get_page(pagecache_node pn, u64 node_offset, u64 size, boolean private,
                        pagecache_page_handler handler);
range pagecache_get_page_if_filled(pagecache_node pn, u64 node_offset, boolean private);
void pagecache_release_page(pagecache_node pn, u64 node_offset);

void pagecache_node_unmap_pages(pagecache_node pn, range v /* bytes */, u64 node_offset,
                                boolean del_mappings);

pagecache_volume pagecache_allocate_volume(u64 length, int block_order);

/* Lets the nodes of a volume lay their pages over one contiguous block, so that a mapping of a
   node can be described by a single block PTE. Only for a volume whose pages are cheap to fill:
   a whole window of them is filled at the first fault. */
void pagecache_set_volume_huge(pagecache_volume pv);
void pagecache_dealloc_volume(pagecache_volume pv);

void init_pagecache(heap general, heap contiguous, u64 pagesize);
