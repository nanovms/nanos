#ifndef _PAGE_HEAP_H_
#define _PAGE_HEAP_H_

heap pageheap_init(heap meta);
boolean pageheap_add_range(u64 base, u64 length);
void pageheap_init_done(void *virt_base, u64 max_page_size);
bytes pageheap_max_pagesize(void);
void pageheap_range_foreach(range_handler rh);

#endif
