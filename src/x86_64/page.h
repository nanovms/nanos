#pragma once

#define INITIAL_MAP_SIZE (0xa000)

#define PAGE_NO_EXEC       U64_FROM_BIT(63)
#define PAGE_NO_FAT        0x0200 /* AVL[0] */
#define PAGE_2M_SIZE       0x0080
#define PAGE_DIRTY         0x0040
#define PAGE_ACCESSED      0x0020
#define PAGE_CACHE_DISABLE 0x0010
#define PAGE_WRITETHROUGH  0x0008
#define PAGE_USER          0x0004
#define PAGE_WRITABLE      0x0002
#define PAGE_PRESENT       0x0001

#define PAGE_FLAGS_MASK    (PAGE_NO_EXEC | PAGEMASK)
#define PAGE_PROT_FLAGS (PAGE_NO_EXEC | PAGE_USER | PAGE_WRITABLE)
#define PAGE_DEV_FLAGS (PAGE_WRITABLE | PAGE_WRITETHROUGH | PAGE_NO_EXEC)

#ifndef physical_from_virtual
physical physical_from_virtual(void *x);
#endif

void map(u64 virtual, physical p, u64 length, u64 flags, heap h);
void unmap(u64 virtual, u64 length, heap h);
void unmap_pages_with_handler(u64 virtual, u64 length, range_handler rh);

static inline void unmap_pages(u64 virtual, u64 length)
{
    unmap_pages_with_handler(virtual, length, 0);
}

void update_map_flags(u64 vaddr, u64 length, u64 flags);
void zero_mapped_pages(u64 vaddr, u64 length);
void remap_pages(u64 vaddr_new, u64 vaddr_old, u64 length, heap h);
void mincore_pages(u64 vaddr, u64 length, u8 * vec);

void dump_ptes(void *x);
