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

void map(u64 virtual, physical p, int length, u64 flags, heap h);
void vremap(void *old_virtual, u64 old_size,
            u64 new_virtual, u64 flags, heap h);
void unmap(u64 virtual, int length, heap h);
