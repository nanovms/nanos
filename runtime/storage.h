
// entry
//   key - offset into symbol table
//   offset - offset into body
//   length - body length or -1 for snode


#define storage_type_tuple 1
#define storage_type_unaligned 2
#define storage_type_aligned 3
#define STORAGE_TYPE_OFFSET 30
#define STORAGE_SLOT_SIZE 12


#define ENTRY_ALIGNMENT_LOG 2
#define ENTRY_LENGTH 12
typedef u32 offset;

#define STORAGE_LEN_MAP (-1ul)

#define naddr(__n, __o) (__n.base + (__o << ENTRY_ALIGNMENT_LOG))
#define is_empty(__n) ((__n).base == INVALID_ADDRESS)
