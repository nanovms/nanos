
// definitions to allow runtime to be compiled in 32 bit
// mode - just jump to 64 bit mode

#define pointer_from_u64(__a) ((u64 *)(void *)(u32)(__a))
#define u64_from_pointer(__a) ((u64)(u32)(__a))
#define physical_from_virtual(__x) u64_from_pointer(__x)
