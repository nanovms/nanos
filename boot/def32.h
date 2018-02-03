
// definitions to allow runtime to be compiled for 32 pointers

#define pointer_from_u64(__a) ((void *)(u32)(__a))
#define u64_from_pointer(__a) ((u64)(u32)(__a))
#define physical_from_virtual(__x) u64_from_pointer(__x)
