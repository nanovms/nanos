typedef int descriptor;
heap init_process_runtime();
sstring errno_sstring(void);
heap allocate_mmapheap(heap meta, bytes size);
heap make_tiny_heap(heap parent);
tuple parse_arguments(heap h, int argc, char **argv);
