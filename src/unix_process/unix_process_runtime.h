typedef int descriptor;
heap init_process_runtime();
heap allocate_mmapheap(heap meta, bytes size);
heap make_tiny_heap(heap parent);
tuple parse_arguments(heap h, int argc, char **argv);
