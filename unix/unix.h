void init_unix(heap, heap, heap, tuple);
typedef struct process *process;
typedef struct thread *thread;
process create_process(heap h, heap pages, heap physical, tuple filesystem);
thread create_thread(process p);
process exec_elf(buffer ex, heap general, heap physical, heap pages, heap virtual, tuple fs);
