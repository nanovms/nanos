typedef struct process *process;
typedef struct thread *thread;

process create_process(heap h, heap pages, heap contig, buffer filesystem);
thread create_thread(process);
void run(thread);

