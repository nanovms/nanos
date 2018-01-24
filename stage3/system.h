typedef struct process *process;
typedef struct thread *thread;

process create_process(heap);
thread create_thread(process);
void run(thread);

