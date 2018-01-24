typedef struct process *process;
typedef struct thread *thread;

process create_process(heap, buffer);
thread create_thread(process);
void run(thread);

