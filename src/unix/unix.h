typedef struct kernel_heaps *kernel_heaps;
typedef struct unix_heaps *unix_heaps;
typedef struct process *process;
typedef struct thread *thread;

process init_unix(kernel_heaps kh, tuple root, filesystem fs);
process create_process(unix_heaps uh, tuple root, filesystem fs);
thread create_thread(process p);
process exec_elf(buffer ex, process kernel_process);

void thread_enter_user(thread out, thread in);
void thread_enter_system(thread t);
void thread_pause(thread t);
void thread_resume(thread t);

timestamp proc_utime(process p);
timestamp proc_stime(process p);

timestamp thread_utime(thread t);
timestamp thread_stime(thread t);
