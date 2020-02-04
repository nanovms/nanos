typedef struct kernel_heaps *kernel_heaps;
typedef struct unix_heaps *unix_heaps;
typedef struct process *process;
typedef struct thread *thread;

process init_unix(kernel_heaps kh, tuple root, filesystem fs);
process create_process(unix_heaps uh, tuple root, filesystem fs);
thread create_thread(process p);
process exec_elf(buffer ex, process kernel_process);

void proc_enter_user(process p);
void proc_enter_system(process p);
void proc_pause(process p);
void proc_resume(process p);

timestamp proc_utime(process p);
timestamp proc_stime(process p);
