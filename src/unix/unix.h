typedef struct kernel_heaps *kernel_heaps;
typedef struct unix_heaps *unix_heaps;
typedef struct process *process;
typedef struct thread *thread;

process init_unix(kernel_heaps kh, tuple root, filesystem fs);
process create_process(unix_heaps uh, tuple root, filesystem fs);
void process_get_cwd(process p, filesystem *cwd_fs, inode *cwd);
thread create_thread(process p, u64 tid);
process exec_elf(buffer ex, process kernel_process);
void unix_shutdown(void);

void program_set_perms(tuple root, tuple prog);

void dump_mem_stats(buffer b);

void coredump_set_limit(u64 s);
u64 coredump_get_limit(void);

timestamp proc_utime(process p);
timestamp proc_stime(process p);

timestamp thread_utime(thread t);
timestamp thread_stime(thread t);
