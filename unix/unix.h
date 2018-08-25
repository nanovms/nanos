typedef struct kernel *kernel;
typedef struct process *process;
typedef struct thread *thread;

kernel init_unix(heap h,
		 heap pages,
		 heap physical,
		 heap virtual,
		 heap virtual_pagesized,
		 heap backed,
		 tuple root,
		 filesystem fs);
process create_process(kernel k);
thread create_thread(process p);
process exec_elf(buffer ex, kernel k);
