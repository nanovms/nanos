#pragma once
typedef struct kernel_heaps *kernel_heaps;
typedef struct unix_heaps *unix_heaps;
typedef struct process *process;
typedef struct thread *thread;

process init_unix(kernel_heaps kh, tuple root, filesystem fs, void *stack_top);
process create_process(unix_heaps uh, tuple root, filesystem fs);
thread create_thread(process, void*);
process exec_elf(buffer ex, process kernel_process);
