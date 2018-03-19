#include <syscalls.h>
#include <system_structs.h>

typedef struct process *process;
typedef struct thread *thread;

process create_process(heap h, heap pages, heap contig, node filesystem);
thread create_thread(process);
void run(thread);


typedef struct thread {
    process p;
    u64 frame[20];
    void *set_child_tid;
    void *clear_child_tid;
    u64 tid;
} *thread;

typedef struct process *process;

typedef closure_type(io, int, void *, u64 length, u64 offset);


void init_unix(heap);
