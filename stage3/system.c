#include <runtime.h>
#include <syscalls.h>
#include <system_structs.h>

unsigned int process_count = 110;

typedef struct file {
    // make this buffery?
    // make this closury?
    void *state;
    u64 offset; //stupid implicit offset interface
    int (*write)(void *f, void *body, bytes length);
    int (*read)(void *f, void *body, bytes length, bytes offset);    
} *file;

typedef struct process {
    heap h;
    int pid;
    buffer filesystem;
    // create stdout
    struct file files[32];
    int filecount;
    void *brk;
} *process;

typedef struct thread {
    process p;
    u64 frame[19];
} *thread;
    
thread current;

// could really take the args directly off the function..maybe dispatch in
// asm
// packed?

static int readbufferv(void *z, void *dest, u64 length, u64 offset)
{
    rprintf("read: %d %d\n", length, offset);
    // um, truncate read past boundary
    buffer b = z;
    runtime_memcpy(b->contents + b->start + offset, dest, length);
    return length;
}

// mux
static int write(int fd, u8 *body, bytes length)
{
    for (int i = 0; i< length; i++) serial_out(body[i]);
}

static int writev(int fd, iovec v, int count)
{
    for (int i = 0; i < count; i++)
        write(fd, v[i].address, v[i].length);
}

#define staticbuffer(__n) ({ \
    static struct buffer _ssym##__n;\
    static char _cont##__n[] = #__n; \
    if (_ssym##__n.contents == 0) {\
        _ssym##__n.contents = _cont##__n;\
        _ssym##__n.start = 0;\
        _ssym##__n.end = sizeof(_cont##__n) -1;\
    } &_ssym##__n;})
    
static int open(char *name, int flags, int mode)
{
    buffer filesym = staticbuffer(files);
    buffer contents = staticbuffer(contents);

    // oh right, we're supposed to keep track of cwd...alot of
    // of this could have been handled completely in userspace
    console("open ");
    console(name);
    console("\n");
    // breakout name resolution
    little_stack_buffer(element, 1024);

    // make a namei
    u64 where = 0;
    bytes length;

    buffer fs = current->p->filesystem;
    // vector split....xxx - chuck the mandatory leading slash..        
    for (char *i = name + 1; *i; i++) {
        if (*i == '/') {
            if (!storage_lookup(fs, where, filesym, &where, &length)) 
                return -ENOENT;
            rprintf ("where %x\n", where);
            if (!storage_lookup(fs, where, element, &where, &length)) 
                return -ENOENT;
            element->start = element->end = 0;
        } else push_character(element, *i);
    }
    if (!storage_lookup(fs, where, filesym, &where, &length)) 
        return -ENOENT;
    if (!storage_lookup(fs, where, element, &where, &length)) 
        return -ENOENT;
    if (!storage_lookup(fs, where, contents, &where, &length)) 
        return -ENOENT;    

    buffer  b = allocate(general, sizeof(struct buffer));
    b->contents = fs->contents + where;
    b->end = length;
    b->start = 0; 
    current->p->files[current->p->filecount].state = b;
    current->p->files[current->p->filecount].read = readbufferv;
    //      file[filecount].write = ERDONLY;
    return  current->p->filecount++;
}

static u64 mmap(void *target, u64 *size, int prot, int flags, int fd, u64 offset)
{
    buffer b = (buffer)current->p->files[fd].state;
    rprintf ("mmap %d %d %p\n", fd, *size, b->contents); 
    return u64_from_pointer(b->contents);
}

static int fstat(int fd, stat s)
{
    buffer b = (buffer)current->p->files[fd].state;
    rprintf  ("fstat %d %d %x\n", fd, buffer_length(b), (void *)&s->st_size - (void *)s);
    // return is broken?
    s->st_size = buffer_length(b);
    return 0;
}

static void *brk(void *x)
{
    u64 alloc = u64_from_pointer(x) - u64_from_pointer(current->p->brk);
    rprintf ("brk: %x %x\n", current->p->brk,alloc);
    current->p->brk += alloc; 
    return current->p->brk;
}

// because the conventions mostly line up, and because the lower level
// handler doesn't touch these, using the arglist here should be
// a bit faster than digging them out of frame
u64 syscall()
{
    u64 *f = current->frame;
    int call = f[FRAME_VECTOR];
    u64 a[6] = {f[FRAME_RDI], f[FRAME_RSI], f[FRAME_RDX], f[FRAME_R10], f[FRAME_R8], f[FRAME_R9]};

    // vector dispatch with things like fd decoding and general error processing
    switch (call) {
    case SYS_write: return write(a[0], pointer_from_u64(a[1]), a[2]);
    case SYS_open: return open(pointer_from_u64(a[0]), a[1], a[2]);
    case SYS_fstat: return fstat(a[0], pointer_from_u64(a[1]));
    case SYS_writev: return writev(a[0], pointer_from_u64(a[1]), a[2]);
    case SYS_brk: return u64_from_pointer(brk(pointer_from_u64(a[0])));
    case SYS_mmap: return mmap(pointer_from_u64(a[0]),
                               pointer_from_u64(a[1]),
                               a[2],
                               a[3],
                               a[4],
                               a[5]);
    case SYS_getpid: return current->p->pid;

    default:
        rprintf("syscall %d %x %x %x\n", call, a[0], a[1], a[2]);
        return (0);
    }
}

extern void *frame;
void run(thread t)
{
    // should be the same, fix the interrupt and syscall handlers...or leave them
    // independent of whether we are runing unix
    current = t;
    frame = &t->frame;
    // actually go to thread
}

thread create_thread(process p)
{
    thread t = allocate(p->h, sizeof(struct thread));
    t->p = p;
    // stack goes here
    return t;
}

process create_process(heap h)
{
    process p = allocate(h, sizeof(struct process));
    p->h = h;
    p->brk = pointer_from_u64(0x50000000);
    p->filecount = 3;
    p->pid = process_count++;
    // allocate main thread, setup context, run main thread
    return p;
}
