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
    heap h, pages, contig;
    int pid;
    buffer filesystem;
    // create stdout
    struct file files[32];
    int filecount;
    void *brk;
    void *valloc;
    // cwd here
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
    // um, truncate read past boundary
    buffer b = z;
    runtime_memcpy(b->contents + b->start + offset, dest, length);
    return length;
}

int read(int fd, u8 *dest, bytes length)
{
    file f = current->p->files + fd;
    buffer b = f->state;
    runtime_memcpy(dest, b->contents + b->start + f->offset, length);
    // truncate copy
    return length;
}

// mux
int write(int fd, u8 *body, bytes length)
{
    for (int i = 0; i< length; i++) serial_out(body[i]);
}

static int writev(int fd, iovec v, int count)
{
    int res;
    for (int i = 0; i < count; i++) {
        res += v[i].length;
        write(fd, v[i].address, v[i].length);
    }
    return res;
}

#define staticbuffer(__x, __n) \
    (__x)->contents = __n;                     \
    (__x)->start = 0;                          \
    (__x)->end = sizeof(__n) -1;               


static boolean lookup(buffer fs, char *file, u64 *storage, u64 *slength)
{
    // oh right, we're supposed to keep track of cwd
    u64 where = 0;
    bytes length;
    static struct buffer filesym;
    little_stack_buffer(element, 1024);
    
    staticbuffer(&filesym, "files");
    for (char *i =file + 1; *i; i++) {
        if (*i == '/') {
            if (!storage_lookup(fs, where, &filesym, &where, &length)) return false;
            if (!storage_lookup(fs, where, element, &where, &length)) return false;
            element->start = element->end = 0;
        } else push_character(element, *i);
    }
    if (!storage_lookup(fs, where, &filesym, &where, &length)) return false;
    if (!storage_lookup(fs, where, element, &where, &length)) return false;
    *storage =  where;
    *slength = length;
    return true;
}


static int access(char *name, int mode)
{
    u64 where = 0;
    bytes length;
    if (!lookup(current->p->filesystem, name, &where, &length)) 
        return -ENOENT;
    return 0;
}

static int open(char *name, int flags, int mode)
{
    u64 where = 0, w2;
    bytes length;
    static struct buffer contents;
    staticbuffer(&contents, "contents");
    
    if (!lookup(current->p->filesystem, name, &where, &length)) {
        return -ENOENT;
    }
    // policy on opening directories?
    if (!storage_lookup(current->p->filesystem, where, &contents, &w2, &length)) return -ENOENT;

    // vector split....xxx - chuck the mandatory leading slash..        

    buffer  b = allocate(current->p->h, sizeof(struct buffer));
    b->contents = current->p->filesystem->contents + w2;
    b->end = length;
    b->start = 0;
    file f = current->p->files +current->p->filecount;
    f->state = b;
    f->offset = 0;
    //      file[filecount].write = ERDONLY;
    // xxx - use allocator for filecount
    return  current->p->filecount++;
}

#ifndef MIN
#define MIN(x, y) ((x) < (y)? (x):(y))
#endif

static void *mmap(void *target, u64 size, int prot, int flags, int fd, u64 offset)
{
    process p = current->p;
        
    if (flags == (MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE)) {
        u64 len = pad(size, PAGESIZE);
        // alloc phys
        void *r = allocate(p->contig, len);
        map(u64_from_pointer(target), physical_from_virtual(r), len, p->pages);
        runtime_memset(target, 0, len); // seems like people assume?
        return target;
    }
    

    file f = p->files + fd;
    buffer b = (buffer)f->state;

    u64 psize = buffer_length(b);
    if (size < psize) psize = size;
    psize = pad(psize, PAGESIZE);
    
    void *vwhere = target;
    if (!vwhere) {
        // use an allocator
        vwhere = current->p->valloc;
        current->p->valloc += psize;
    }
        
    map(u64_from_pointer(vwhere), physical_from_virtual(b->contents + offset), psize, p->pages);

    if (size > psize) {
        u64 bss = pad(size, PAGESIZE) - psize;
        void *empty = allocate(p->contig, bss);
        map(u64_from_pointer(p->valloc), physical_from_virtual(empty), bss, p->pages);
        p->valloc += bss;
    }

    return vwhere;
}

static int fstat(int fd, struct stat *s)
{
    buffer b = (buffer)current->p->files[fd].state;
    s->st_size = buffer_length(b);
    return 0;
}

static int stat(char *name, struct stat *s)
{
    u64 where = 0;
    bytes length;

    if (!lookup(current->p->filesystem, name, &where, &length)) {
        return -ENOENT;
    }
    s->st_mode = S_IFDIR | 0777;
    s->st_size = length;
    return 0;
}

static int uname(struct utsname *v)
{
    char rel[]= "4.4.0-87";
    char sys[] = "pugnix";
    runtime_memcpy(v->sysname,sys, sizeof(sys));
    runtime_memcpy(v->release, rel, sizeof(rel));
    return 0;
}

static void *brk(void *x)
{
    u64 alloc = u64_from_pointer(x) - u64_from_pointer(current->p->brk);
    current->p->brk += alloc; 
    return current->p->brk;
}

// because the conventions mostly line up, and because the lower level
// handler doesn't touch these, using the arglist here should be
// a bit faster than digging them out of frame
// need to change to deal with errno conventions
u64 syscall()
{
    u64 *f = current->frame;
    int call = f[FRAME_VECTOR];
    u64 a[6] = {f[FRAME_RDI], f[FRAME_RSI], f[FRAME_RDX], f[FRAME_R10], f[FRAME_R8], f[FRAME_R9]};
    // vector dispatch with things like fd decoding and general error processing
    switch (call) {
    case SYS_read: return read(a[0],pointer_from_u64(a[1]), a[2]);
    case SYS_write: return write(a[0], pointer_from_u64(a[1]), a[2]);
    case SYS_open: return open(pointer_from_u64(a[0]), a[1], a[2]);
    case SYS_fstat: return fstat(a[0], pointer_from_u64(a[1]));
    case SYS_stat: return stat(pointer_from_u64(a[0]), pointer_from_u64(a[1]));        
    case SYS_writev: return writev(a[0], pointer_from_u64(a[1]), a[2]);
    case SYS_brk: return u64_from_pointer(brk(pointer_from_u64(a[0])));
    case SYS_uname: return uname(pointer_from_u64(a[0]));
    case SYS_mmap: return u64_from_pointer(mmap(pointer_from_u64(a[0]), a[1], a[2], a[3], a[4], a[5]));
    case SYS_access: return access(pointer_from_u64(a[0]), a[1]);
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

process create_process(heap h, heap pages, heap contig, buffer filesystem)
{
    process p = allocate(h, sizeof(struct process));
    p->filesystem = filesystem;
    p->h = h;
    p->brk = pointer_from_u64(0x8000000);
    p->filecount = 3;
    p->pid = process_count++;
    // allocate main thread, setup context, run main thread
    // this should be a heap
    p->valloc = (void *)0x7000000000;
    p->pages = pages;
    p->contig = contig;    
    return p;
}
