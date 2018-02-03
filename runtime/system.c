#include <sruntime.h>
#include <system.h>

// allocator
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
    rprintf("open %s\n", name);
    if (!storage_resolve(current->p->filesystem, name, &where, &length)) 
        return -ENOENT;

    // policy on opening directories?
    if (!storage_lookup(current->p->filesystem, where, &contents, &w2, &length))
        return -ENOENT;
    

    // vector split....xxx - chuck the mandatory leading slash..        

    buffer  b = allocate(current->p->h, sizeof(struct buffer));
    b->contents = current->p->filesystem->contents + w2;
    rprintf("open %s %p %x %d\n", name, physical_from_virtual(b->contents), length, current->p->filecount);
    
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

void *mremap(void *old_address, u64 old_size,  u64 new_size, int flags,  void *new_address )
{
    // this seems poorly thought out - what if there is a backing file?
    // and if its anonymous why do we care where it is..i guess this
    // is just for large realloc operations? if these aren't aligned
    // its completely unclear what to do
    rprintf ("mremap %p %x %x %x %p\n", old_address, old_size, new_size, flags, new_address);
    u64 align =  ~MASK(PAGELOG);
    if (new_size > old_size) {
        u64 diff = pad(new_size - old_size, PAGESIZE);
        u64 base = u64_from_pointer(old_address + old_size) & align;
        void *r = allocate(current->p->contig, diff);
        if (u64_from_pointer(r) == PHYSICAL_INVALID) {
            // MAP_FAILED
            return r;
        }
        rprintf ("new alloc %p %x\n", r, diff);
        map(base, physical_from_virtual(r), diff, current->p->pages);
        zero(pointer_from_u64(base), diff); 
    }
    //    map(u64_from_pointer(new_address)&align, physical_from_virtual(old_address), old_size, current->p->pages);
    return old_address;
}


static void *mmap(void *target, u64 size, int prot, int flags, int fd, u64 offset)
{
    rprintf("mmap %p %x %x %d %p\n", target, size, flags, fd, offset);
    process p = current->p;
    u64 len = pad(size, PAGESIZE);
    u64 where = u64_from_pointer(target);
    
    if (!(flags &MAP_FIXED)) {
        // use an allocator
        where = u64_from_pointer(current->p->valloc);
        current->p->valloc += len;
    }
        
    // merge these two cases to the extent possible
    // make a generic zero page function
    if (flags & MAP_ANONYMOUS) {
        void *r = allocate(p->contig, len);
        map(where, physical_from_virtual(r), len, p->pages);
        rprintf("zero %p %x\n", where, len);
        zero(pointer_from_u64(where), len); // seems like people assume?
        return pointer_from_u64(where);
    }
    

    file f = p->files + fd;
    buffer b = (buffer)f->state;

    u64 psize = buffer_length(b);
    if (size < psize) psize = size;
    psize = pad(psize, PAGESIZE);
        
    map(u64_from_pointer(where), physical_from_virtual(b->contents + offset), psize, p->pages);

    if (size > psize) {
        u64 bss = pad(size, PAGESIZE) - psize;
        void *empty = allocate(p->contig, bss);
        map(u64_from_pointer(p->valloc), physical_from_virtual(empty), bss, p->pages);
        rprintf("zero %p %x\n", where, len);        
        zero(p->valloc, bss);        
        p->valloc += bss;
    }

    return pointer_from_u64(where);
}

static void fill_stat(u64 where, u64 len, struct stat *s)
{
    s->st_dev = 0;
    s->st_ino = u64_from_pointer(where);
    s->st_size = len;
    if (len == 0) {
        // fix dir demux
        s->st_mode = S_IFDIR | 0777;
    }
}

static int fstat(int fd, struct stat *s)
{
    if (fd == 1) {
        s->st_mode = S_IFIFO;
        return 0;
    }
    
    buffer b = (buffer)current->p->files[fd].state;
    fill_stat(u64_from_pointer(b->contents) - u64_from_pointer(current->p->filesystem->contents),
              buffer_length(b), s);
    return 0;
}

static int futex(int *uaddr, int futex_op, int val,
                 const struct timespec *timeout,   
                 int *uaddr2, int val3)
{
    rprintf("futex op %d %x %d %p %p\n", futex_op, uaddr, val, current->frame[FRAME_RDX], timeout);
#if 0
    u64 *stack = pointer_from_u64(current->frame[FRAME_RSP]);        
    for (int j = 0; j< 20; j++) {
        print_u64(stack[j]);
        console("\n");        
    }
    asm("hlt");
#endif        
    int op = futex_op & 127; // chuck the private bit
    switch(op) {
    case FUTEX_WAIT: rprintf("futex_wait\n"); {
            //       *uaddr = val;
            return 0;
        }
    case FUTEX_WAKE: rprintf("futex_wake\n"); break;
    case FUTEX_FD: rprintf("futex_fd\n"); break;
    case FUTEX_REQUEUE: rprintf("futex_requeue\n"); break;
    case FUTEX_CMP_REQUEUE: rprintf("FUTEX_cmp_requeue\n"); break;
    case FUTEX_WAKE_OP: rprintf("FUTEX_wake_op\n"); break;
    case FUTEX_WAIT_BITSET: rprintf("FUTEX_wait_bitset\n"); break;
    case FUTEX_WAKE_BITSET: rprintf("FUTEX_wake_bitset\n"); break;
    case FUTEX_LOCK_PI: rprintf("FUTEX_lock_pi\n"); break;
    case FUTEX_TRYLOCK_PI: rprintf("FUTEX_trylock_pi\n"); break;
    case FUTEX_UNLOCK_PI: rprintf("FUTEX_unlock_pi\n"); break;
    case FUTEX_CMP_REQUEUE_PI: rprintf("FUTEX_CMP_requeue_pi\n"); break;
    case FUTEX_WAIT_REQUEUE_PI: rprintf("FUTEX_WAIT_requeue_pi\n"); break;
    }
}


static int stat(char *name, struct stat *s)
{
    u64 where = 0;
    bytes length;

    if (!lookup(current->p->filesystem, name, &where, &length)) {
        return -ENOENT;
    }
    fill_stat(where, length, s);
    return 0;
}

extern void write_msr(u64 a, u64 b);
static int arch_prctl(int code, unsigned long a)
{
    rprintf("arch prctl op %x\n", code);
    switch (code) {
    case ARCH_SET_GS:
        break;
    case ARCH_SET_FS:
        write_msr(FS_MSR, a);
        break;
    case ARCH_GET_FS:
        break;
    case ARCH_GET_GS:
        break;
    default:
        return -1;
    }
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
    case SYS_arch_prctl: return arch_prctl(a[0], a[1]);
    case SYS_mremap: return u64_from_pointer(mremap(pointer_from_u64(a[0]), a[1], a[2], a[3], pointer_from_u64(a[4])));        
    case SYS_futex: return futex(pointer_from_u64(a[0]), a[1], a[2], pointer_from_u64(a[3]),
                                 pointer_from_u64(a[4]),a[5]);

    default:
        rprintf("syscall %d %x %x %x\n", call, a[0], a[1], a[2]);
        return (0);
    }
}

extern u64 *frame;
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
