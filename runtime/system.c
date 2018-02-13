#include <sruntime.h>
#include <system.h>

static heap processes;

typedef struct file {
    u64 offset; 
    io read, write;
    node n;
} *file;

typedef vector runqueue;
static runqueue runnable;

#define NUMBER_OF_FDS 32
typedef struct process {
    heap h, pages, physical;
    int pid;
    node filesystem;
    // could resize
    struct file files[NUMBER_OF_FDS];
    void *brk;
    heap virtual;
    heap virtual32;    
    heap fdallocator;
    node cwd;
    table futices;
} *process;

thread current;

static node lookup(process p, char *name)
{
    struct buffer b;
    b.start = 0;
    b.end = runtime_strlen(name);
    b.contents = name;
    // transient
    vector vn = split(p->h, &b, '/');
    vector_pop(vn);
    // relative path resolution with cwd
    if (vector_length(vn) == 0) {
        return node_invalid;
    }
    return storage_resolve(p->filesystem, vn);
}

int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact)
{
    if (oldact) oldact->_u._sa_handler = SIG_DFL;
    return 0;
}

int read(int fd, u8 *dest, bytes length)
{
    file f = current->p->files + fd;
    return apply(f->read, dest, length, f->offset);
}

// callibration is an issue
int gettimeofday(struct timeval *tv, void *tz)
{
    static u64 seconds;
    static u64 microseconds;
    tv->tv_sec = seconds;
    tv->tv_usec = microseconds++;
    return 0;
}

int write(int fd, u8 *body, bytes length)
{
    file f = current->p->files +fd;
    int res = apply(f->write, body, length, f->offset);
    f->offset += length;
    return res;
}

static int writev(int fd, iovec v, int count)
{
    int res;
    file f = current->p->files +fd;    
    for (int i = 0; i < count; i++) res += write(fd, v[i].address, v[i].length);
    return res;
}

static int access(char *name, int mode)
{
    void *where;
    bytes length;
    if (is_empty(lookup(current->p, name)))
        return -ENOENT;
    return 0;
}

static CLOSURE_1_3(contents_read, int, node, void *, u64, u64);
static int contents_read(node n, void *dest, u64 length, u64 offset)
{
    void *base;
    u64 flength;
    if (!node_contents(n, &base, &flength)) return -EINVAL;
    if (length < flength) {
        flength = length;
    }
    runtime_memcpy(dest, base + offset, flength);
    return flength;
}

long clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, void *x)
{
    thread t = create_thread(current->p);
    //    rprintf("clone! %d->%d\n", current->tid, t->tid);
    runtime_memcpy(t->frame, current->frame, sizeof(t->frame));
    t->frame[FRAME_RSP]= u64_from_pointer(child_stack);
    t->frame[FRAME_RAX]= *(u32 *)ctid;
    t->frame[FRAME_FS] = u64_from_pointer(x);
    vector_push(runnable, t);
    return t->tid;
}

int open(char *name, int flags, int mode)
{
    struct node n;
    bytes length;
    
    // fix - lookup should be robust
    if (name == 0) return -EINVAL;
    
    if (is_empty(n = lookup(current->p, name))) {
        //rprintf("open %s - not found\n", name);
        return -ENOENT;
    }

    buffer b = allocate(current->p->h, sizeof(struct buffer));
    // might be functional, or be a directory
    int fd = allocate_u64(current->p->fdallocator, 1);
    file f = current->p->files+fd;
    f->n = n;
    f->read = closure(current->p->h, contents_read, n);
    f->offset = 0;
    //    rprintf("open %s return %x\n", name, fd);
    return fd;
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
    u64 align =  ~MASK(PAGELOG);
    if (new_size > old_size) {
        u64 diff = pad(new_size - old_size, PAGESIZE);
        u64 base = u64_from_pointer(old_address + old_size) & align;
        void *r = allocate(current->p->physical,diff);
        if (u64_from_pointer(r) == PHYSICAL_INVALID) {
            // MAP_FAILED
            return r;
        }
        map(base, physical_from_virtual(r), diff, current->p->pages);
        zero(pointer_from_u64(base), diff); 
    }
    //    map(u64_from_pointer(new_address)&align, physical_from_virtual(old_address), old_size, current->p->pages);
    return old_address;
}


static void *mmap(void *target, u64 size, int prot, int flags, int fd, u64 offset)
{
    //    rprintf("mmap %p %p %x %d %p\n", target, size, flags, fd, offset);
    process p = current->p;
    // its really unclear whether this should be extended or truncated
    u64 len = pad(size, PAGESIZE);
    //gack
    len = len & MASK(32);
    u64 where = u64_from_pointer(target);

    if (!(flags &MAP_FIXED)){
        if (flags & MAP_32BIT)
            where = allocate_u64(current->p->virtual32, len);
        else
            where = allocate_u64(current->p->virtual, len);
    }
        
    // make a generic zero page function
    if (flags & MAP_ANONYMOUS) {
        u64  m = allocate_u64(p->physical, len);
        if (m == PHYSICAL_INVALID) return pointer_from_u64(m);
        map(where, m, len, p->pages);
        zero(pointer_from_u64(where), len);
        return pointer_from_u64(where);
    }
    

    // check that fd is valid
    file f = p->files + fd;
    void *fbase;
    u64 flen;
    if (!node_contents(f->n, &fbase, &flen)) return pointer_from_u64(PHYSICAL_INVALID);

    u64 msize = 0;
    if (flen > offset) msize = pad(flen-offset, PAGESIZE);
    if (msize > len) msize = len;
    
    // mutal misalignment?...discontiguous backing?
    map(where, physical_from_virtual(fbase + offset), msize, p->pages);

    if (len > msize) {
        u64 bss = pad(len, PAGESIZE) - msize;
        map(where + msize, allocate_u64(p->physical, bss), bss, p->pages);
        zero(pointer_from_u64(where+msize), bss);
    }
    // ok, if we change pages entries we need to flush the tlb...dont need
    // to do this every time
    u64 x;
    mov_from_cr("cr3", x);
    mov_to_cr("cr3", x);    
    return pointer_from_u64(where);
}

static boolean fill_stat(node n, struct stat *s)
{
    void *fbase;
    u64 flen;
    
    s->st_dev = 0;
    s->st_ino = u64_from_pointer(n.offset);
    // dir doesn't have contents
    if (!node_contents(n, &fbase, &flen)) return false;    
    s->st_size = flen;

    if (flen == 0) {
        // fix dir demux
        s->st_mode = S_IFDIR | 0777;
    }
}

static int fstat(int fd, struct stat *s)
{
    // take this from tuple space
    if (fd == 1) {
        s->st_mode = S_IFIFO;
        return 0;
    }
    fill_stat(current->p->files[fd].n, s);
    return 0;
}

static runqueue allocate_runqueue(heap h)
{
    return allocate_vector(h, 5);
}

static void run_enqueue(vector v, thread t)
{
    vector_push(v, t);
}

typedef struct fut {
    runqueue waiters;
} *fut;
    
static fut soft_create_futex(process p, u64 key)
{
    fut f;
    // of course this is supossed to be serialized
    if (!(f = table_find(p->futices, pointer_from_u64(key)))) {
        f = allocate(p->h, sizeof(struct fut));
        f->waiters = allocate_runqueue(p->h);
        table_set(p->futices, pointer_from_u64(key), f);
    }
    return f;
}

void run_queue(runqueue r)
{
    thread t =vector_pop(r);
    if (t) {
        run(t);
    } else {
        //        rprintf("empty queue buddy\n");
        QEMU_HALT();
    }
}

static int futex(int *uaddr, int futex_op, int val,
                 u64 val2,
                 int *uaddr2, int val3)
{
    struct timespec *timeout = pointer_from_u64(val2);
    int verbose = false;
    
    fut f = soft_create_futex(current->p, u64_from_pointer(uaddr));
    int op = futex_op & 127; // chuck the private bit
    switch(op) {
    case FUTEX_WAIT:
        if (verbose)
            rprintf("futex_wait [%d %p %d] %p\n", current->tid, uaddr, *uaddr, val);
        if (*uaddr == val) {
            // if we resume we are woken up, no timeout support
            current->frame[FRAME_RAX] = 0;
            run_enqueue(f->waiters, current);
            run_queue(runnable);
            // so now we need to schedule some other poor sucker
        }
        return -EAGAIN;
            
    case FUTEX_WAKE:
        // return the number of waiters that were woken up
        if (verbose)
            rprintf("futex_wake [%d %p %d] %d\n", current->tid, uaddr, *uaddr, vector_length(f->waiters));
        if (vector_length(f->waiters)) {
            current->frame[FRAME_RAX] = 1;
            vector_push(runnable, current);
            run_queue(f->waiters);
        }
        return 0;
        
    case FUTEX_FD: rprintf("futex_fd\n"); break;
    case FUTEX_REQUEUE: rprintf("futex_requeue\n"); break;
    case FUTEX_CMP_REQUEUE:
        if (verbose)
            rprintf("futex_cmp_requeue [%d %p %d] %d\n", current->tid, uaddr, *uaddr, val3);
        if (*uaddr == val3) {
            if (vector_length(f->waiters)) {
                current->frame[FRAME_RAX] = 1;
                vector_push(runnable, current);
                run_queue(f->waiters);
            }
            return 0;
        }
        return -EAGAIN;
    case FUTEX_WAKE_OP:
        {
            unsigned int cmparg = val3 & MASK(12);
            unsigned int oparg = (val3 >> 12) & MASK(12);
            unsigned int cmp = (val3 >> 24) & MASK(4);
            unsigned int op = (val3 >> 28) & MASK(4);

            if (verbose)
                rprintf("futex wake op: [%d %p %d] %p %d %d %d %d\n",  current->tid, uaddr, *uaddr, uaddr2, cmparg, oparg, cmp, op);
            int oldval = *(int *) uaddr2;
            
            switch (cmp) {
            case FUTEX_OP_SET:   *uaddr  = oparg; break;
            case FUTEX_OP_ADD:   *uaddr2 += oparg; break;
            case FUTEX_OP_OR:    *uaddr2 |= oparg; break;
            case FUTEX_OP_ANDN:  *uaddr2 &= ~oparg; break;
            case FUTEX_OP_XOR:   *uaddr2 ^= oparg; break;
            }

            int result = 0;
            while (vector_length(f->waiters)) {
                result++;
                run_enqueue(runnable, vector_pop(f->waiters));
            }
            
            int c;
            switch (cmp) {
            case FUTEX_OP_CMP_EQ: c = (oldval == cmparg) ; break;
            case FUTEX_OP_CMP_NE: c = (oldval != cmparg); break;
            case FUTEX_OP_CMP_LT: c = (oldval < cmparg); break;
            case FUTEX_OP_CMP_LE: c = (oldval <= cmparg); break;
            case FUTEX_OP_CMP_GT: c = (oldval > cmparg) ; break;
            case FUTEX_OP_CMP_GE: c = (oldval >= cmparg) ; break;
            }
            
            if (c) {
                fut f = soft_create_futex(current->p, u64_from_pointer(uaddr2));
                while (vector_length(f->waiters)) {
                    result++;
                    run_enqueue(runnable, vector_pop(f->waiters));
                }
            }
            return result;
        }

    case FUTEX_WAIT_BITSET:
        if (verbose)
            rprintf("futex_wait_bitset [%d %p %d] %p %p\n", current->tid, uaddr, *uaddr, val3);
        if (*uaddr == val) {
            current->frame[FRAME_RAX] = 0;
            run_enqueue(f->waiters, current);
            run_queue(runnable);
        }
        break;
    case FUTEX_WAKE_BITSET: rprintf("FUTEX_wake_bitset\n"); break;
    case FUTEX_LOCK_PI: rprintf("FUTEX_lock_pi\n"); break;
    case FUTEX_TRYLOCK_PI: rprintf("FUTEX_trylock_pi\n"); break;
    case FUTEX_UNLOCK_PI: rprintf("FUTEX_unlock_pi\n"); break;
    case FUTEX_CMP_REQUEUE_PI: rprintf("FUTEX_CMP_requeue_pi\n"); break;
    case FUTEX_WAIT_REQUEUE_PI: rprintf("FUTEX_WAIT_requeue_pi\n"); break;
    }
    return 0;
}


static int stat(char *name, struct stat *s)
{
    u64 where = 0;
    bytes length;
    node n;

    if (is_empty(n = lookup(current->p, name)))
        return -ENOENT;

    fill_stat(n, s);
    return 0;
}

static u64 lseek(int fd, u64 offset, int whence)
{
    return current->p->files[fd].offset;
}


extern void write_msr(u64 a, u64 b);
static int arch_prctl(int code, unsigned long a)
{
    switch (code) {
    case ARCH_SET_GS:
        break;
    case ARCH_SET_FS:
        current->frame[FRAME_FS] = a;
        return 0;
    case ARCH_GET_FS:
        break;
    case ARCH_GET_GS:
        break;
    default:
        return -EINVAL;
    }
}

static int uname(struct utsname *v)
{
    char rel[]= "4.4.0-87";
    char sys[] = "pugnix";
    runtime_memcpy(v->sysname,sys, sizeof(sys));
    runtime_memcpy(v->release, rel, sizeof(rel));
    return 0;
}

int getrlimit(int resource, struct rlimit *rlim)
{
    switch (resource) {
    case RLIMIT_STACK:
        rlim->rlim_cur = 2*1024*1024;
        rlim->rlim_max = 2*1024*1024;
        return 0;
    case RLIMIT_NOFILE:
        rlim->rlim_cur = NUMBER_OF_FDS;
        rlim->rlim_max = NUMBER_OF_FDS;
        return 0;
    }
    return -1;
}

static char *getcwd(char *buf, u64 length)
{
    runtime_memcpy(buf, "/", 2);
    return buf;
}

static void *brk(void *x)
{
    process p = current->p;
    if (p->brk) {
        if (p->brk > x) {
            p->brk = x;
            // free
        } else {
            u64 alloc = u64_from_pointer(x) - u64_from_pointer(p->brk);
            map(u64_from_pointer(p->brk), allocate_u64(p->physical, alloc), alloc, p->pages);
            zero(p->brk, alloc);
            p->brk += alloc;         
        }
    }
    return p->brk;
}

u64 readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return -EINVAL;

}

u64 fcntl(int fd, int cmd)
{
    return O_RDWR;
}

u64 set_tid_address(void *a)
{
    current->set_child_tid = a;
    return current->tid;
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
    case SYS_getrlimit: return getrlimit(a[0], pointer_from_u64(a[1]));
    case SYS_getpid: return current->p->pid;
    case SYS_arch_prctl: return arch_prctl(a[0], a[1]);
    case SYS_rt_sigaction: return sigaction(a[0], pointer_from_u64(a[1]), pointer_from_u64(a[2]));        
    case SYS_lseek: return lseek(a[0], a[1], a[2]);
    case SYS_fcntl: return fcntl(a[0], a[2]);
    case SYS_getcwd: return u64_from_pointer(getcwd(pointer_from_u64(a[0]), a[1]));
    case SYS_mremap: return u64_from_pointer(mremap(pointer_from_u64(a[0]), a[1], a[2], a[3], pointer_from_u64(a[4])));        
    case SYS_futex: return futex(pointer_from_u64(a[0]), a[1], a[2], a[3],
                                 pointer_from_u64(a[4]),a[5]);
    case SYS_readlink: return readlink(pointer_from_u64(a[0]), pointer_from_u64(a[2]), a[3]);
    case SYS_set_tid_address: return set_tid_address(pointer_from_u64(a[0]));
    case SYS_gettimeofday: return gettimeofday(pointer_from_u64(a[0]), pointer_from_u64(a[2]));
    case SYS_clone: return clone(a[0], pointer_from_u64(a[1]), pointer_from_u64(a[2]), pointer_from_u64(a[3]), pointer_from_u64(a[4]));
    case SYS_close: return 0;
    case SYS_munmap: return 0;
    case SYS_mprotect: return 0;
    case SYS_clock_gettime: return 0;
    case SYS_clock_getres: return 0;
    case SYS_exit: QEMU_HALT();

    default:
        //        rprintf("syscall %d %p %p %p\n", call, a[0], a[1], a[2]);
        return (0);
    }
}

extern u64 *frame;
void run(thread t)
{
    // rprintf("run %d\n", t->tid);
    current = t;
    frame = t->frame;
    ENTER(frame);
}

static int tidcount = 1;

thread create_thread(process p)
{
    thread t = allocate(p->h, sizeof(struct thread));
    t->p = p;
    t->tid = tidcount++;
    t->set_child_tid = t->clear_child_tid = 0;
    return t;
}

static CLOSURE_0_3(stdout, int, void*, u64, u64);
static int stdout(void *d, u64 length, u64 offset)
{
    character *z = d;
    for (int i = 0; i< length; i++) {
        serial_out(z[i]);
    }
}

static u64 futex_key_function(void *x)
{
    return u64_from_pointer(x);
}

static boolean futex_key_equal(void *a, void *b)
{
    return a == b;
}


process create_process(heap h, heap pages, heap physical, node filesystem)
{
    process p = allocate(h, sizeof(struct process));
    p->filesystem = filesystem;
    p->h = h;
    // stash end of bss? collisions?
    p->brk = pointer_from_u64(0x8000000);
    p->pid = allocate_u64(processes, 1);
    // allocate main thread, setup context, run main thread
    p->virtual = create_id_heap(h, 0x7000000000ull, 0x100000000);
    p->virtual32 = create_id_heap(h, 0x10000000, PAGESIZE);
    p->pages = pages;
    p->fdallocator = create_id_heap(h, 3, 1);
    p->physical = physical;
    p->files[1].write = closure(h, stdout);    
    p->files[2].write = closure(h, stdout);
    p->futices = allocate_table(h, futex_key_function, futex_key_equal);
    return p;
}

void init_system(heap h)
{
    set_syscall_handler(syscall_enter);
    // could wrap this in a 'system'
    processes = create_id_heap(h, 110, 1);
    runnable = allocate_runqueue(h);
}
