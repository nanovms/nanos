#include <sruntime.h>
#include <unix.h>
// parameter
#include <gdb.h>
#include <net.h>


int sigaction(int signum,
              const struct sigaction *act,
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
    if (!resolve_cstring(current->p->cwd, name)) {
        return -ENOENT;
    }
    return 0;
}

static CLOSURE_1_3(contents_read, int, tuple, void *, u64, u64);
static int contents_read(tuple n, void *dest, u64 length, u64 offset)
{
    // offset?
    buffer b;
    if (!(b = contents(n))) return -EINVAL;
    u64 len = MIN(buffer_length(b), length);
    runtime_memcpy(dest, buffer_ref(b, offset), len);
    return len;
}

long clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, void *x)
{
    thread t = create_thread(current->p);
    runtime_memcpy(t->frame, current->frame, sizeof(t->frame));
    t->frame[FRAME_RSP]= u64_from_pointer(child_stack);
    t->frame[FRAME_RAX]= *(u32 *)ctid;
    t->frame[FRAME_FS] = u64_from_pointer(x);
    enqueue(runqueue, t->run);
    return t->tid;
}

int allocate_fd(process p, io reader, io writer)
{
    // check err
    int fd = allocate_u64(p->fdallocator, 1);
    p->files[fd].offset = 0;
    p->files[fd].read = reader;
    p->files[fd].write = writer;
    return fd;
}

int open(char *name, int flags, int mode)
{
    tuple n;
    bytes length;
    
    // fix - lookup should be robust
    if (name == 0) return -EINVAL;
    if (!(n = resolve_cstring(current->p->cwd, name))) {
        rprintf("open %s - not found\n", name);
        return -ENOENT;
    }

    buffer b = allocate(current->p->h, sizeof(struct buffer));
    // might be functional, or be a directory
    int fd = allocate_u64(current->p->fdallocator, 1);
    file f = current->p->files+fd;
    f->n = n;
    f->read = closure(current->p->h, contents_read, n);
    f->offset = 0;
    return fd;
}

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
        if (u64_from_pointer(r) == INVALID_PHYSICAL) {
            // MAP_FAILED
            return r;
        }
        map(base, physical_from_virtual(r), diff, current->p->pages);
        zero(pointer_from_u64(base), diff); 
    }
    //    map(u64_from_pointer(new_address)&align, physical_from_virtual(old_address), old_size, current->p->pages);
    return old_address;
}


static int mincore(void *addr, u64 length, u8 *vec)
{
    if (validate_virtual(addr, length)) {
        u32 vlen = pad(length, PAGESIZE) >> PAGELOG;
        // presumably it wants the right valid bits set? - go doesn't seem to use it this way
        for (int i = 0; i< vlen; i++) vec[i] = 1;
        return 0;
    }
    return -ENOMEM;
}


static void *mmap(void *target, u64 size, int prot, int flags, int fd, u64 offset)
{
    rprintf("mmap %p %p %x %d %p\n", target, size, flags, fd, offset);
    process p = current->p;
    // its really unclear whether this should be extended or truncated
    u64 len = pad(size, PAGESIZE);
    //gack
    len = len & MASK(32);
    u64 where = u64_from_pointer(target);

    // xx - go wants to specify target without map fixed, and has some strange
    // retry logic around it
    if (!(flags &MAP_FIXED) && !target) {
        if (flags & MAP_32BIT)
            where = allocate_u64(current->p->virtual32, len);
        else
            where = allocate_u64(current->p->virtual, len);
    }
    
    // make a generic zero page function
    if (flags & MAP_ANONYMOUS) {
        u64  m = allocate_u64(p->physical, len);
        if (m == INVALID_PHYSICAL) return pointer_from_u64(m);
        map(where, m, len, p->pages);
        zero(pointer_from_u64(where), len);
        return pointer_from_u64(where);
    }
    
    
    // check that fd is valid
    file f = p->files + fd;
    buffer b;
    if (!(b = table_find(f->n, sym(contents)))) return pointer_from_u64(-1ull);
        
    u64 msize = 0;
    u64 blen = buffer_length(b);
    if (blen > offset) msize = pad(blen-offset, PAGESIZE);
    if (msize > len) msize = len;
    
    // mutal misalignment?...discontiguous backing?
    map(where, physical_from_virtual(buffer_ref(b, offset)), msize, p->pages);

    if (len > msize) {
        u64 bss = pad(len, PAGESIZE) - msize;
        map(where + msize, allocate_u64(p->physical, bss), bss, p->pages);
        zero(pointer_from_u64(where+msize), bss);
    }
    // ok, if we change pages entries we need to flush the tlb...dont need
    // to do this every time.. there is also a per-page variant
    u64 x;
    mov_from_cr("cr3", x);
    mov_to_cr("cr3", x);    
    return pointer_from_u64(where);
}

static void fill_stat(node n, struct stat *s)
{
    buffer b;
    zero(s, sizeof(struct stat));
    s->st_dev = 0;
    s->st_ino = u64_from_pointer(n);
    // dir doesn't have contents
    if (!(b = table_find(n, sym(contents)))) {
        s->st_mode = S_IFDIR | 0777;
        return;
    }  else {
        s->st_mode = S_IFREG | 0644;
        s->st_size = buffer_length(b);
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

typedef struct fut {
    queue waiters;
} *fut;
    
static fut soft_create_futex(process p, u64 key)
{
    fut f;
    // of course this is supossed to be serialized
    if (!(f = table_find(p->futices, pointer_from_u64(key)))) {
        f = allocate(p->h, sizeof(struct fut));
        f->waiters = allocate_queue(p->h, 32);
        table_set(p->futices, pointer_from_u64(key), f);
    }
    return f;
}

static int futex(int *uaddr, int futex_op, int val,
                 u64 val2,
                 int *uaddr2, int val3)
{
    struct timespec *timeout = pointer_from_u64(val2);
    int verbose = false;
    thunk w;
    
    fut f = soft_create_futex(current->p, u64_from_pointer(uaddr));
    int op = futex_op & 127; // chuck the private bit
    switch(op) {
    case FUTEX_WAIT:
        if (verbose)
            rprintf("futex_wait [%d %p %d] %p\n", current->tid, uaddr, *uaddr, val);
        if (*uaddr == val) {
            // if we resume we are woken up, no timeout support
            current->frame[FRAME_RAX] = 0;
            enqueue(f->waiters, current->run);
            runloop();
        }
        return -EAGAIN;
            
    case FUTEX_WAKE:
        // return the number of waiters that were woken up
        if (verbose)
            rprintf("futex_wake [%d %p %d]\n", current->tid, uaddr, *uaddr);
        if ((w = dequeue(f->waiters))) {
            current->frame[FRAME_RAX] = 1;
            enqueue(runqueue, w);
        }
        return 0;
        
    case FUTEX_FD: rprintf("futex_fd\n"); break;
    case FUTEX_REQUEUE: rprintf("futex_requeue\n"); break;
    case FUTEX_CMP_REQUEUE:
        if (verbose)
            rprintf("futex_cmp_requeue [%d %p %d] %d\n", current->tid, uaddr, *uaddr, val3);
        if (*uaddr == val3) {
            if ((w = dequeue(f->waiters))) {            
                current->frame[FRAME_RAX] = 1;
                enqueue(runqueue, w);
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
            while ((w = dequeue(f->waiters))) {
                result++;
                enqueue(runqueue, w);
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
                if ((w = dequeue(f->waiters))) {                
                    result++;
                    enqueue(runqueue, w);                    
                }
            }
            return result;
        }

    case FUTEX_WAIT_BITSET:
        if (verbose)
            rprintf("futex_wait_bitset [%d %p %d] %p %p\n", current->tid, uaddr, *uaddr, val3);
        if (*uaddr == val) {
            current->frame[FRAME_RAX] = 0;
            enqueue(f->waiters, current->run);
            // xxx - go back to sched
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
    node n;

    if (!(n = resolve_cstring(current->p->cwd, name))) {    
        return -ENOENT;
    }
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
        rprintf("set fs: %p\n", a);
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
        rlim->rlim_cur = FDS;
        rlim->rlim_max = FDS;
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

int sigprocmask(int how, u64 *new, u64 *old)
{
    *old = 0;
    return 0;
}

int pselect(int nfds,
            u64 *readfds, u64 *writefds, u64 *exceptfds,
            const struct timespec *timeout,
            u64 *sigmask)
{
    return 0;
}

int gettid()
{
    return current->tid;
}

// because the conventions mostly line up, and because the lower level
// handler doesn't touch these, using the abi arguments registers here should be
// a bit faster than digging them out of frame
// should break out the signal section like the socket section, or make
// a more general registration

u64 syscall()
{
    u64 *f = current->frame;
    int call = f[FRAME_VECTOR];
    if (call != SYS_write)
        rprintf("syscall %d\n", call);
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
    case SYS_mincore: return mincore(pointer_from_u64(a[0]), a[1], pointer_from_u64(a[2]));
    case SYS_access: return access(pointer_from_u64(a[0]), a[1]);
    case SYS_getrlimit: return getrlimit(a[0], pointer_from_u64(a[1]));
    case SYS_getpid: return current->p->pid;
    case SYS_arch_prctl: return arch_prctl(a[0], a[1]);
    case SYS_rt_sigprocmask: return sigprocmask(a[0], pointer_from_u64(a[1]), pointer_from_u64(a[2]));
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
    case SYS_gettid: return gettid();
    case SYS_exit: QEMU_HALT();
    case SYS_pselect6: return pselect(a[0], pointer_from_u64(a[1]), pointer_from_u64(a[2]), pointer_from_u64(a[3]),
                                     pointer_from_u64(a[4]), pointer_from_u64(a[5]));
                                     

    default:
#ifdef NET
        // use dynamic registration
        return net_syscall(call, a);
#endif        
        //        rprintf("syscall %d %p %p %p\n", call, a[0], a[1], a[2]);
        return (-ENOENT);
    }
}


