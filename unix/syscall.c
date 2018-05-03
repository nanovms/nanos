#include <sruntime.h>
#include <unix.h>


int read(int fd, u8 *dest, bytes length)
{
    file f = current->p->files + fd;
    return apply(f->read, dest, length, f->offset);
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

int pselect(int nfds,
            u64 *readfds, u64 *writefds, u64 *exceptfds,
            struct timespec *timeout,
            u64 *sigmask)
{
    if (timeout == 0) {
        rprintf("select poll\n");
    } else {
        rprintf("select %d %d\n", timeout->tv_sec, timeout->tv_nsec);
        //register_timer()
        runloop(); // sleep
    }
    return 0;
}

u64 syscall_ignore()
{
    return 0;
}

u64 getpid()
{
    return current->p->pid;
}

void exit(int code)
{
    QEMU_HALT();
    while(1); //compiler put a noreturn on exit
}

void register_file_syscalls(void **map)
{
    register_syscall(map, SYS_read, read);
    register_syscall(map, SYS_write, write);
    register_syscall(map, SYS_open, open);
    register_syscall(map, SYS_fstat, fstat);
    register_syscall(map, SYS_stat, stat);
    register_syscall(map, SYS_writev, writev);
    register_syscall(map, SYS_access, access);
    register_syscall(map, SYS_lseek, lseek);
    register_syscall(map, SYS_fcntl, fcntl);
    register_syscall(map, SYS_getcwd, getcwd);
    register_syscall(map, SYS_readlink, readlink);
    register_syscall(map, SYS_close, syscall_ignore);

    register_syscall(map, SYS_brk, brk);
    register_syscall(map, SYS_uname, uname);
    register_syscall(map, SYS_getrlimit, getrlimit);
    register_syscall(map, SYS_getpid, getpid);    
    register_syscall(map, SYS_exit, exit);
    register_syscall(map, SYS_pselect6,pselect);
}
