#include <runtime.h>
#include <syscalls.h>
#include <system_structs.h>

extern u64 *frame;
// xxx - fill in the time fields once we have time

typedef struct file {
    int (*write)(struct file *f, void *body, bytes length);
} *file;

// could really take the args directly off the function..maybe dispatch in
// asm
// packed?

static int write(int fd, u8 *body, bytes length)
{
    for (int i = 0; i< length; i++) serial_out(body[i]);
}

static int writev(int fd, iovec v, int count)
{
    for (int i = 0; i < count; i++)
        write(fd, v[i].address, v[i].length);
}


static int open(char *name, int flags, int mode)
{
    console("open ");
    console(name);
    console("\n");
    return -ENOENT;
}

static int fstat(int fd, stat s)
{
    // return is broken?
    console("fstat ");
    print_u64(fd);
    console("  ");
    print_u64(s);
    console("\n");
    s->st_size = 0;
    return 0;
}

static int brk(void *x)
{
    console ("brk: ");
    print_u64(u64_from_pointer(x));
    console ("\n");
    return 0;
}

// because the conventions mostly line up, and because the lower level
// handler doesn't touch these, using the arglist here should be
// a bit faster than digging them out of frame
u64 syscall()
{
    int call = frame[FRAME_VECTOR];
    // vector dispatch with things like fd decoding and general error processing
    switch (call) {
    case SYS_write: return write(frame[FRAME_RDI], pointer_from_u64(frame[FRAME_RSI]), frame[FRAME_RDX]);
    case SYS_open: return open(pointer_from_u64(frame[FRAME_RDI]), frame[FRAME_RSI], frame[FRAME_RDX]);
    case SYS_fstat: return fstat(frame[FRAME_RDI], pointer_from_u64(frame[FRAME_RSI]));
    case SYS_writev: return writev(frame[FRAME_RDI], pointer_from_u64(frame[FRAME_RSI]), frame[FRAME_RDX]);
    case SYS_brk: return brk(pointer_from_u64(frame[FRAME_RDI]));

    default:
        console("syscall ");
        print_u64(frame[FRAME_VECTOR]);
        console(" ");
        print_u64(frame[FRAME_RDI]);
        console(" ");
        print_u64(frame[FRAME_RSI]);        
        console(" ");
        print_u64(frame[FRAME_RDX]);        
        console("\n");
        return (0);
    }
}
