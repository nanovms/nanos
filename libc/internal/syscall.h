// xxx - fix, there are two copies of this file because musl is looking
// in two different places

extern void console();
extern void print_u64();

static __inline long __syscall0(long n)
{
    console("syscall ");
    print_u64(n);
    console("\n");
    return 0;
}

static __inline long __syscall1(long n, long a1)
{
    __syscall0(n);
	return 0;
}

static __inline long __syscall2(long n, long a1, long a2)
{
        __syscall0(n);
	return 0;
}

static __inline long __syscall3(long n, long a1, long a2, long a3)
{
        __syscall0(n);
	return 0;
}

static __inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{
        __syscall0(n);
	return 0;
}

static __inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
        __syscall0(n);
	return 0;
}

static __inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    __syscall0(n);
	return 0;
}
