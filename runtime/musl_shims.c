// probably..make a non-trap _syscall dispatch just to reduce the
// raggedness of this cut

void __lockfile()
{
}

void __unlockfile()
{
}

void __overflow()
{
}

void __stdio_close()
{
}

void __stdio_seek()
{
}

extern void serial_out(char x);

void __stdout_write(void *nothing, unsigned char *body, unsigned long length)
{
    for (int i = 0; i < length; i++)
        serial_out(body[i]);
}

// wtf is this? - its shortcutting buffered output
int __towrite()
{
    return 0;
}

static int errno;

int *__errno_location()
{
    return &errno;
}

char *strerror(int k)
{
    return ("error");
}

void __signbitl()
{
}

void __fpclassifyl()
{
}

long double frexpl(long double x, int *exp)
{
}

void __set_thread_area()
{
}


void exit(int k)
{
    while(1);
}
