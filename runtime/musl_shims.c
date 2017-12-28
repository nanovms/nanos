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

extern serial_out(char x);

void __stdout_write(void *nothing, unsigned char *body, unsigned long length)
{
    for (int i = 0; i < length; i++)
        serial_out(body[i]);
}

void __towrite()
{
}

static int errno;

int *__errno_location()
{
    return &errno;
}

char *sterror(int k)
{
    return ("error");
}

void __signbitl();
{
}

void __fpclassifyl();
{
}

void frexpl();
{
}

