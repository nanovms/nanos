
typedef void *status;
#define STATUS_OK ((void *)0)
static inline status status_nomem() {return (void *)1;}

static inline boolean is_ok(status s)
{
    return s == ((void *)0);
}

static inline status allocate_status(char *format, ...)
{
}
