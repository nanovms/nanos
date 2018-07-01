
typedef tuple status;
typedef closure_type(status_handler, void, status);
// should probably be on transient 
static inline status allocate_status(char *x, ...)
{
    return allocate_tuple();
}
#define STATUS_OK ((tuple)0)
static inline boolean is_ok(status s)
{
    return (s == STATUS_OK);
}



