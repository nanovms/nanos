
static inline int computeSignal (context c)
{
    return 0;
}

static inline void clear_thread_stepping(thread t)
{
}

static inline void set_thread_stepping(thread t)
{
}

static inline int get_register(u64 num, void *buf, context c)
{
    return -1;
}

static boolean set_thread_register(thread t, int regno, u64 val)
{
    return false;
}

static inline void set_thread_pc(thread t, u64 addr)
{
}

static inline void read_registers(buffer b, thread t)
{
}

static inline void write_registers(buffer b, thread t)
{
}

static inline void set_write_protect(boolean enable)
{
}

boolean breakpoint_insert(heap h, u64 a, u8 type, u8 log_length, thunk completion)
{
    return false;
}

boolean breakpoint_remove(heap h, u32 a, thunk completion)
{
    return false;
}
