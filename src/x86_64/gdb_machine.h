const int signalmap[]={8, 5, 0, 5, 8, 10, 4, 8, 7, 10, 11, 11, 11, 11, 0, 0, 8, 10, 10, 8, 10};
static inline int computeSignal (context frame)
{
    u64 exceptionVector = frame[FRAME_VECTOR];
    if (exceptionVector > (sizeof(signalmap)/sizeof(int)))
        return(7);
    return(signalmap[exceptionVector]);
}

static inline void clear_thread_stepping(thread t)
{
    thread_frame(t)[FRAME_FLAGS] &= ~U64_FROM_BIT(EFLAG_TRAP);
    thread_frame(t)[FRAME_FLAGS] |= U64_FROM_BIT(EFLAG_RESUME);
}

static inline void set_thread_stepping(thread t)
{
    thread_frame(t)[FRAME_FLAGS] &= ~U64_FROM_BIT(EFLAG_RESUME);
    thread_frame(t)[FRAME_FLAGS] |= U64_FROM_BIT(EFLAG_TRAP);
}

/* XXX This is a hack. The numbering of the registers is based on
 * xml files describing the registers. For reference, see
 * https://github.com/bminor/binutils-gdb/tree/master/gdb/features/i386
 * The register numbers can change based on which register groups
 * gdb is using. I think the qSupported xmlRegisters option can allow
 * the stub to define which registers are which number, which is the
 * real solution. */
static inline int get_register(u64 num, void *buf, context c)
{
    /* gp registers plus rip */
    if (num >= 0 && num < 17) {
        *(u64 *)buf = c[num];
        return sizeof(u64);
    } else if (num >= 17 && num < 24) {
        *(u32 *)buf = (u32)c[num];
        return sizeof(u32);
    } else if (num == 57 || num == 58) {
        *(u64 *)buf = c[num-35];
        return sizeof(u64);
    } else
        return -1;
}

static boolean set_thread_register(thread t, int regno, u64 val)
{
    if (regno < 22) {
        thread_frame(t)[regno] = val;
        return true;
    }
    return false;
}

static inline void set_thread_pc(thread t, u64 addr)
{
    set_thread_register(t, FRAME_RIP, addr);
}

static inline void read_registers(buffer b, thread t)
{
    mem2hex (b, thread_frame(t), sizeof(u64)*17);
}

static inline void write_registers(buffer b, thread t)
{
    hex2mem (b, thread_frame(t), sizeof(u64)*17);
}

static inline void set_write_protect(boolean enable)
{
    set_page_write_protect(enable);
}
