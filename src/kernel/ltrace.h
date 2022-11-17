#ifdef CONFIG_LTRACE

void ltrace_init(value cfg, buffer exe, u64 load_offset);
boolean ltrace_handle_trap(context_frame f);
void ltrace_signal(u32 signo);

#else

static inline void ltrace_init(value cfg, buffer exe, u64 load_offset) {}
static inline boolean ltrace_handle_trap(context_frame f) {return false;}
static inline void ltrace_signal(u32 signo) {}

#endif
