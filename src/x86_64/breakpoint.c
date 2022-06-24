#include <kernel.h>

typedef struct breakpoint {
    u32 address;
    boolean assigned;
    void (*set)();
} *breakpoint;

// there are 7 of these
static void _b0(u64 a){__asm__("mov %0, %%dr0":: "a"(a));}
static void _b1(u64 a){__asm__("mov %0, %%dr1":: "a"(a));}
static void _b2(u64 a){__asm__("mov %0, %%dr2":: "a"(a));}
static void _b3(u64 a){__asm__("mov %0, %%dr3":: "a"(a));}

struct breakpoint breakpoints[4] = {{0, 0, _b0}, {0, 0, _b1}, {0, 0, _b2}, {0, 0, _b3}};

#define mutate(__x, __offset, __len, __v)                           \
    (((__x) & ~ (((1ull<<__len) - 1) << (__offset))) | ((__v)<<(__offset)))


// XXX move to gdb init?
#define DEBUG_BIT 3
void enable_debug_registers()
{
    u64 cr4;
    mov_from_cr("cr4", cr4);
    if (!(cr4 & U64_FROM_BIT(DEBUG_BIT))) {
        cr4 |= U64_FROM_BIT(DEBUG_BIT);
        mov_to_cr("cr4", cr4);
    }
}

closure_function(6, 0, void, set_breakpoint,
                 boolean, set, u64, a, u8, type, int, reg, word, cnt, thunk, completion)
{
    register u64 dr7;
    int i = bound(reg);
    if (bound(set)) {
        mov_from_cr("dr7", dr7);
        // r/w bits
        dr7 = mutate(dr7, 4 * i + 16, 2, bound(type));
        // len
        dr7 = mutate(dr7, 4 * i + 18, 2, 0);
        // both global and local
        dr7 = mutate(dr7, 2 * i, 2, 3);
        mov_to_cr("dr7", dr7);
        breakpoints[i].set(bound(a));
    } else {
        mov_from_cr("dr7", dr7);
        dr7 = mutate(dr7, 2 * i, 2, 0);
        mov_to_cr("dr7", dr7);
    }
    if (fetch_and_add(&bound(cnt), (word)-1) == 1) {
        if (bound(completion))
            apply(bound(completion));
        closure_finish();
    }
}

// address type
boolean breakpoint_insert(heap h, u64 a, u8 type, u8 log_length, thunk completion)
{
    enable_debug_registers();

    for (int i = 0; i< 4; i++) {
        if (!breakpoints[i].assigned) {
            breakpoints[i].assigned = true;
            breakpoints[i].address = a;
            thunk t = closure(h, set_breakpoint, true, a, type, i, total_processors, completion);
            cpuinfo ci;
            vector_foreach(cpuinfos, ci) {
                assert(enqueue_irqsafe(ci->cpu_queue, t));
            }
            wakeup_or_interrupt_cpu_all();
            return(true);
        }
    }
    return(false);
}

boolean breakpoint_remove(heap h, u32 a, thunk completion)
{
    for (int i = 0; i< 4; i++) {
        if (breakpoints[i].address == a) {
            breakpoints[i].assigned = false;
            thunk t = closure(h, set_breakpoint, false, 0, 0, i, total_processors, completion);
            cpuinfo ci;
            vector_foreach(cpuinfos, ci) {
                assert(enqueue_irqsafe(ci->cpu_queue, t));
            }
            wakeup_or_interrupt_cpu_all();
            return(true);
        }
    }
    return(false);
}

