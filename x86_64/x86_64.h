#define VIRTUAL_ADDRESS_BITS 48

#define FS_MSR 0xc0000100
#define GS_MSR 0xc0000101
#define LSTAR 0xC0000082
#define EFER_MSR 0xc0000080
#define EFER_SCE 1
#define STAR_MSR 0xc0000081
#define LSTAR_MSR 0xc0000082
#define SFMASK_MSR 0xc0000084

extern u64 cpuid();
extern u64 read_msr(u64);
extern void write_msr(u64, u64);
extern u64 read_xmsr(u64);
extern void write_xmsr(u64, u64);
extern void syscall_enter();

#define HUGE_PAGESIZE 0x100000000ull


static inline void enable_interrupts()
{
    asm ("sti");
}

static inline void disable_interrupts()
{
    asm ("cli");
}

/* returns -1 if x == 0, caller must check */
static inline u64 msb(u64 x)
{
    /* gcc docs state __builtin_clz for 0 val is undefined, so check */
    unsigned int high = x >> 32;
    if (high) {
	return 63 - __builtin_clz(high);
    } else {
	unsigned int low = x & (((u64)1 << 32) - 1);
	return low ? 31 - __builtin_clz(low) : -1;
    }
}

// belong here? share with nasm
// currently maps to the linux gdb frame layout for convenience
#include <frame.h>

typedef u64 *context;

extern u64 *frame;

#define BREAKPOINT_INSTRUCTION 00
#define BREAKPOINT_WRITE 01
#define BREAKPOINT_IO 10
#define BREAKPOINT_READ_WRITE 11

boolean breakpoint_insert(u64 a, u8 type, u8 length);
boolean breakpoint_remove(u32 a);

#define IRETURN(frame) __asm__("mov %0, %%rbx"::"g"(frame)); __asm__("jmp frame_return")
#define ENTER(frame) __asm__("mov %0, %%rbx"::"g"(frame)); __asm__("jmp frame_enter")

void msi_map_vector(int slot, int msislot, int vector);

static inline void write_barrier()
{
    asm ("sfence");
}

#define rol(__x, __b)\
     ({\
        __asm__("rol %1, %0": "=g"(__x): "i" (__b));\
        __x;\
     })\

/*static inline u64 msb(u64 x)
{
    u64 r;
    __asm__("bsr %0, %1":"=g"(r):"g"(x));
    return r;
}
*/

static inline void read_barrier()
{
        asm ("lfence");
}

static inline void memory_barrier()
{
    // waa
    asm ("lfence");
    asm ("sfence");
}


static inline void set_syscall_handler(void *syscall_entry)
{
    u64 cs  = 0x08;
    u64 ss  = 0x10;

    write_msr(LSTAR_MSR, u64_from_pointer(syscall_entry));
    // 48 is sysret cs, and ds is cs + 16...so fix the gdt for return
    // 32 is syscall cs, and ds is cs + 8
    write_msr(STAR_MSR, (cs<<48) | (cs<<32));
    write_msr(SFMASK_MSR, 0);
    write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_SCE);
}

static time rdtsc(void)
{
    u64 a, d;
    asm("cpuid":::"%rax", "%rbx", "%rcx", "%rdx");
    asm volatile("rdtsc" : "=a" (a), "=d" (d));

    return (((time)a) | (((time)d) << 32));
}

void init_clock(heap backed_virtual);
void serial_out(u8 a);

boolean valiate_virtual(void *base, u64 length);

// tuples
char *interrupt_name(u64 code);
char *register_name(u64 code);

static inline word fetch_and_add(word* variable, word value)
{
    __asm__ volatile("lock; xadd %0, %1"
                     : "+r" (value), "+m" (*variable) // input+output
                     : // No input-only
                     : "memory"
                     );
    return value;
}


// tuples
#define FLAG_INTERRUPT 9

static inline u64 read_flags()
{
    u64 out;
    __asm__("pushf");
    __asm__("pop %0":"=g"(out));
    return out;
}

typedef struct queue *queue;
extern queue runqueue;

heap physically_backed(heap meta, heap virtual, heap physical, heap pages);
void print_stack(context c);
void print_frame(context f);
#include <synth.h>
void *load_elf(buffer elf, u64 offset, heap pages, heap bss);
void elf_symbols(buffer elf, closure_type(each, void, char *, u64, u64, u8));

#include <symtab.h>

#define mov_to_cr(__x, __y) __asm__("mov %0,%%"__x: :"a"(__y):);
#define mov_from_cr(__x, __y) __asm__("mov %%"__x", %0":"=a"(__y):);

typedef closure_type(fault_handler, u64 *, context);
void configure_timer(time rate, thunk t);
void enqueue(queue q, void *n);
void *dequeue(queue q);
void *queue_peek(queue q);
int queue_length(queue q);
queue allocate_queue(heap h, u64 size);
void runloop();
heap allocate_fragmentor(heap meta, heap parent, bytes size);
void map(u64 virtual, physical p, int length, heap h);

// xxx - hide
struct queue {
    // these should be on cache lines in the mp case
    u64 read, write, length;
    void *body[];
};


#define foreach_phdr(__e, __p)\
    for (int __i = 0; __i< __e->e_phnum; __i++)\
        for (Elf64_Phdr *__p = (void *)__e + __e->e_phoff + (__i * __e->e_phentsize); __p ; __p = 0) \

