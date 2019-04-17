#pragma once
#define STACK_ALIGNMENT 16

#define VIRTUAL_ADDRESS_BITS 48

#define FS_MSR 0xc0000100
#define GS_MSR 0xc0000101
#define LSTAR 0xC0000082
#define EFER_MSR 0xc0000080
#define EFER_SCE   0x0001
#define EFER_LME   0x0100
#define EFER_LMA   0x0400
#define EFER_NXE   0x0800
#define EFER_SVME  0x1000
#define EFER_LMSLE 0x2000
#define EFER_FFXSR 0x4000
#define EFER_TCE   0x8000
#define STAR_MSR 0xc0000081
#define LSTAR_MSR 0xc0000082
#define SFMASK_MSR 0xc0000084
#define TSC_DEADLINE_MSR 0x6e0

#define C0_WP   0x00010000
#define INITIAL_MAP_SIZE (0xa000)

#define VM_EXIT_GDB 0x7d
#define VM_EXIT_FAULT 0x7e
#define VM_EXIT_HALT 0x7f

static inline void cpuid(u32 fn, u32 * v)
{
    asm volatile("cpuid" : "=a" (v[0]), "=b" (v[1]), "=c" (v[2]), "=d" (v[3]) : "0" (fn));
}

extern u64 read_msr(u64);
extern void write_msr(u64, u64);
extern u64 read_xmsr(u64);
extern void write_xmsr(u64, u64);
extern void syscall_enter();

#define HUGE_PAGESIZE 0x100000000ull

#define mov_to_cr(__x, __y) asm volatile("mov %0,%%"__x : : "a"(__y) : "memory");
#define mov_from_cr(__x, __y) asm volatile("mov %%"__x", %0" : "=a"(__y) : : "memory");

static inline void enable_interrupts()
{
    asm volatile("sti");
}

static inline void disable_interrupts()
{
    asm volatile("cli");
}

/* returns -1 if x == 0, caller must check */
static inline u64 msb(u64 x)
{
#ifdef BOOT			/* 32 bit */
    /* gcc docs state __builtin_clz for 0 val is undefined, so check */
    unsigned int high = x >> 32;
    if (high) {
	return 63 - __builtin_clz(high);
    } else {
	unsigned int low = x & MASK(32);
	return low ? 31 - __builtin_clz(low) : -1ull;
    }
#else
    return x ? 63 - __builtin_clzll(x) : -1ull;
#endif
}

#ifndef BOOT
static inline u64 lsb(u64 x)
{
    return ((s64)__builtin_ffsll(x)) - 1;
}
#endif

// belong here? share with nasm
// currently maps to the linux gdb frame layout for convenience
#include <frame.h>

typedef u64 *context;

extern context running_frame;

#define BREAKPOINT_INSTRUCTION 00
#define BREAKPOINT_WRITE 01
#define BREAKPOINT_IO 10
#define BREAKPOINT_READ_WRITE 11

boolean breakpoint_insert(u64 a, u8 type, u8 length);
boolean breakpoint_remove(u32 a);

#define IRETURN(frame) asm volatile("mov %0, %%rbx"::"g"(frame)); asm("jmp frame_return")
#define ENTER(frame) asm volatile("mov %0, %%rbx"::"g"(frame)); asm("jmp frame_enter")

void msi_map_vector(int slot, int msislot, int vector);

static inline void write_barrier()
{
    asm volatile("sfence");
}

static inline void read_barrier()
{
    asm volatile("lfence" ::: "memory");
}

static inline void memory_barrier()
{
    asm volatile("mfence" ::: "memory");
}

static inline void set_syscall_handler(void *syscall_entry)
{
    u64 cs  = 0x08;

    write_msr(LSTAR_MSR, u64_from_pointer(syscall_entry));
    // 48 is sysret cs, and ds is cs + 16...so fix the gdt for return
    // 32 is syscall cs, and ds is cs + 8
    write_msr(STAR_MSR, (cs<<48) | (cs<<32));
    write_msr(SFMASK_MSR, 0);

    u64 efer_flags = EFER_SCE;
    u32 v[4];
    cpuid(0x80000001, v);
    if (v[3] & (1 << 20)) {     /* EDX.NX */
        efer_flags |= EFER_NXE;
    } else {
        msg_err("platform doesn't support no exec page protection\n");
    }

    write_msr(EFER_MSR, read_msr(EFER_MSR) | efer_flags);
}

static inline void set_page_write_protect(boolean enable)
{
    u64 cr0;
    mov_from_cr("cr0", cr0);
    cr0 = enable ? (cr0 | C0_WP) : (cr0 & ~C0_WP);
    mov_to_cr("cr0", cr0);
}

static inline u64 rdtsc(void)
{
    u32 a, d;
    asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx"); /* serialize execution */
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

void init_clock(kernel_heaps kh);
boolean using_lapic_timer(void);
void serial_out(u8 a);

boolean valiate_virtual(void *base, u64 length);

// tuples
char *interrupt_name(u64 code);
char *register_name(u64 code);

static inline word fetch_and_add(word* variable, word value)
{
    asm volatile("lock; xadd %0, %1"
                     : "+r" (value), "+m" (*variable) // input+output
                     : // No input-only
                     : "memory"
                     );
    return value;
}

static inline void store_fence()
{
    asm volatile("sfence");
}

static inline void load_fence()
{
    asm volatile("lfence");
}

static inline void memory_fence()
{
    asm volatile("mfence");
}

// tuples
#define FLAG_INTERRUPT 9

static inline u64 read_flags()
{
    u64 out;
    asm("pushf");
    asm("pop %0":"=g"(out));
    return out;
}

typedef struct queue *queue;
extern queue runqueue;

heap physically_backed(heap meta, heap virtual, heap physical, heap pages, u64 pagesize);
void physically_backed_dealloc_virtual(heap h, u64 x, bytes length);
void print_stack(context c);
void print_frame(context f);
#include <synth.h>
void *load_elf(buffer elf, u64 offset, heap pages, heap bss, boolean user);
void elf_symbols(buffer elf, closure_type(each, void, char *, u64, u64, u8));

#include <symtab.h>

typedef closure_type(fault_handler, context, context);

void configure_timer(timestamp rate, thunk t);

boolean enqueue(queue q, void *n);
void *dequeue(queue q);
void *queue_peek(queue q);
int queue_length(queue q);
queue allocate_queue(heap h, u64 size);
void deallocate_queue(queue q);

context allocate_frame(heap h);
void runloop() __attribute__((noreturn));
void handle_interrupts();
void install_fallback_fault_handler(fault_handler h);

#define PAGE_NO_EXEC U64_FROM_BIT(63)
#define PAGE_NO_FAT U64_FROM_BIT(9) /* AVL[0] */
#define PAGE_2M_SIZE U64_FROM_BIT(7)
#define PAGE_DIRTY U64_FROM_BIT(6)
#define PAGE_ACCESSED U64_FROM_BIT(5)
#define PAGE_CACHE_DISABLE U64_FROM_BIT(4)
#define PAGE_WRITETHROUGH U64_FROM_BIT(3)
#define PAGE_USER U64_FROM_BIT(2)
#define PAGE_WRITABLE U64_FROM_BIT(1)
#define PAGE_PRESENT U64_FROM_BIT(0)

#define PAGE_PROT_FLAGS (PAGE_NO_EXEC | PAGE_USER | PAGE_WRITABLE)
#define PAGE_DEV_FLAGS (PAGE_WRITABLE | PAGE_WRITETHROUGH | PAGE_NO_EXEC)

void map(u64 virtual, physical p, int length, u64 flags, heap h);
void unmap(u64 virtual, int length, heap h);

// xxx - hide
struct queue {
    u64 count;
    u64 write;
    u64 read;
    u64 size;
    heap h;
    void *buf[];
};


#define foreach_phdr(__e, __p)\
    for (int __i = 0; __i< __e->e_phnum; __i++)\
        for (Elf64_Phdr *__p = (void *)__e + __e->e_phoff + (__i * __e->e_phentsize); __p ; __p = 0) \

void msi_format(u32 *address, u32 *data, int vector);
void register_interrupt(int vector, thunk t);
extern heap interrupt_vectors;
