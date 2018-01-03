#include <runtime.h>
#include <pci.h>

struct heap gh;
heap general = &gh;
struct heap ch;
heap contiguous = &ch;
void *pagebase;
static void *base;
static void *top;

status allocate_status(char *x, ...)
{
    console(x);
}


//void *memset(void *a, int val, unsigned long length)
//{
//    for (int i = 0 ; i < length; i++) ((u8*)a)[i]=val;
//}

handler *handlers;

static void *getpage(heap h, bytes b)
{
    u64 p = pad(b, h->pagesize);
    void *r  = top - p;
    top = r;
    return r;
}

static void *leak(heap h, bytes b)
{
    void *r  = base;
    base += b;
    return r;
}

void *ptalloc()
{
    return allocate(contiguous, PAGESIZE);
}

extern void __libc_start_main(int (*)(int, char **, char**), int, char **);;

extern int main(int argc, char **argv, char **envp);

extern void enable_lapic();

extern void start_interrupts();

static inline u64 *grabby(u64 *table, u64 t, unsigned int x)
{
    return (u64 *)(table[(t>>x)&MASK(9)] & ~MASK(12));
}

physical vtop(void *x)
{
    u64 xt = (u64)x;

    u64 *l3 = grabby(pagebase, xt, 39);
    u64 *l2 = grabby(l3, xt, 30);
    u64 *l1 = grabby(l2, xt, 21); // 2m pages
    u64 *l0 = grabby(l1, xt, 12);
    return (u64)l0 | xt & MASK(12);

}

void init_service(u64 passed_base)
{
    u32 start = *START_ADDRESS;
    base = (void *)(u64)start;
    gh.allocate = leak;
    ch.allocate = getpage;
    ch.pagesize = PAGESIZE;
    // fix
    top = (void *)0x400000;

    u64 *pages;
    mov_from_cr("cr3", pages);
    pagebase = pages;
    
    start_interrupts();

    // lets get out of the bios area
    // should translate into constructing a frame and an iret call (thread create)
    u64 stacksize = 16384;
    void *stack = allocate(contiguous, stacksize) + stacksize;
    asm ("mov %0, %%rsp": :"m"(stack));  
    pci_checko();
    char *program = "program";

    __libc_start_main(main, 1, &program);
}

extern void *gallocate(unsigned long a);
// for lwip
void *calloc(size_t nmemb, size_t b)
{
    void *x = gallocate(nmemb * b);
    memset(x, 0, b);
}

void *gallocate(unsigned long b)
{
    return(allocate(general, (unsigned long)b));
}
