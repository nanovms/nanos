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

u64 *ptalloc()
{
    return allocate(contiguous, PAGESIZE);
}

extern void enable_lapic();

extern void start_interrupts();

extern void startup();

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

    u64 stacksize = 16384;
    void *stack = allocate(contiguous, stacksize) + stacksize;
    asm ("mov %0, %%rsp": :"m"(stack));
    
    start_interrupts();
    // lets get out of the bios area
    // should translate into constructing a frame and an iret call (thread create)

    //pci_checko();
    startup();
    
    //  this is the musl start - move somewhere else
    //        char *program = "program";
    // extern void __libc_start_main(int (*)(int, char **, char**), int, char **);;
    // __libc_start_main(main, 1, &program);
}

extern void *gallocate(unsigned long a);
// for lwip
void *calloc(size_t nmemb, size_t b)
{
    allocate_zero(general, (unsigned long)b);
}

void *gallocate(unsigned long b)
{
    return(allocate(general, (unsigned long)b));
}
