#include <runtime.h>
#include <pci.h>

struct heap gh;
heap general = &gh;
heap contiguous = &gh;
static void *base;

status allocate_status(char *x, ...)
{
    console(x);
}


//void *memset(void *a, int val, unsigned long length)
//{
//    for (int i = 0 ; i < length; i++) ((u8*)a)[i]=val;
//}

static void *leak(heap h, bytes b)
{
    void *r  = base;
    base += b;
    return r;
}

extern void __libc_start_main(int (*)(int, char **, char**), int, char **);;

extern int main(int argc, char **argv);
void init_service(u64 passed_base)
{
    u32 start = *START_ADDRESS;
    console("whoot\n");
    print_u64(start);
    console("\n");
    print_u64(passed_base);
    console("\n");    
    base = (void *)(u64)start;
    gh.allocate = leak;
    pci_checko();
    char *program = "program";
    __libc_start_main(main, 1, &program);
    main(0, 0);
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
