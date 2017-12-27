#include <runtime.h>
#include <pci.h>

struct heap gh;
heap general = &gh;
heap contiguous = &gh;

// xxx - get from boot loader
static void *base = (void *)0x16000;


status allocate_status(char *x, ...)
{
    console(x);
}


void *memset(void *a, int val, unsigned long length)
{
    for (int i = 0 ; i < length; i++) ((u8*)a)[i]=val;
}

static void *leak(heap h, bytes b)
{
    void *r  = base;
    base += b;
    return r;
}

extern int main(int argc, char **argv);
void init_service()
{
    gh.allocate = leak;
    pci_checko();
    main(0, 0);
}
