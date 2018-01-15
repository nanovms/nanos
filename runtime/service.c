#include <runtime.h>
#include <pci.h>

static struct region_heap generalh;
static struct region_heap pagesh;
static struct region_heap contiguoush;

status allocate_status(char *x, ...)
{
    console(x);
}


//void *memset(void *a, int val, unsigned long length)
//{
//    for (int i = 0 ; i < length; i++) ((u8*)a)[i]=val;
//}

handler *handlers;

extern void enable_lapic();
extern void start_interrupts();
extern void startup();

u64 virtual_region_base = 0x100000000;
u64 virtual_region_offset = 0x100000000;

region create_virtual_region(region r)
{
    u64 m2 = 1<<21;
    u64 pb = pad(region_base(r), m2);
    u64 pl = (region_length(r) - pb - region_base(r)) & MASK(21);
    
    region v = create_region(virtual_region_base, pl, REGION_VIRTUAL);
    map(region_base(v) , pb, pl, (heap)&pagesh);
    virtual_region_base += virtual_region_offset;
    return v;
}

void init_service(u64 passed_base)
{
    region c, g;

    for (region e = regions; region_type(e); e--) {
        if (region_type(e) == 1) {
            // ahem
            if  ((region_base(e) +  region_length(e)) == 0x90000) {
                region_allocator(&pagesh, e);
                // this is already identity mapped by stage2
            } else{
                g = e;
            }
        }
    }

    u64 split = region_length(g)/2;
    c = create_region(region_base(g) + split, split, REGION_PHYSICAL);
    region_length(g) = split;
    region_allocator(&generalh, create_virtual_region(g));
    region_allocator(&contiguoush, create_virtual_region(c));

    u64 stacksize = 16384;
    void *stack = allocate((heap)&contiguoush, stacksize) + stacksize - 8;
    asm ("mov %0, %%rsp": :"m"(stack));
    start_interrupts((heap)&pagesh, (heap)&generalh, (heap)&contiguoush);
    // should translate into constructing a frame and an iret call (thread create)
    // pci_checko();
    startup((heap)&pagesh, (heap)&generalh);
    //  this is the musl start - move somewhere else
    //        char *program = "program";
    // extern void __libc_start_main(int (*)(int, char **, char**), int, char **);;
    // __libc_start_main(main, 1, &program);
}

extern void *gallocate(unsigned long a);
// for lwip
void *calloc(size_t nmemb, size_t b)
{
    allocate_zero((heap)&generalh, (unsigned long)b);
}

void *gallocate(unsigned long b)
{
    return(allocate((heap)&generalh, (unsigned long)b));
}
