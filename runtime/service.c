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
    // try to pad to 2m..right now its a distraction
    //    u64 m2 = 1<<21;
    //    u64 pb = pad(region_base(r), m2);
    //    u64 pl = (region_length(r) - pb - region_base(r)) & MASK(21);
    
    u64 pb = region_base(r);
    u64 pl = region_length(r);
    region v = create_region(virtual_region_base, pl, REGION_VIRTUAL);
    map(region_base(v) , pb, pl, (heap)&pagesh);
    virtual_region_base += virtual_region_offset;
    // it would be .. nice? if the virtual region could
    // deplete the physical region? 
    region_length(v) = region_length(r);
    return v;
}

void init_service(u64 passed_base)
{
    region k[2]={0};

    // gonna assume there are two regions. we'reagonna take the little
    // one for pages, and the big one for stuff

    for (region e = regions; region_type(e); e--) {
        if (region_type(e) == 1) {
            if (k[0] == 0) {
                k[0] = e;
            } else {
                if (region_length(k[0]) < region_length(e)) {
                    k[1] = k[0];
                    k[0] = e;
                } else {
                    if (k[1] == 0) {
                        k[1] = e;
                    } else {
                        if (region_length(k[1]) < region_length(e)) {
                            k[1] = e;
                        }
                    }
                }
            }
        }
    }
    region_allocator(&pagesh, k[1], PAGESIZE);
    u64 split = region_length(k[0])/2;
    region c = create_region(region_base(k[0]) + split, split, REGION_PHYSICAL);
    
    region_length(k[0]) = split;
    region_allocator(&generalh, create_virtual_region(k[0]), 1);
    region_allocator(&contiguoush, create_virtual_region(c), PAGESIZE);

    u64 stacksize = 16384;
    void *stack = allocate((heap)&contiguoush, stacksize) + stacksize - 8;
    asm ("mov %0, %%rsp": :"m"(stack));
    start_interrupts((heap)&pagesh, (heap)&generalh, (heap)&contiguoush);
    // should translate into constructing a frame and an iret call (thread create)
    // pci_checko();
    startup((heap)&pagesh, (heap)&generalh, (heap)&contiguoush);
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
