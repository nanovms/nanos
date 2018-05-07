#include <sruntime.h>
#include <pci.h>
#include <virtio.h>

extern void startup();
extern void start_interrupts();


static u8 bootstrap_region[1024];
static u64 bootstrap_base = (unsigned long long)bootstrap_region;
static u64 bootstrap_alloc(heap h, bytes length)
{
    u64 result = bootstrap_base;
    if ((result + length) >=  (u64_from_pointer(bootstrap_region) + sizeof(bootstrap_region)))
        return INVALID_PHYSICAL;
    bootstrap_base += length;
    return result;
}

queue runqueue;

static CLOSURE_1_0(read_complete, void, thunk);
static void read_complete(thunk target)
{
    enqueue(runqueue, target);
}

static context miscframe;

void runloop()
{
    thunk t;
    while(1) {
        // hopefully overall loop is being driven by the lapic periodic interrupt,
        // which should limit the skew
        timer_check();
        
        while((t = dequeue(runqueue))) {
            apply(t);
        }
        frame = miscframe;
        enable_interrupts();
        __asm__("hlt");
        disable_interrupts();
    }
}

static CLOSURE_0_0(ignore, void);
void ignore(){}

static CLOSURE_5_0(run_startup, void, heap, heap, heap, heap, buffer);
static void run_startup(heap pages, heap misc, heap physical, heap virtual, buffer fs)
{
    startup(pages, misc, physical, virtual, fs);
}

// bad global, put in the filesystem space
extern u64 storage_length;

void init_service_new_stack(heap pages, heap physical, heap backed, heap virtual)
{
    u64 fs_offset;
    
    // stack was here, map this invalid so we get crashes
    // in the appropriate place
    map(0, INVALID_PHYSICAL, PAGESIZE, pages);
    
    // rdtsc is corrupting something oddly
    //    init_clock(backed);

    heap misc = allocate_rolling_heap(backed);
    runqueue = allocate_queue(misc, 64);
    start_interrupts(pages, misc, physical);
    
    // general runtime startup
    initialize_timers(misc);
    
    init_symbols(misc);
    init_pci(misc);    
    init_virtio_storage(misc, backed, pages, virtual);
    init_virtio_network(misc, backed, pages);
    init_clock(backed);
    miscframe = allocate(misc, FRAME_MAX * sizeof(u64));
    pci_discover(pages, virtual);

    for (region e = regions; region_type(e); e -= 1) {
        if (region_type(e) == REGION_FILESYSTEM) {
            fs_offset = region_base(e);
        }
    }
    u64 len = storage_length - fs_offset;
    void *k = allocate(virtual, len);
    map(u64_from_pointer(k), allocate_u64(physical, len), len, pages);
    // wrap.. this was misc, which isn't aligned
    buffer drive = allocate_buffer(backed, len);
    drive->contents = k;
    drive->start = 0;
    drive->end = len;
    
    void *s = closure(misc, run_startup, pages, misc, physical, virtual, drive);
    void *z = closure(misc, read_complete, s);
    // dont really need to pass misc

    storage_read(k, fs_offset, len, z);

    // just to get the hlt loop to wake up and service timers, we
    // can adapt this to the front of the timer queue once we get
    // our clocks calibrated
    configure_timer(milliseconds(50), closure(misc, ignore)); 

    runloop();
}

// init linker set
void init_service()
{
    struct heap bootstrap;

    bootstrap.alloc = bootstrap_alloc;
    bootstrap.dealloc = leak;
    heap pages = region_allocator(&bootstrap, PAGESIZE, REGION_IDENTITY);
    heap physical = region_allocator(&bootstrap, PAGESIZE, REGION_PHYSICAL);    

    heap virtual = create_id_heap(&bootstrap, HUGE_PAGESIZE, (1ull<<VIRTUAL_ADDRESS_BITS)- HUGE_PAGESIZE, HUGE_PAGESIZE);
    heap virtual_pagesize = allocate_fragmentor(&bootstrap, virtual, PAGESIZE);

    heap backed = physically_backed(&bootstrap, virtual_pagesize, physical, pages);

    frame = allocate(&bootstrap, FRAME_MAX *8);
    // on demand stack allocation
    u64 stack_size = 32*PAGESIZE;
    u64 stack_location = allocate_u64(backed, stack_size);
    stack_location += stack_size - 16;
    asm ("mov %0, %%rsp": :"m"(stack_location));
    init_service_new_stack(pages, physical, backed, virtual); 
    // locals aren't really valid any more!
}
