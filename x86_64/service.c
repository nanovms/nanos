#include <runtime.h>
#include <kvm_platform.h>
#include <pci.h>
#include <virtio.h>
#include <tfs.h>

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

static CLOSURE_2_3(offset_block_write, void, block_write, u64, buffer, u64, status_handler);
static void offset_block_write(block_write w, u64 start, buffer b, u64 offset, status_handler h)
{
    apply(w, b, start + offset, h);
}

// ordering of length and offset
static CLOSURE_2_4(offset_block_read, void, block_read, u64, void *, u64, u64, status_handler);
static void offset_block_read(block_read r, u64 start, void *dest, u64 length, u64 offset, status_handler h)
{
    apply(r, dest, length, start + offset, h);
}

filesystem allocate_filesystem(tuple root, heap h, block_read in, block_write out)
{
    u64 fs_offset, fs_length;
    for_regions(e)
        if (region_type(e) == REGION_FILESYSTEM) {
            fs_length = region_length(e);
            fs_offset = region_base(e);
        }
    return create_filesystem(h,
                             512,
                             fs_length,
                             in, out,
                             root);
}

void init_service_new_stack(heap pages, heap physical, heap backed, heap virtual)
{
    u64 fs_offset;
    
    // stack was here, map this invalid so we get crashes
    // in the appropriate place
    map(0, INVALID_PHYSICAL, PAGESIZE, pages);

    heap misc = allocate_rolling_heap(backed);
    runqueue = allocate_queue(misc, 64);
    start_interrupts(pages, misc, physical);

    tuple root = allocate_tuple();
    init_runtime(backed);
    initialize_timers(misc);
    
    init_pci(misc);

    block_read in;
    block_write out;
    init_virtio_storage(misc, backed, pages, virtual, &in, &out);
    // if we have a storage? - its gets instantiated on a callback - fix, populate root after
    // we also know the size then
    allocate_filesystem(root, misc, in, out);
    init_virtio_network(misc, backed, pages);
    init_clock(backed);
    miscframe = allocate(misc, FRAME_MAX * sizeof(u64));
    pci_discover(pages, virtual);
    // just to get the hlt loop to wake up and service timers. 
    // should change this to post the delta to the front of the queue each time
    configure_timer(milliseconds(50), ignore);
    startup(pages, misc, physical, virtual, root);    
}

// init linker set
void init_service()
{
    console("babby\n");
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
}
