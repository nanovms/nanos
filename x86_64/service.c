#include <runtime.h>
#include <kvm_platform.h>
#include <pci.h>
#include <virtio.h>
#include <tfs.h>

extern void init_net(kernel_heaps kh);
extern void startup();
extern void start_interrupts(kernel_heaps kh);

static struct kernel_heaps heaps;

// doesnt belong here
void startup(kernel_heaps kh,
             tuple root,
             filesystem fs);

// xxx -this is handing out a page per object
heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    heap h = heap_general(kh);
    heap pages = heap_pages(kh);
    heap physical = heap_physical(kh);
    return physically_backed(h,
                             create_id_heap(h, tag << va_tag_offset, 1ull<<va_tag_offset, physical->pagesize),
                             physical, pages, physical->pagesize);
}

#define BOOTSTRAP_REGION_SIZE_KB	2048
static u8 bootstrap_region[BOOTSTRAP_REGION_SIZE_KB << 10];
static u64 bootstrap_base = (unsigned long long)bootstrap_region;
static u64 bootstrap_alloc(heap h, bytes length)
{
    u64 result = bootstrap_base;
    if ((result + length) >=  (u64_from_pointer(bootstrap_region) + sizeof(bootstrap_region))) {
	console("*** bootstrap heap overflow! ***\n");
        return INVALID_PHYSICAL;
    }
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

static CLOSURE_2_4(offset_block_read, void, block_read, u64, void *, u64, u64, status_handler);
static void offset_block_read(block_read r, u64 start, void *dest, u64 length, u64 offset, status_handler h)
{
    apply(r, dest, length, start + offset, h);
}

void init_extra_prints(); 

CLOSURE_3_0(startup, void, kernel_heaps, tuple, filesystem);

static CLOSURE_1_2(fsstarted, void, tuple, filesystem, status);
static void fsstarted(tuple root, filesystem fs, status s)
{
    enqueue(runqueue, closure(heap_general(&heaps), startup, &heaps, root, fs));
}

static CLOSURE_1_3(attach_storage, void, tuple, block_read, block_write, u64);
static void attach_storage(tuple root, block_read r, block_write w, u64 length)
{
    u64 fs_offset;
    
    // bios couldn't probe length(?) .. so from the virtio driver...remember
    // the location of that block
    for_regions(e)
        if (region_type(e) == REGION_FILESYSTEM) {
            fs_offset = region_base(e);
        }

    // with filesystem...should be hidden as functional handlers on the tuplespace
    heap h = heap_general(&heaps);
    create_filesystem(h,
                      512, // from the device please
                      length,
                      closure(h, offset_block_read, r, fs_offset),
                      closure(h, offset_block_write, w, fs_offset),
                      root,
                      closure(h, fsstarted, root));
}

static void read_kernel_syms()
{
    u64 kern_base = INVALID_PHYSICAL;
    u64 kern_length;

    /* add kernel symbols */
    for_regions(e)
	if (region_type(e) == REGION_KERNIMAGE) {
	    kern_base = region_base(e);
	    kern_length = region_length(e);

	    /* XXX At present, this maps the kernel ELF image in order
	     * to get to the symbols, then leaves it mapped to use its
	     * strings. It should just copy the strings over and unmap
	     * it. */
	    u64 v = allocate_u64(heap_virtual_huge(&heaps), kern_length);
	    map(v, kern_base, kern_length, heap_pages(&heaps));
#ifdef ELF_SYMTAB_DEBUG
	    rprintf("kernel ELF image at %P, length %P, mapped at %P\n",
		    kern_base, kern_length, v);
#endif
	    add_elf_syms(alloca_wrap_buffer(v, kern_length));
	    break;
	}
    
    if (kern_base == INVALID_PHYSICAL) {
	console("kernel elf image region not found; no debugging symbols\n");
    }
}

static void format_elf_symbol(buffer dest, buffer fmt, vlist *v)
{
    u64 x, offset = varg(*v, u64);
    char *name = find_elf_sym(x, &offset);
    bprintf(dest, "%s + %p", name, offset);
}


static struct heap bootstrap;
static heap pages, physical_memory, backed, backed_2M, virtual;
static void __attribute__((noinline)) init_service_new_stack()
{
    kernel_heaps kh = &heaps;
    heap misc = heap_general(kh);
    heap pages = heap_pages(kh);
    heap virtual_huge = heap_virtual_huge(kh);
    heap virtual_page = heap_virtual_page(kh);
    heap physical = heap_physical(kh);
    heap backed = heap_backed(kh);
    // just to find maintain the convention of faulting on zero references
    unmap(0, PAGESIZE, pages);
    runqueue = allocate_queue(misc, 64);

    start_interrupts(kh);
    init_runtime(kh);
    init_symtab(kh);
    read_kernel_syms();
    init_clock(kh);
    init_net(kh);
    tuple root = allocate_tuple();
    initialize_timers(kh);
    init_pci(kh);
    init_virtio_storage(kh, closure(misc, attach_storage, root));
    init_virtio_network(kh);

    miscframe = allocate(misc, FRAME_MAX * sizeof(u64));
    pci_discover();
    // just to get the hlt loop to wake up and service timers. 
    // should change this to post the delta to the front of the queue each time
    configure_timer(milliseconds(50), ignore);
    runloop();
}

static heap init_pages_id_heap(heap h)
{
    heap pages = allocate_id_heap(h, PAGESIZE);
    for_regions(e) {
	if (region_type(e) == REGION_IDENTITY) {
	    u64 base = region_base(e);
	    u64 length = region_length(e);
	    if ((base & (PAGESIZE-1)) | (length & (PAGESIZE-1))) {
		console("identity region unaligned!\nbase: ");
		print_u64(base);
		console(", length: ");
		print_u64(length);
		halt("\nhalt");
	    }
	    console("pages heap: ");
	    print_u64(base);
	    console(", length ");
	    print_u64(length);
	    console("\n");
	    if (!id_heap_add_range(pages, base, length))
		halt("    - id_heap_add_range failed\n");
	    return pages;
	}
    }
    halt("no identity region found; halt\n");
    return INVALID_ADDRESS;	/* no warning */
}

static heap init_physical_id_heap(heap h)
{
    heap physical = allocate_id_heap(h, PAGESIZE);
    boolean found = false;
    console("physical memory:\n");
    for_regions(e) {
	if (region_type(e) == REGION_PHYSICAL) {
	    /* Align for 2M pages */
	    u64 base = region_base(e);
	    u64 end = base + region_length(e) - 1;
	    u64 page2m_mask = (2 << 20) - 1;
	    base = (base + page2m_mask) & ~page2m_mask;
	    end &= ~page2m_mask;
	    if (base >= end)
		continue;
	    u64 length = end - base;
	    console("   base ");
	    print_u64(base);
	    console(", length ");
	    print_u64(length);
	    console("\n");
	    if (!id_heap_add_range(physical, base, length))
		halt("    - id_heap_add_range failed\n");
	    found = true;
	}
    }
    if (!found) {
	halt("no valid physical regions found; halt\n");
    }
    return physical;
}

static void init_kernel_heaps()
{
    struct heap bootstrap;
    bootstrap.alloc = bootstrap_alloc;
    bootstrap.dealloc = leak;

    heaps.pages = init_pages_id_heap(&bootstrap);
    heaps.physical = init_physical_id_heap(&bootstrap);

    heaps.virtual_huge = create_id_heap(&bootstrap, HUGE_PAGESIZE,
				      (1ull<<VIRTUAL_ADDRESS_BITS)- HUGE_PAGESIZE, HUGE_PAGESIZE);
    assert(heaps.virtual_huge != INVALID_ADDRESS);

    heaps.virtual_page = create_id_heap_backed(&bootstrap, heaps.virtual_huge, PAGESIZE);
    assert(heaps.virtual_page != INVALID_ADDRESS);

    heaps.backed = physically_backed(&bootstrap, heaps.virtual_page, heaps.physical, heaps.pages, PAGESIZE);
    assert(heaps.backed != INVALID_ADDRESS);

    heaps.general = allocate_mcache(&bootstrap, heaps.backed, 5, 20, PAGESIZE_2M);
    assert(heaps.general != INVALID_ADDRESS);
}

// init linker set
void init_service()
{
    init_kernel_heaps();
    u64 stack_size = 32*PAGESIZE;
    u64 stack_location = allocate_u64(heap_backed(&heaps), stack_size);
    stack_location += stack_size - 16;
    *(u64 *)stack_location = 0;
    asm ("mov %0, %%rsp": :"m"(stack_location));
    init_service_new_stack();
}
