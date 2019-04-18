#include <runtime.h>
#include <kvm_platform.h>
#include <pci.h>
#include <virtio.h>
#include <tfs.h>

extern void init_net(kernel_heaps kh);
extern void start_interrupts(kernel_heaps kh);

static struct kernel_heaps heaps;

// doesnt belong here
CLOSURE_3_0(startup, void, kernel_heaps, tuple, filesystem);
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

void runloop()
{
    /* minimum runloop period - XXX move to a config header */
    timestamp max_timeout = milliseconds(100);
    thunk t;

    while(1) {
	timestamp timeout = MIN(timer_check(), max_timeout);
	runloop_timer(timeout);
        while((t = dequeue(runqueue))) {
            apply(t);
        }
        handle_interrupts();
    }
}

//#define MAX_BLOCK_IO_SIZE PAGE_SIZE
#define MAX_BLOCK_IO_SIZE (256 * 1024)

static CLOSURE_2_3(offset_block_io, void, u64, block_io, void *, range, status_handler);
static void offset_block_io(u64 offset, block_io io, void *dest, range blocks, status_handler sh)
{
    assert((offset & (SECTOR_SIZE - 1)) == 0);
    u64 ds = offset >> SECTOR_OFFSET;
    blocks.start += ds;
    blocks.end += ds;

    // split I/O to storage driver to PAGESIZE requests
    heap h = heap_general(&heaps);
    merge m = allocate_merge(h, sh);
    status_handler k = apply_merge(m);
    while (blocks.start < blocks.end) {
        u64 span = MIN(range_span(blocks), MAX_BLOCK_IO_SIZE >> SECTOR_OFFSET);
        apply(io, dest, irange(blocks.start, blocks.start + span), apply_merge(m));

        // next block
        blocks.start += span;
        dest = (char *) dest + (span << SECTOR_OFFSET);
    }
    apply(k, STATUS_OK);
}

void init_extra_prints(); 

static CLOSURE_1_2(fsstarted, void, tuple, filesystem, status);
static void fsstarted(tuple root, filesystem fs, status s)
{
    assert(s == STATUS_OK);
    enqueue(runqueue, closure(heap_general(&heaps), startup, &heaps, root, fs));
}

static CLOSURE_2_3(attach_storage, void, tuple, u64, block_io, block_io, u64);
static void attach_storage(tuple root, u64 fs_offset, block_io r, block_io w, u64 length)
{
    // with filesystem...should be hidden as functional handlers on the tuplespace
    heap h = heap_general(&heaps);
    create_filesystem(h,
                      SECTOR_SIZE,
                      length,
                      heap_backed(&heaps),
                      closure(h, offset_block_io, fs_offset, r),
                      closure(h, offset_block_io, fs_offset, w),
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

	    u64 v = allocate_u64(heap_virtual_huge(&heaps), kern_length);
	    map(v, kern_base, kern_length, 0, heap_pages(&heaps));
#ifdef ELF_SYMTAB_DEBUG
	    rprintf("kernel ELF image at 0x%lx, length %ld, mapped at 0x%lx\n",
		    kern_base, kern_length, v);
#endif
	    add_elf_syms(alloca_wrap_buffer(v, kern_length));
            unmap(v, kern_length, heap_pages(&heaps));
	    break;
	}
    
    if (kern_base == INVALID_PHYSICAL) {
	console("kernel elf image region not found; no debugging symbols\n");
    }
}

extern void install_gdt64_and_tss();

static void __attribute__((noinline)) init_service_new_stack()
{
    kernel_heaps kh = &heaps;
    heap misc = heap_general(kh);
    heap pages = heap_pages(kh);

    /* Unmap the first page so we catch faults on null pointer references. */
    unmap(0, PAGESIZE, pages);

    runqueue = allocate_queue(misc, 64);
    init_clock(kh);
    init_random(now());
    __stack_chk_guard_init();
    start_interrupts(kh);
    init_extra_prints();
    init_runtime(kh);
    init_symtab(kh);
    read_kernel_syms();
    init_net(kh);
    tuple root = allocate_tuple();
    init_pci(kh);

    u64 fs_offset = 0;
    for_regions(e)
        if (region_type(e) == REGION_FILESYSTEM) {
            fs_offset = region_base(e);
        }
    if (fs_offset == 0)
        halt("filesystem region not found; halt\n");
    init_virtio_storage(kh, closure(misc, attach_storage, root, fs_offset));
    init_virtio_network(kh);
    pci_discover();

    /* Switch to stage3 GDT64, enable TSS and free up initial map */
    install_gdt64_and_tss();
    unmap(PAGESIZE, INITIAL_MAP_SIZE - PAGESIZE, pages);

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

#if KERNEL_DEBUG
	    console("pages heap: ");
	    print_u64(base);
	    console(", length ");
	    print_u64(length);
	    console("\n");
#endif
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
#if KERNEL_DEBUG
    console("physical memory:\n");
#endif
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
#if KERNEL_DEBUG
	    console("   base ");
	    print_u64(base);
	    console(", length ");
	    print_u64(length);
	    console("\n");
#endif
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
    static struct heap bootstrap;
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
    stack_location += stack_size - STACK_ALIGNMENT;
    *(u64 *)stack_location = 0;
    asm ("mov %0, %%rsp": :"m"(stack_location));
    init_service_new_stack();
}
