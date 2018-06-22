#include <runtime.h>
#include <kvm_platform.h>
#include <unix.h>
#include <gdb.h>
#include <tfs.h>

// shouldn't use unix, but the fact that this should work is cute
heap allocate_tagged_region(heap h, u64 tag)
{
    u64 size = 4*1024*1024;
    void *region;
    //    void *region = mmap(pointer_from_u64(tag << va_tag_offset),
    //                        size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    // use a specific growable heap
    return create_id_heap(h, u64_from_pointer(region), size, 1);
}


static CLOSURE_5_1(read_program_complete, void, tuple, heap, heap, heap, heap, buffer);
static void read_program_complete(tuple root, heap pages, heap general, heap physical, heap virtual, buffer b)
{
    //    elf_symbols(exc, closure(general, prinsym)); 
    exec_elf(b, general, physical, pages, virtual, root);
}

static CLOSURE_3_1(program_name_complete, void, tuple, heap, buffer_handler, buffer); 
static void program_name_complete(tuple root, heap h, buffer_handler next, buffer program)
{
    contentsof(resolve_path(root, split(h, program, '/')), next);
}

void startup(heap pages, heap general, heap physical, heap virtual, tuple root)
{
    console("stage3\n");
    init_unix(general, pages, physical, root);
    buffer_handler pg = closure(general, read_program_complete, root, pages, general, physical, virtual);  
    contentsof(lookup(root, sym(program)), closure(general, program_name_complete, root, general, pg));
}

