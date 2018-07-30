#include <runtime.h>
#include <kvm_platform.h>
#include <unix.h>
#include <gdb.h>
#include <tfs.h>


static CLOSURE_5_1(read_program_complete, void, tuple, heap, heap, heap, heap, buffer);
static void read_program_complete(tuple root, heap pages, heap general, heap physical, heap virtual, buffer b)
{
    //    elf_symbols(exc, closure(general, prinsym)); 
    exec_elf(b, general, physical, pages, virtual, root);
}

void startup(heap pages, heap general, heap physical, heap virtual, tuple root)
{
    console("stage3\n");
    // xxx - loader had us throw away the first 4k page
    //    elf_symbols(START, closure(general, prinsym)); stage3
    init_unix(general, pages, physical, root);
    console("unix complete\n");    
    buffer_handler pg = closure(general, read_program_complete, root, pages, general, physical, virtual);
    rprintf("root: %v\n", root);
    value p = table_find(root, sym(program));
    rprintf("program %p\n", p);
    contentsof(resolve_path(root, split(general, p, '/')), pg);
}

