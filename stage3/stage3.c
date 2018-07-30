#include <runtime.h>
#include <kvm_platform.h>
#include <unix.h>
#include <gdb.h>
#include <tfs.h>


static CLOSURE_5_1(read_program_complete, void, tuple, heap, heap, heap, heap, buffer);
static void read_program_complete(tuple root, heap pages, heap general, heap physical, heap virtual, buffer b)
{
    //    elf_symbols(exc, closure(general, prinsym));
    rprintf ("read program complete: %p\n", buffer_ref(b, 0));
    exec_elf(b, general, physical, pages, virtual, root);
}
static CLOSURE_0_1(read_program_fail, void, status);
static void read_program_fail(status s)
{
    halt("read program failed %v\n", s);
}

void startup(heap pages,
             heap general,
             heap physical,
             heap virtual,
             tuple root,
             filesystem fs)
{
    console("stage3\n");
    // xxx - loader had us throw away the first 4k page
    //    elf_symbols(START, closure(general, prinsym)); stage3
    init_unix(general, pages, physical, root);
    buffer_handler pg = closure(general, read_program_complete, root, pages, general, physical, virtual);
    rprintf("root: %v\n", root);
    value p = table_find(root, sym(program));
    rprintf("program %v\n", p);

    // copied from service.c - how much should we pass?
    heap virtual_pagesized = allocate_fragmentor(general, virtual, PAGESIZE);
    heap backed = physically_backed(general, virtual_pagesized, physical, pages);

    tuple pro = resolve_path(root, split(general, p, '/'));
    rprintf("resolve: %v\n", pro);
    
    filesystem_read_entire(fs, pro, backed, pg, closure(general, read_program_fail));
}

