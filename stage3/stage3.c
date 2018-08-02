#include <runtime.h>
#include <kvm_platform.h>
#include <tfs.h>
#include <unix.h>
#include <gdb.h>



static CLOSURE_7_1(read_program_complete, void, tuple, heap, heap, heap, heap, heap, filesystem, buffer);
static void read_program_complete(tuple root, heap pages, heap general, heap physical, heap virtual, heap backed,
                                  filesystem fs, buffer b)
{
    //    elf_symbols(exc, closure(general, prinsym));
    rprintf ("read program complete: %p\n", buffer_ref(b, 0));
    exec_elf(b, root, root, general, physical, pages, virtual, backed, fs);
}

static CLOSURE_0_1(read_program_fail, void, status);
static void read_program_fail(status s)
{
    console("fail\n");
    halt("read program failed %v\n", s);
}

void startup(heap pages,
             heap general,
             heap physical,
             heap virtual,
             tuple root,
             filesystem fs)
{
    // xxx - loader had us throw away the first 4k page
    //    elf_symbols(START, closure(general, prinsym)); stage3
    init_unix(general, pages, physical, root);
    value p = table_find(root, sym(program));
    // error on not program 
    // copied from service.c - how much should we pass?
    heap virtual_pagesized = allocate_fragmentor(general, virtual, PAGESIZE);
    heap backed = physically_backed(general, virtual_pagesized, physical, pages);
    buffer_handler pg = closure(general, read_program_complete, root, pages, general, physical, virtual, backed, fs);
    
    tuple pro = resolve_path(root, split(general, p, '/'));
    filesystem_read_entire(fs, pro, backed, pg, closure(general, read_program_fail));
}

