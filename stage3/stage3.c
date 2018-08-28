#include <runtime.h>
#include <kvm_platform.h>
#include <tfs.h>
#include <unix.h>
#include <gdb.h>

void add_elf_syms(heap h, buffer b);

static CLOSURE_2_1(read_program_complete, void, kernel, tuple, buffer);
static void read_program_complete(kernel k, tuple root, buffer b)
{
    rprintf ("read program complete: %p %v\n", root, root);
    exec_elf(b, k);
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
    // copied from service.c - how much should we pass?
    heap virtual_pagesized = allocate_fragmentor(general, virtual, PAGESIZE);
    heap backed = physically_backed(general, virtual_pagesized, physical, pages);
    
    kernel k = init_unix(general, pages, physical, virtual, virtual_pagesized, backed, root, fs);
    if (k == INVALID_ADDRESS) {
	halt("unable to initialize unix instance; halt\n");
    }

    buffer_handler pg = closure(general, read_program_complete, k, root);
    value p = table_find(root, sym(program));
    tuple pro = resolve_path(root, split(general, p, '/'));
    filesystem_read_entire(fs, pro, backed, pg, closure(general, read_program_fail));
}

