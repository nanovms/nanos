#include <runtime.h>
#include <kvm_platform.h>
#include <tfs.h>
#include <unix.h>
#include <gdb.h>
#include <virtio.h>

// copied from print_tuple()
void print_root(buffer b, tuple z)
{
    table t = valueof(z);
    boolean sub = false;
    bprintf(b, "(");
    table_foreach(t, n, v) {
        if (sub) {
            push_character(b, ' ');
        }
        bprintf(b, "%b:", symbol_string((symbol)n));
        if (n != sym_this(".") && n != sym_this("..") && n != sym_this("special")) {
            if (tagof(v) == tag_tuple) {
                print_root(b, v);
            } else {
                bprintf(b, "%b", v);
            }
        }
        sub = true;
    }
    bprintf(b, ")");
}

static CLOSURE_2_1(read_program_complete, void, process, tuple, buffer);
static void read_program_complete(process kp, tuple root, buffer b)
{
    if (table_find(root, sym(trace))) {
        rprintf("read program complete: %p ", root);
        rprintf("gitversion: %s ", gitversion);

        buffer b = allocate_buffer(transient, 64);
        print_root(b, root);
        debug(b);
        deallocate_buffer(b);
        rprintf("\n");
       
    }
    exec_elf(b, kp);
}

static CLOSURE_0_1(read_program_fail, void, status);
static void read_program_fail(status s)
{
    halt("read program failed %v\n", s);
}

void startup(kernel_heaps kh,
             tuple root,
             filesystem fs)
{
    /* kernel process is used as a handle for unix */
    process kp = init_unix(kh, root, fs);
    if (kp == INVALID_ADDRESS) {
	halt("unable to initialize unix instance; halt\n");
    }
    heap general = heap_general(kh);
    buffer_handler pg = closure(general, read_program_complete, kp, root);
    value p = table_find(root, sym(program));
    tuple pro = resolve_path(root, split(general, p, '/'));
    init_network_iface(root);
    filesystem_read_entire(fs, pro, heap_backed(kh), pg, closure(general, read_program_fail));
}

