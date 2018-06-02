#include <sruntime.h>
#include <unix.h>
#include <pci.h>
#include <virtio.h>
#include <gdb.h>
#include <net.h>

symbol intern_buffer_symbol(void *x)
{
    struct buffer stemp;
    stemp.contents = x;
    stemp.start = stemp.end =0;
    int slen = pop_varint(&stemp);
    stemp.end = stemp.start + slen;
    return(intern(&stemp));
}

// would be nice to do this from a stream
// currently tuples are bibop, so they leak
// and use a reserved heap.
tuple storage_to_tuple(heap h, buffer b)
{
    tuple t = allocate_tuple();
    struct buffer etemp;
    buffer e = &etemp;
    copy_descriptor(e, b);
    u32 entries = pop_varint(e);

    for (int i; i < entries; i++) {
        u32 name = buffer_read_le32(e);
        u32 value = buffer_read_le32(e);
        u32 length = buffer_read_le32(e);
        u32 type = value >> STORAGE_TYPE_OFFSET;
        value &= MASK(STORAGE_TYPE_OFFSET);        
        symbol s = intern_buffer_symbol(b->contents + name);
        void *v;
        switch(type) {
        case storage_type_tuple:
            {
                struct buffer ttemp;
                copy_descriptor(&ttemp, e);
                ttemp.start = value;
                // length here is redundant, encode some header metadata
                v = storage_to_tuple(h, &ttemp);
            }
            break;
            // mkfs isn't shifting, so we wont
        case storage_type_unaligned:
        case storage_type_aligned:
            {
                buffer z = allocate(h, sizeof(struct buffer));
                z->contents = b->contents;
                z->start = value;
                z->end = value + length;
                v = z;
            }
            break;
        default:
            halt("fs metadata encoding error\n");
        }
        table_set(t, s, v);
    }
    return t;
}

// there is a type here
CLOSURE_0_2(prinsym, void, char *, u64);
void prinsym(char *name, u64 value)
{
    rprintf ("sym: %s %d\n", name, value);
}

void startup(heap pages, heap general, heap physical, heap virtual, buffer storage)
{
    console("stage3\n");
    tuple fs = storage_to_tuple(general, storage);
    init_unix(general, pages, physical, fs);
    tuple n = table_find(fs, sym(children));
    n = table_find(n, sym(program));    
    buffer z = table_find(n, sym(contents));        
    vector path = split(general, z, '/');
    tuple ex = resolve_path(fs, path);
    buffer exc = table_find(ex, sym(contents));
    elf_symbols(exc, closure(general, prinsym)); 
    exec_elf(exc, general, physical, pages, virtual, fs);
}

