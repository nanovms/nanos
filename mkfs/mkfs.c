#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <tfs.h>

static buffer read_stdin(heap h)
{
    buffer in = allocate_buffer(h, 1024);
    int r, k;
    while ((r = in->length - in->end) &&
           ((k = read(0, in->contents + in->end, r)), in->end += k, k == r)) 
        buffer_extend(in, 1024);
    return in;
}

u64 read_file(buffer out, buffer name, u64 *length)
{
    struct stat st;
    push_character(name, 0);
    // xxx -- all files are page aligned and padded, because
    // we might be doing linky things. that isn't necessary
    // for many files, and we should also be able to
    // allocate more tightly around them..in particular
    // by keeping a single small region in the pad to fill
    char *fn = (char *)(name->contents+name->start);
    int fd = open(fn, O_RDONLY);
    if (fd < 0) halt("couldn't open file %b\n", name);
    u64 foff = pad(out->end, PAGESIZE);
    fstat(fd, &st);
    u64 psz = pad(st.st_size, PAGESIZE);
    u64 total = foff-out->end + psz;
    buffer_extend(out, foff-out->end + psz);
    read(fd, out->contents + foff, st.st_size);
    *length = st.st_size;
    // trying to paint in parts of the bss :(
    zero(out->contents + foff + st.st_size, psz-st.st_size);
    out->end += total;
    return foff;
}

heap malloc_allocator();

tuple root;
CLOSURE_1_1(finish, void, heap, void*);
void finish(heap h, void *v)
{
    if (tagof(v) == tag_tuple) {
        buffer b = allocate_buffer(h, 100);
        print_tuple(b, v);
        rprintf ("tval %b\n", b);
    } else {
        rprintf ("val %b\n", v);
    }
    root = v;
}

CLOSURE_0_1(perr, void, string);
void perr(string s)
{
    rprintf("parse error %b\n", s);
}


static CLOSURE_1_3(bwrite, void, buffer, buffer, u64, status_handler);
static void bwrite(buffer d, buffer s, u64 offset, status_handler c)
{
}

static CLOSURE_1_4(bread, void, buffer, void *, u64, u64, status_handler);
static void bread(buffer b, void *source, u64 offset, u64 length, status_handler completion)
{
}

extern heap init_process_runtime();    
int main(int argc, char **argv)
{
    heap h=  init_process_runtime();    
    parser p = tuple_parser(h, closure(h, finish, h), closure(h, perr));
    // this can be streaming
    parser_feed (p, read_stdin(h));
    vector file_relocations = allocate_vector(h, 10);

    buffer b = allocate_buffer(h, 10);
    table dout = allocate_table(h, key_from_symbol, pointer_equal);
    table din = allocate_table(h, identity_key, pointer_equal);
    //    serialize_tuple(dout, b, root);
    // this cant be streaming
    //    tuple t2 = deserialize_tuple(h, din, b);
    buffer out = allocate_buffer(h, 1024);
    // fixing the size doesn't make sense in this context?
    tuple root = allocate_tuple();
    filesystem fs = create_filesystem(h, 512, 10ull * 1024 * 1024 * 1024,
                                      closure(h, bread, out),
                                      closure(h, bwrite, out),
                                      root);

    write(1, out->contents, out->end);
}
