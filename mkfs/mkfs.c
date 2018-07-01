#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <tfs.h>
#include <dirent.h>

#define SECTOR_SIZE 512

static buffer read_stdin(heap h)
{
    buffer in = allocate_buffer(h, 1024);
    int r, k;
    while ((r = in->length - in->end) &&
           ((k = read(0, in->contents + in->end, r)), in->end += k, k == r)) 
        buffer_extend(in, 1024);
    return in;
}

#define cfilename(__b) ({buffer n = little_stack_buffer(512); bprintf(n, "%b\0", __b); n->contents;})

void read_file(buffer dest, buffer name, u64 *length)
{
    struct stat st;
    int fd = open(cfilename(name), O_RDONLY);
    if (fd < 0) halt("couldn't open file %b\n", name);
    fstat(fd, &st);
    u64 size = st.st_size;
    buffer_extend(dest, pad(st.st_size, SECTOR_SIZE));
    read(fd, buffer_ref(dest, 0), size);
    dest->end += size;
}

heap malloc_allocator();

tuple root;
CLOSURE_1_1(finish, void, heap, void*);
void finish(heap h, void *v)
{
    rprintf ("val %v\n", v);    
    root = v;
}

CLOSURE_0_1(perr, void, string);
void perr(string s)
{
    rprintf("parse error %b\n", s);
}

// status
void includedir(tuple dest, buffer path)
{
    DIR *d = opendir(cfilename(dest));
}


static CLOSURE_1_3(bwrite, void, buffer, buffer, u64, status_handler);
static void bwrite(buffer d, buffer s, u64 offset, status_handler c)
{
    rprintf("bwrite! offset %p len %p\n", offset, buffer_length(s));
    apply(c, STATUS_OK);
}

static CLOSURE_1_4(bread, void, buffer, void *, u64, u64, status_handler);
static void bread(buffer b, void *source, u64 offset, u64 length, status_handler completion)
{
}

static CLOSURE_0_1(err, void, status);
static void err(status s)
{
    rprintf ("reported error\n");
}


static buffer translate_contents(heap h, value v)
{
    if (tagof(v) == tag_tuple) {
        value path = table_find((table)v, sym(host));
        if (path) {
            u64 len;
            // seems like it wouldn't be to hard to arrange
            // for this to avoid the staging copy
            buffer dest = allocate_buffer(h, 1024);
            read_file(dest, path, &len) ;
            return dest;
        }
    }
    return v;
}

// dont really like the file/tuple duality, but we need to get something running today,
// so push all the bodies onto a worklist
static value translate(heap h, vector worklist, filesystem fs, value v, status_handler sh)
{
    rprintf ("translate %v\n", v);
    switch(tagof(v)) {
    case tag_tuple:
        {
            tuple out = allocate_tuple();
            table_foreach((table)v, k, child) {
                rprintf ("k %b\n", symbol_string((symbol)k));
                buffer b;
                if (k == sym(contents)) {
                    vector_push(worklist, build_vector(h, out, translate_contents(h, child)));
                } else {
                    table_set(out, k, translate(h, worklist, fs, child, sh));
                }
            }
            return out;
        }
    default:
        return v;
    }
}

extern heap init_process_runtime();    
int main(int argc, char **argv)
{
    heap h = init_process_runtime();    
    parser p = tuple_parser(h, closure(h, finish, h), closure(h, perr));
    // this can be streaming
    parser_feed (p, read_stdin(h));
    buffer out = allocate_buffer(h, 1024);
    // fixing the size doesn't make sense in this context?
    filesystem fs = create_filesystem(h,
                                      SECTOR_SIZE,
                                      10ull * 1024 * 1024 * 1024,
                                      closure(h, bread, out),
                                      closure(h, bwrite, out),
                                      allocate_tuple());
    vector worklist = allocate_vector(h, 10);
    filesystem_write_tuple(fs, translate(h, worklist, fs, root, closure(h, err)));
    vector i;
    vector_foreach(worklist, i) {
        tuple f = vector_get(i, 0);        
        buffer c = vector_get(i, 1);
        allocate_fsfile(fs, f);
        filesystem_write(fs, f, c, 0, ignore_status);
    }
    
    flush(fs, ignore_status);
    write(1, out->contents, out->end);
}
