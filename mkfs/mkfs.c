#include <unix_process_runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <tfs.h>
#include <dirent.h>
#include <errno.h>

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

// its nice that we can append a file to any existing buffer, but harsh we have to grow the buffer
void read_file(buffer dest, buffer name, u64 *length)
{
    // mode bit metadata
    struct stat st;
    int fd = open(cstring(name), O_RDONLY);
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
    DIR *d = opendir(cstring(path));
    struct dirent *dip;
    while (dip = readdir(d)) {
    }
}


static CLOSURE_1_3(bwrite, void, descriptor, buffer, u64, status_handler);
static void bwrite(descriptor d, buffer s, u64 offset, status_handler c)
{
    int res = pwrite(d, buffer_ref(s, 0), buffer_length(s),  offset);
    apply(c, STATUS_OK);
}

static CLOSURE_1_4(bread, void, descriptor, void *, u64, u64, status_handler);
static void bread(descriptor d, void *source, u64 length, u64 offset, status_handler completion)
{
    apply(completion, timm("error", "empty file"));
}

static CLOSURE_1_3(buffer_bwrite, void, buffer, buffer, u64, status_handler);
static void buffer_bwrite(buffer d, buffer s, u64 offset, status_handler c)
{
    u64 final =  offset + buffer_length(s);
    buffer_extend(d, final);
    runtime_memcpy(buffer_ref(d, offset), buffer_ref(s, 0), buffer_length(s));
    d->end = MAX(d->end, final);
    apply(c, STATUS_OK);
}

static CLOSURE_1_4(buffer_bread, void, buffer, void *, u64, u64, status_handler);
static void buffer_bread(buffer d, void *source, u64 length, u64 offset, status_handler completion)
{
    apply(completion, timm("error", "empty file"));
}

static CLOSURE_0_1(err, void, status);
static void err(status s)
{
    rprintf ("reported error\n");
}

buffer cwd;

static buffer translate_contents(heap h, buffer cwd, value v)
{
    if (tagof(v) == tag_tuple) {
        // xxx - type assert
        buffer path = table_find((table)v, sym(host));
        
        if (path) {
            u64 len;
            if (*(u8 *)buffer_ref(path, 0) != '/')
                path = aprintf(h, "%b/%b", cwd, path);
            // seems like it wouldn't be to hard to arrange
            // for this to avoid the staging copy
            buffer dest = allocate_buffer(h, 1024);
            read_file(dest, path, &len);
            return dest;
        }
    }
    return v;
}

// dont really like the file/tuple duality, but we need to get something running today,
// so push all the bodies onto a worklist
static value translate(heap h, vector worklist, filesystem fs, value v, status_handler sh)
{
    switch(tagof(v)) {
    case tag_tuple:
        {
            tuple out = allocate_tuple();
            table_foreach((table)v, k, child) {
                buffer b;
                if (k == sym(contents)) {
                    vector_push(worklist, build_vector(h, out, translate_contents(h, cwd, child)));
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
#include <stdio.h>

static CLOSURE_2_2(fsc, void, heap, thunk, filesystem, status);
static void fsc(heap h, thunk close, filesystem fs, status s)
{
    
    vector worklist = allocate_vector(h, 10);
    tuple md = translate(h, worklist, fs, root, closure(h, err));
    filesystem_write_tuple(fs, md);
    vector i;
    vector_foreach(worklist, i) {
        tuple f = vector_get(i, 0);        
        buffer c = vector_get(i, 1);
        allocate_fsfile(fs, f);
        filesystem_write(fs, f, c, 0, ignore_status);
    }
    flush(fs, ignore_status);
    apply(close);
}

CLOSURE_1_0(close_file, void, descriptor);
void close_file(descriptor out)
{
    close(out);
}

CLOSURE_1_0(close_stdout, void, buffer);

void close_stdout(buffer b)
{
    write(1, buffer_ref(b, 0), buffer_length(b));
    close(1);
    exit(0);
}

// mkfs to be subsumed by nvm
int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    block_read r;
    block_write w;
    thunk d;
    
    if (argv[1][0] == '-') {
        buffer b = allocate_buffer(h, 1024);
        r = closure(h, buffer_bread, b);
        w = closure(h, buffer_bwrite, b);
        d = closure(h, close_stdout, b);
    }  else {
        descriptor out = open(argv[1], O_CREAT|O_WRONLY, 0644);
        if (out < 0) {
            halt("couldn't open output file %s\n", argv[1]);
        }
        r = closure(h, bread, out);
        w = closure(h, bwrite, out);
        d = closure(h, close_file, out);        
    }

    cwd = aprintf(h, ".");
    if (argc > 2)
        cwd = wrap_buffer(h, argv[2], runtime_strlen(argv[2]));


    parser p = tuple_parser(h, closure(h, finish, h), closure(h, perr));
    // this can be streaming
    parser_feed (p, read_stdin(h));
    // fixing the size doesn't make sense in this context?
    create_filesystem(h,
                      SECTOR_SIZE,
                      10ull * 1024 * 1024 * 1024, r, w, 
                      allocate_tuple(),
                      closure(h, fsc, h, d));
}
