#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

static void *malloc_allocator(heap h, bytes s)
{
    return malloc(s);
}

static buffer files, contents;

static buffer read_stdin(heap h)
{
    buffer in = allocate_buffer(h, 1024);
    int r, k;
    while ((r = in->length - in->end) &&
           ((k = read(0, in->contents + in->end, r)), in->end += k, k == r)) 
        buffer_extend(in, 1024);
    return in;
}

static table parse_mappings(heap h, buffer desc)
{
    table root = allocate_table(h, fnv64, buffer_compare);
    table rf = allocate_table(h, fnv64, buffer_compare);
    table_set(root, files, rf);
    
    vector lines = split(h, desc, '\n');
    buffer line;
    vector_foreach(line, lines) {
        vector terms = split(h, line, ' ');
        buffer dest = vector_pop(terms);
        vector path = split(h, dest, '/');
        table dir = rf;

        // xxx - assume everyone starts with slash
        vector_pop(path);
        int len = vector_length(path);        
        for (int i = 0; i <(len -1); i++) {
            buffer p= vector_pop(path);
            table y;
            if (!(y = table_find(dir, p))) {
                y = allocate_table(h, fnv64, buffer_compare);
                // ((u8 *)p->contents)[p->end] = 0;
                table f = allocate_table(h, fnv64, buffer_compare);
                table_set(dir, p, f);
                table_set(f, files, y);
                dir = y;
            }  else {
                dir = table_find(y, files);
            }
        }
        buffer filename = vector_pop(path);
        table f = allocate_table(h, fnv64, buffer_compare);
        table_set(dir, filename, f);
        table_set(f, contents, vector_pop(terms));
    }
    return root;
}

void notreally(heap h, void *z, bytes length)
{
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
    if (fd < 0) {
        write(2, "couldn't open file ", 19);
        write(2, name->contents + name->start, buffer_length(name) -1);
        write(2, "\n", 1);        
        exit(-1);
    }
    u64 foff = pad(out->end, 4096);
    fstat(fd, &st);
    u64 psz = pad(st.st_size, 4096);
    u64 total = foff-out->end + psz;
    buffer_extend(out, foff-out->end + psz);
    read(fd, out->contents + foff, st.st_size);
    *length = st.st_size;
    // trying to paint in parts of the bss :(
    zero(out->contents + foff + st.st_size, psz-st.st_size);
    out->end += total;
    return foff;
}

    
// merge this into storage somehow
u64 serialize(buffer out, table t)
{
    // could perfect hash here
    u64 off = init_storage(out, t->count);

    table_foreach(t, k, v)  {

        if (k == contents) {
            buffer b = v;
            if (*(u8 *)buffer_ref(v, 0) == '@') {
                b->start += 1; 
                u64 length;
                u64 foff = read_file(out, (buffer)v, &length);
                storage_set(out, off, k, foff, length);
            } else {
                u64 foff = out->end;
                buffer_write(out, b->contents + b->start, buffer_length(b));
                storage_set(out, off, k, foff,  buffer_length(b));
            }
        } else {
            storage_set(out, off, k, serialize (out, (table)v), 0);
        }
    }
    return off;
}


int main(int argc, char **argv)
{
    struct heap h;
    h.allocate = malloc_allocator;
    h.deallocate = notreally;

    files = allocate_buffer(&h, 5);  buffer_append(files, "files", 5);
    contents = allocate_buffer(&h, 8);  buffer_append(contents, "contents", 8);
    buffer desc = read_stdin(&h);
    table root = parse_mappings(&h,desc);
    buffer out = allocate_buffer(&h, 10000);
    serialize(out, root);

    write(1, out->contents, out->end);
}
