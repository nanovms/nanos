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

// merge this into storage somehow
u64 serialize(buffer out, table t)
{
    // could perfect hash here
    u64 off = init_storage(out, t->count);

    table_foreach(t, k, v)  {
        if (k == contents) {
            buffer name = (buffer)v;
            struct stat st;
            push_character(name, 0);
            int fd = open((char *)name->contents, O_RDONLY);

            u64 foff = out->end;
            fstat(fd, &st);
            u64 psz = pad(st.st_size, 4);
            buffer_extend(out, psz);
            read(fd, out->contents + out->end, st.st_size);
            out->end += psz;
            storage_set(out, off, k, foff, st.st_size);        
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
