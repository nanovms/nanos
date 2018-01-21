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

// translate whole directories!
static void file(heap h, buffer name, buffer dest)
{
    push_character(name, 0);
    int fd = open((char *)name->contents, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    buffer_extend(dest, st.st_size);
    read(fd, dest->contents + dest->end, st.st_size);
    dest->end += st.st_size;
}



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
                ((u8 *)p->contents)[p->end] = 0;
                table f = allocate_table(h, fnv64, buffer_compare);
                table_set(dir, p, f);
                table_set(f, files, y);
            }
            dir = y;
        }
        buffer filename = vector_pop(path);
        table f = allocate_table(h, fnv64, buffer_compare);
        table_set(dir, filename, f);
        table_set(f, contents, vector_pop(terms));
    }
    return root;
}

void print_stuff(buffer b, table x)
{
    int start = b->end;
    table f;
    table_foreach(x, k, v){
        buffer key = k;
        table file = v;
        b->end = start;
        buffer_append(b, key->contents, key->end);
        if ((f = table_find(file, files))) {
            push_character(b, '/');
            print_stuff(b, f);
        } else {
            write(2, b->contents, b->end);
            write(2, "\n", 1);
        }
        b->end = start;
    }
}

void notreally(heap h, void *z, bytes length)
{
}

// stop copying all that stuff..dont necessarily need to stage this
u64 serialize(heap h, table t, buffer out)
{
    // could perfect hash here
    u64 off;
    storage ind = create_storage(h, t->count, out, &off);
    table_foreach(t, k, v)  {
        u64 off, sz;

        if (k == contents) {
            off = out->end;
            file(h, v, out);
            sz = out->end - sz;
        } else {
            u64 b = serialize (h, v, out);
            sz = 0;  // not used here
        }
        storage_set(ind, k, off, sz);        
    }
    return off;
}


int main(int argc, char **argv)
{
    struct heap h;
    h.allocate = malloc_allocator;
    h.deallocate = notreally;
    
    // xx - symbol table
    files = allocate_buffer(&h, 5);  buffer_append(files, "files", 5);
    contents = allocate_buffer(&h, 8);  buffer_append(contents, "contents", 8);

    buffer desc = read_stdin(&h);
    
    table root = parse_mappings(&h,desc);
    
    buffer x = allocate_buffer(&h, 10);
    print_stuff(x, root);
    write(2, x->contents, x->end);

    buffer out = allocate_buffer(&h, 10000);
    serialize(&h, root, out);

    write(1, out->contents, out->end);
}
