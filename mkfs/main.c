#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

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

    
static table parse_mappings(heap h)
{
    table root = allocate_table(h, fnv64, buffer_compare);
    buffer desc = allocate_buffer(h, 1024);
    buffer a = allocate_buffer(h, 50);
    buffer b = allocate_buffer(h, 50);
    int r, k;

    while (r = desc->length - desc->end, (k = read(0, desc->contents + desc->end, r)) == r) 
        buffer_extend(desc, 1024);

    vector lines = split(h, desc, '\n');
    buffer line;
    vector_foreach(line, lines) {
        vector terms = split(h, desc, ' ');
        vector path = split(h, vector_pop(terms), '/');
        table dir = root;
        buffer p;
        for (int i = 0; i <vector_length(path)  -1; i++) {
            buffer p= vector_pop(path);
            table y;
            if (!(y = table_find(dir, p))) {
                y = allocate_table(h, fnv64, buffer_compare);
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
buffer serialize(heap h, table t, buffer b)
{
    // could perfect hash here
    buffer ind = create_index(h, t->count);
    table_foreach(t, k, v)  {
        buffer v2 = v;
        if (k == contents) {
            // it wouldn't be too hard to actually stream this
            v2 = allocate_buffer(h, 30);
            file(h, v, v2);
        }
        if (k == files) {
            b = serialize (h, v, b);            
        }
        index_set(ind, k, v2);        
    }
    return ind;
}


int main(int argc, char **argv)
{
    struct heap h;
    h.allocate = malloc_allocator;
    h.deallocate = notreally;
    
    // xx - symbol table
    files = allocate_buffer(&h, 5);  buffer_append(files, "files", 5);
    contents = allocate_buffer(&h, 8);  buffer_append(contents, "contents", 8);            
    table root = parse_mappings(&h);

    buffer x = allocate_buffer(&h, 10);
    print_stuff(x, root);
    write(2, x->contents, x->end);

    buffer out = allocate_buffer(&h, 10000);
    serialize(&h, root, out);
    write(0, out->contents, out->end);
}
