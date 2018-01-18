#include <runtime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

static void *malloc_allocator(heap h, bytes s)
{
    return malloc(s);
}

static buffer filessym;

static buffer file(heap h, buffer name)
{
    push_character(name, 0);
    int fd = open((char *)name->contents, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    buffer out = allocate_buffer(h, st.st_size);
    read(fd, out->contents, st.st_size);
    out->end = st.st_size;
    return out;
}

static table parse_mappings(heap h)
{
    table root = allocate_table(h, fnv64, buffer_compare);
    buffer a = allocate_buffer(h, 50);
    buffer b = allocate_buffer(h, 50);

    char c[512];
    int x;
    int state = 0;
    table dir = root;
    u64 size;
    
    while ((size = read(0, c, 512))> 0) {
        for (int i = 0; i < size; i++) {
            character x = c[i]; 
            switch (state) {
            case 0:
                if (x == '/') {
                    // initial slash is a noop, intermediate // is broken
                    if ((buffer_length(a) != 0) || (dir != root)){
                        table y;
                        if (!(y = table_find(dir, a))) {
                            y = allocate_table(h, fnv64, buffer_compare);
                            table f = allocate_table(h, fnv64, buffer_compare);
                            table_set(dir, a, f);
                            table_set(f, filessym, y);
                            a = allocate_buffer(h, 20);
                        } else {
                            a->end = 0;
                        }
                        dir = y;
                    }
                    break;
                }
                if (x != ' ') {
                    push_character(a, x);
                    break;
                }
                state++;
            case 1:
                if (x == ' ') {
                    break;
                }
                state++;
            case 2:
                if (x != '\n') {
                    push_character(b, x);
                    break;
                }

                table ft = allocate_table(h, fnv64, buffer_compare);
                // could fold this in with directory create
                
                table_set(dir, a, ft);
                a = allocate_buffer(h, 50);
                b = allocate_buffer(h, 50);
                dir = root;
                state = 0;
            }
        }
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
        if ((f = table_find(file, filessym))) {
            push_character(b, '/');
            print_stuff(b, f);
        } else {
            write(1, b->contents, b->end);
            write(1, "\n", 1);
        }
        b->end = start;
    }
}

void notreally(heap h, void *z, bytes length)
{
}

int main(int argc, char **argv)
{
    struct heap h;
    h.allocate = malloc_allocator;
    h.deallocate = notreally;
    filessym = allocate_buffer(&h, 6);        
    // add symbol table to thingy
    buffer_append(filessym, "files", 6);        
    table root = parse_mappings(&h);
    buffer x = allocate_buffer(&h, 10);
    print_stuff(x, root);
}
