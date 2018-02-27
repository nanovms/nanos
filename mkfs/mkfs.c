#include <runtime.h>
#include <symbol.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

void *tuple_region;
u64 tuple_region_size;

static u64 malloc_allocator(heap h, bytes s)
{
    return (u64)malloc(s);
}

#define is_tuple(x) ((x > tuple_region) && (u64_from_pointer(x-tuple_region) < tuple_region_size))

static buffer read_stdin(heap h)
{
    buffer in = allocate_buffer(h, 1024);
    int r, k;
    while ((r = in->length - in->end) &&
           ((k = read(0, in->contents + in->end, r)), in->end += k, k == r)) 
        buffer_extend(in, 1024);
    return in;
}

static u64 sintern(buffer b, table symbols, symbol n)
{
    // consider padding
    u64 offset;
    if (!(offset = u64_from_pointer(table_find(symbols, n)))) {
        string s = symbol_string(n);
        offset = b->end;
        push_varint(b, buffer_length(s));
        push_buffer(b, s);
        table_set(symbols, n, pointer_from_u64(offset));
    }
    return offset;
}

typedef struct relocation {
    u64 offset;
    u64 length;
    buffer name;
} *relocation;

static u64 serialize(buffer b,
                     heap h,
                     table t,
                     vector file_relocations,
                     table symbols)
{
    int tlen = table_elements(t);
    table_foreach (t, n, v) if (n == sym(file)) tlen+=1;
    u64 result = b->end;
    push_varint(b, tlen);
    struct buffer here;
    int len = tlen * STORAGE_SLOT_SIZE;
    
    buffer_extend(b, len);
    copy_descriptor(&here, b);
    b->end += len;

    table_foreach (t, n, v) {
        buffer nb = *(buffer *)n;
        
        if (n == sym(file)) {
            buffer_write_le32(&here, sintern(b, symbols, sym(contents)));
            relocation r = allocate(h, sizeof(struct relocation));
            r->offset = here.end; here.end += 4;
            // push a an extra length property .. this needs to be
            // an actual value and not encoded over the offset
            buffer_write_le32(&here, sintern(b, symbols, sym(length)));
            r->length = here.end; here.end += 4;            
            r->name = v;
            vector_push(file_relocations, r);
        } else {
            buffer_write_le32(&here, sintern(b, symbols, n));
            if (is_tuple(v)) {
                // storage byte tuple could be 32 bit aligned.
                buffer_write_le32(&here, serialize(b, h, v, file_relocations, symbols)|
                                  (storage_type_tuple << STORAGE_TYPE_OFFSET));
            } else {
                u32 off =  sintern(b, symbols, intern(v));
                buffer_write_le32(&here,off | (storage_type_unaligned << STORAGE_TYPE_OFFSET));
            }
        }
    }
    return result;
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

static void resolve_files(heap h, buffer b, vector file_relocations)
{
    table locations = allocate_tuple();
    relocation r, i;
    vector_foreach(i, file_relocations) {
        if (!table_find(locations, i)) {
            relocation r = allocate(h, sizeof(struct relocation));
            r->offset = read_file(b, i->name, &r->length)  | (storage_type_aligned<<STORAGE_TYPE_OFFSET);
            table_set(locations, i->name, r);
        }
    }
                     
    vector_foreach(i, file_relocations) {
        r = table_find(locations, i->name);
        *(u32 *)buffer_ref(b, i->offset) = r->offset;
        *(u32 *)buffer_ref(b, i->length) = r->length;
    }
}

static table parse_mappings(heap h, buffer desc)
{
    tuple root = allocate_tuple();
    vector lines = split(h, desc, '\n');
    buffer line;
    vector_foreach(line, lines) {
        tuple children;

        vector terms = split(h, line, ' ');
        buffer dest = vector_pop(terms);
        vector path = split(h, dest, '/');

        // xxx - assume everyone starts with slash
        vector_pop(path);
        int len = vector_length(path);
        tuple here = root;
        
        for (int i = 0; i <len; i++) {
            if (!(children = table_find(here, sym(children)))) 
                table_set(here, sym(children), children = allocate_tuple());
            buffer p = vector_pop(path);
            if (!(here = table_find(children, p))) {
                table_set(children, intern(p), here = allocate_tuple());
            }
        }

        buffer contents = vector_pop(terms);
        if (*(u8 *) buffer_ref(contents, 0) == '@') {
            contents->start++;
            table_set(here, sym(file), contents);
        } else {
            table_set(here, sym(contents), contents);
        }
    }
    return root;
}

void notreally(heap h, u64 z, bytes length)
{
}



int main(int argc, char **argv)
{
    struct heap h;
    h.alloc = malloc_allocator;
    h.dealloc = notreally;

    buffer out = allocate_buffer(&h, 1024);
    tuple_region_size = 4*1024*1024;
    tuple_region = mmap(0, tuple_region_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    heap th = create_id_heap(&h, u64_from_pointer(tuple_region), tuple_region_size, 1);
    // ok...since in stage3 the syscall interface is directly available, we can
    // live on top of that with no restrictions
    init_symbols(th);    
    
    buffer desc = read_stdin(&h);
    table root = parse_mappings(&h, desc);
    table symbols = allocate_table(&h, key_from_symbol, symbol_equal);
    vector file_relocations = allocate_vector(&h, 10);
    serialize(out, &h, root, file_relocations, symbols);
    resolve_files(&h, out, file_relocations);
    write(1, out->contents, out->end);
}
