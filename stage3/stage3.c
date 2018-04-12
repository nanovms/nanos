#include <sruntime.h>
#include <unix.h>
#include <pci.h>
#include <virtio.h>
#include <gdb.h>
#include <net.h>

u8 userspace_random_seed[16];

typedef struct aux {u64 tag; u64 val;} *aux;

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
                       
static void build_exec_stack(buffer s, heap general, vector argv, node env, vector auxp)
{
    int length = vector_length(argv) + table_elements(env) +  2 * vector_length(auxp) + 6;
    s->start = s->end = s->length - length *8;
    buffer_write_le64(s, vector_length(argv));
    tuple i;
    vector_foreach(i, argv) 
        buffer_write_le64(s, u64_from_pointer(aprintf(general, "%b\0\n", contents(i))->contents));
    
    buffer_write_le64(s, 0);

    table_foreach(env, n, v) {
        buffer binding = aprintf(general, "%b=%b\0\n", symbol_string(n), contents(v));
        buffer_write_le64(s, u64_from_pointer(binding->contents));
    }
    buffer_write_le64(s, 0);

    aux a;
    vector_foreach(a, auxp) {
        buffer_write_le64(s, a->tag);
        buffer_write_le64(s, a->val);
    }
    buffer_write_le64(s, 0);
    buffer_write_le64(s, 0);
}

process exec_elf(buffer ex, heap general, heap physical, heap pages, heap virtual, tuple fs)
{
    process p = create_process(general, pages, physical, fs);
    thread t = create_thread(p);
    void *user_entry = load_elf(ex, 0, pages, physical);        
    void *va;

    // extra elf munging
    Elf64_Ehdr *elfh = (Elf64_Ehdr *)buffer_ref(ex, 0);


    // also pick up the maximum load address for the brk
    for (int i = 0; i< elfh->e_phnum; i++){
        Elf64_Phdr *p = (void *)elfh + elfh->e_phoff + (i * elfh->e_phentsize);
        if ((p->p_type == PT_LOAD)  && (p->p_offset == 0))
            va = pointer_from_u64(p->p_vaddr);
        if (p->p_type == PT_INTERP) {
            char *n = (void *)elfh + p->p_offset;
            // xxx - assuming leading slash
            buffer nb = alloca_wrap_buffer(n, runtime_strlen(n));
            // file not found
            tuple ldso = resolve_path(fs, split(general, nb, '/'));
            u64 where = allocate_u64(virtual, HUGE_PAGESIZE);
            buffer c = table_find(ldso, sym(contents));
            user_entry = load_elf(c, where, pages, physical);
        }
    }


    struct aux auxp[] = {
        {AT_PHDR, elfh->e_phoff + u64_from_pointer(va)},
        {AT_PHENT, elfh->e_phentsize},
        {AT_PHNUM, elfh->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_RANDOM, u64_from_pointer(userspace_random_seed)},        
        {AT_ENTRY, u64_from_pointer(user_entry)}};
    
    t->frame[FRAME_RIP] = u64_from_pointer(user_entry);
    map(0, INVALID_PHYSICAL, PAGESIZE, pages);
    
    // use runtime random
    u8 seed = 0x3e;
    for (int i = 0; i< sizeof(userspace_random_seed); i++)
        userspace_random_seed[i] = (seed<<3) ^ 0x9e;
    
    vector aux = allocate_vector(general, 10);
    for (int i = 0; i< sizeof(auxp)/(2*sizeof(u64)); i++) 
        vector_push(aux, auxp+i);

    u64 stack_size = 2*1024*1024;
    void *user_stack = allocate(virtual, stack_size);
    buffer s = alloca_wrap_buffer(user_stack, stack_size);       
    map(u64_from_pointer(user_stack), allocate_u64(physical, stack_size), stack_size, pages);

    build_exec_stack(s,
                     general,
                     tuple_vector(general, children(resolve_cstring(fs, "arguments"))),
                     children(resolve_cstring(fs, "environment")),
                     aux);

    t->frame[FRAME_RSP] = u64_from_pointer(buffer_ref(s, 0));
    // move outside?
#if NET && GDB
    if (resolve_cstring(fs, "gdb")) {
        console ("gdb!\n");
        init_tcp_gdb(general, p, 1234);
    } else
#endif
    {
        console ("not gdb!\n");
        enqueue(runqueue, t->run);
    }
    return p;    
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
    exec_elf(exc, general, physical, pages, virtual, fs);
}

