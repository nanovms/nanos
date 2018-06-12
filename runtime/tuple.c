#include <runtime.h>
// synthesize the parser
typedef closure_type(selfparser, parser, parser, character);
typedef closure_type(completion, parser, void *);
typedef closure_type(err_internal, parser, buffer);

typedef table charset;
static charset name_terminal;
static charset whitespace;
buffer intermediate;
heap theap;

// region?
tuple allocate_tuple()
{
    return tag(allocate_table(theap, key_from_symbol, pointer_equal), tag_tuple);
}

// find sequence combinator
static boolean member(charset cs, character c)
{
    return table_find(cs, pointer_from_u64((u64)c))?true:false; 
}

// kind of a special case y combinator, try to fix the
// allocation issues
static CLOSURE_2_1(selfinate, parser, heap, selfparser, character);
static parser selfinate (heap h, selfparser p, character in)
{
    parser k = (void *)closure(h, selfinate, h, p);
    return apply(p, k, in);
}

// this also has to be done on the return
static parser combinate(heap h, selfparser p)
{
    return (parser)closure(h, selfinate, h, p);    
}


static CLOSURE_1_2(til_newline, parser, parser, parser, character);
static parser til_newline(parser finish, parser self, character in)
{
    if (in == '\n') return finish;
    return self;
}

static CLOSURE_2_2(eat_whitespace, parser, heap, parser, parser, character);
static parser eat_whitespace(heap h, parser finish, parser self, character in)
{
    if (in == '#') {
        return combinate(h, closure(h, til_newline, self));
    }
    
    if (member(whitespace, in)) return self;
    return apply(finish, in);
}

static parser ignore_whitespace(heap h, parser next)
{
    selfparser s = (void *)closure(h, eat_whitespace, h, next);
    return combinate(h, s);
}

static CLOSURE_3_2(terminal, parser, completion, charset, buffer, parser, character);
static parser terminal(completion c, charset final, buffer b, parser self, character in)
{
    if (member(final, in)) {
        // apply(apply(x)) calls x twice
        parser p = apply(c, b);
        return apply(p, in);
    } else {
        push_character(b, in);
        return self;
    }
}

CLOSURE_4_2(validate, parser, heap, parser, err_internal, buffer, parser, character);
parser validate(heap h, parser next, err_internal err, buffer b, parser self, character in)
{
    if (buffer_length(b) == 0)
        return apply(next, in);
    // utf8
    character c = pop_character(b);
    if (c == in) return self;
    return apply(err, aprintf(h, "expected %c got %c\n", c, in));
}


static CLOSURE_3_1(value_complete, parser, tuple, symbol, parser, void *);
static parser value_complete(tuple t, symbol name, parser check, void *v)
{
    table_set(t, name, v);
    return check;
}

static CLOSURE_3_1(parse_value, parser, heap, completion, err_internal, character);

static CLOSURE_4_1(name_complete, parser, heap, tuple, parser, err_internal, void *);
static parser name_complete(heap h, tuple t, parser check, err_internal err, void *b)
{
    buffer res = allocate_buffer(h, 20);
    completion vc = closure(h, value_complete, t, intern(b), check);
    parser term = combinate(h, closure(h, terminal, vc, name_terminal, res));
    // not sure why we have to violate typing
    parser pv = (void *)closure(h, parse_value, h, vc, err);
    intermediate->start = 0; // hack
    return ignore_whitespace(h, combinate(h, closure(h, validate, h, pv, err, intermediate)));
}


static CLOSURE_4_2(is_end_of_tuple, parser,
                   heap, completion, tuple, err_internal,
                   parser, character);
static parser is_end_of_tuple(heap h, completion c, tuple t, err_internal e, parser self, character in)
{
    if (in != ')') {
        parser *p = allocate(h, sizeof(parser));
        parser cew = ignore_whitespace(h, self);
        completion nc = closure(h, name_complete, h, t, cew, e);
        *p = ignore_whitespace(h, combinate(h, closure(h, terminal, nc, name_terminal, allocate_buffer(h, 100))));
        return apply(*p, in);
    }
    return apply(c, t);
}

static CLOSURE_5_2(is_end_of_vector, parser,
                   heap, completion, tuple, err_internal, u64 *,
                   parser, character);
static parser is_end_of_vector(heap h, completion c, tuple t, err_internal e, u64 *index, parser self, character in)
{
    // keep index also
    if (in != ']') {
        buffer b = allocate_buffer(h, 10);
        format_number(b, *index, 10, 1);
        completion vc = closure(h, value_complete, t, intern(b), self);
        (*index)++;
        // doesnt handle whitespace before end 
        return apply(ignore_whitespace(h, (void *)closure(h, parse_value, h, vc, e)), in);
    }
    return apply(c, t);
}


static parser parse_value(heap h, completion c, err_internal err, character in)
{
    switch(in) {
    case '(':
        return combinate(h, closure(h, is_end_of_tuple, h, c, allocate_tuple(), err));
    case '[':
        {
            u64 *i= allocate(h, sizeof(u64));
            *i = 0;
            return combinate(h, closure(h, is_end_of_vector, h, c, allocate_tuple(), err, i));
        }
    default:
        return apply(ignore_whitespace(h, combinate(h, closure(h, terminal, c, name_terminal, allocate_buffer(h, 8)))), in);
    }
}


static CLOSURE_0_2(kill, parser, parser, character);
static parser kill(parser self, character ig)
{
    return self;
}


static CLOSURE_2_1(bridge_err, parser, heap, parse_error, buffer);
static parser bridge_err(heap h, parse_error error, buffer b)    
{
    apply(error, b);
    return combinate(h, closure(h, kill));
}

static CLOSURE_3_1(bridge_completion, parser, heap, parse_finish, err_internal, void *);
static parser bridge_completion(heap h, parse_finish c, err_internal err, void *v)
{
    apply(c, v);
    // another self case
    completion bc = closure(h, bridge_completion, h, c, err);
    return (void *)closure(h, parse_value, h, bc, err);    
}

static charset charset_from_string(heap h, char *elements)
{
    table t = allocate_table(h, identity_key, pointer_equal);
    // utf8 me
    for (char *i = elements; *i; i++) 
        table_set(t, pointer_from_u64((u64)*i), (void *)1);
    return t;
}

parser tuple_parser(heap h, parse_finish c, parse_error err)
{
    if (!whitespace) whitespace = charset_from_string(h, " \n\t");
    if (!name_terminal) name_terminal = charset_from_string(h, "():[]  \n\t#");    
    if (!intermediate) intermediate = aprintf(h, ":");
    // whitespace eat
    // error close over line number
    err_internal k = closure(h, bridge_err, h, err);
    completion bc = closure(h, bridge_completion, h, c, k);    
    return (void *)closure(h, parse_value, h, bc, k);
}

parser parser_feed (parser p, buffer b)
{
    string_foreach(i, b) p = apply(p, i);
    return p;
}


// type bits 1
// no error
static u64 pop_header(buffer f, u8 *type)
{
    u8 a = pop_u8(f);
    *type = a>>7;
    u64 len = a & 0x3f;
    if (a & (1<<6)) {
        do {
            u8 a = pop_u8(f);
            len = (len<<7) + (a & 127);
        } while(a & 0x80);
    }
    rprintf ("pop header %d %d\n", *type, len, a);
    return len;
}

static void push_header(buffer b, u8 type, u64 length)
{
    int bits = msb(length);
    int words = 0;
    buffer_extend(b, words + 1);
    if (bits > 6) words = (bits - 6)/7;
    u8 first = (type << 7) | (((words)?1:0)<<6) | (length >> (words * 7));
    push_u8(b, first);
    for (int i = 0; i<words; i++) 
        *((u8 *)b->contents + b->start + (words - i)) = (length >> (i * 7)) | (i?0x80:0);
    b->end += words;
    rprintf ("push header %d %d %x\n", type, length, first);
}

// dict is number to symbol
// h is for buffer values, copy them out
void *deserialize_tuple(heap h, tuple dictionary, buffer source)
{
    u8 type;
    u64 len = pop_header(source, &type);
    if (type) {
        tuple t = allocate_tuple();
        for (int i = 0; i < len ; i++) {
            u8 nametype, valuetype;
            u64 nlen = pop_header(source, &nametype);
            symbol s;
            if (nametype) {
                s = table_find(dictionary, pointer_from_u64(nlen));
                if (!s) rprintf("missing decode dictionary symbol %d\n", nlen);
            } else {
                buffer n = alloca_wrap_buffer(buffer_ref(source, 0), nlen);
                void *index = pointer_from_u64((u64)dictionary->count);
                rprintf("insert decode dictionary symbol %d %d %b\n", index, nlen, symbol_string(intern(n)));
                table_set(dictionary, index, s = intern(n));
                source->start += nlen;                
            }
            table_set(t,s, deserialize_tuple(h, dictionary,source));
        }
        return t;
    } else {
        buffer b = allocate_buffer(h, len);
        rprintf("pop buffer: %d\n", len);
        // doesn't seem like this should be neccessary in all cases
        runtime_memcpy(buffer_ref(b, 0), source->contents + source->start, len);
        source->start += len;
        return b;
    }
}

// dict is symbol to number
void serialize_tuple(tuple dictionary, buffer dest, tuple t)
{
    push_header(dest, 1, t->count);
    table_foreach (t, n, v) {
        u64 sn;
        rprintf("checking dict %p\n", n);
        if ((sn = u64_from_pointer(table_find(dictionary, n)))) {
            rprintf("reuse\n");
            push_header(dest, 1, sn - 1);
        } else {
            sn = dictionary->count;
            table_set(dictionary, n, pointer_from_u64(sn + 1));
            rprintf("create sending dict %d %p %b\n", sn, n, symbol_string(n));
            push_header(dest, 0, buffer_length(symbol_string(n)));
            push_buffer(dest, symbol_string(n));
        }
        if (tagof(v) == tag_tuple) {
            serialize_tuple(dictionary, dest, v);
        } else {
            push_header(dest, 0, buffer_length((buffer)v));
            rprintf("push buffer: %d\n", buffer_length((buffer)v));
            push_buffer(dest, (buffer)v);
        }
    }        
}

void init_tuples(heap h)
{
    theap = h;
}

// parametric printf
void print_tuple(buffer b, tuple t)
{
    boolean sub = false;
    bprintf(b, "(");
    table_foreach(t, n, v) {
        if (sub) {
            push_character(b, ' ');
        }
        bprintf(b, "%b:", symbol_string((symbol)n));
        if (tagof(v) == tag_tuple) {
            print_tuple(b, v);
        } else {
            bprintf(b, "%b", v);
        }
        sub = true;
    }
    bprintf(b, ")");
}
