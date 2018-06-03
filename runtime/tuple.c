#include <runtime.h>
// synthesize the parser
typedef closure_type(selfparser, parser, parser, character);
typedef closure_type(completion, parser, void *);
typedef closure_type(err_internal, parser, buffer);

typedef table charset;
static charset name_terminal;
static charset whitespace;

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
    void *x = closure(h, selfinate, h, p);    
    return (parser)p;
}


static CLOSURE_1_2(eat_whitespace, parser, parser, parser, character);
static parser eat_whitespace(parser finish, parser self, character in)
{
    if (member(whitespace, in)) return self;
    return finish;
}

    
static parser ignore_whitespace(heap h, parser next)
{
    selfparser s = (void *)closure(h, eat_whitespace, next);
    return combinate(h, s);
}

static CLOSURE_3_2(terminal, parser, completion, charset, buffer, parser, character);
static parser terminal(completion c, charset final, buffer b, parser self, character in)
{
    if (member(final, in)) {
        return apply(c, b);
    } else {
        push_character(b, in);
        return self;
    }
}

CLOSURE_4_2(validate, parser, heap, parser, err_internal, buffer, parser, character);
parser validate(heap h, parser next, err_internal err, buffer b, parser self, character in)
{
    if (buffer_length(b) == 0)
        return next;
    // utf8
    character c = pop_character(b);
    if (c == in) return self;
    return apply(err, aprintf(h, "expected %c got %c\n", c, in));
}

static CLOSURE_3_1(value_complete, parser, tuple, symbol, completion, void *);
static parser value_complete(tuple t, symbol name, completion c, void *v)
{
    table_set(t, name, v);
    return apply(c, t);
}

static CLOSURE_3_1(parse_value, parser, heap, completion, err_internal, character);

static CLOSURE_4_1(name_complete, parser, heap, tuple, completion, err_internal, void *);
static parser name_complete(heap h, tuple t, completion c, err_internal err, void *b)
{
    completion vc = closure(h, value_complete, t, intern(b), c);
    buffer res = allocate_buffer(h, 20);
    parser term = combinate(h, closure(h, terminal, vc, name_terminal, res));
    // not sure why we have to violate typing
    return (void *)closure(h, parse_value, h, c, err);
}

static parser parse_value(heap h, completion c, err_internal err, character in)
{
    if (in == '(') {
        tuple t = allocate_tuple();
        completion nc =  closure(h, name_complete, h, t, c, err);
        return combinate(h, closure(h, terminal, nc, name_terminal, allocate_buffer(h, 100)));
    } else {
        buffer res = allocate_buffer(h, 8);
        return combinate(h, closure(h, terminal, c, name_terminal, res));
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

parser tuple_parser(heap h, parse_finish c, parse_error err)
{
    // whitespace eat
    // error close over line number
    err_internal k = closure(h, bridge_err, h, err);
    completion bc = closure(h, bridge_completion, h, c, k);    
    return (void *)closure(h, parse_value, h, bc, k);
}

parser parser_feed (parser p, buffer b)
{
    string_foreach(i, b)  p = apply(p, i);
    return p;
}

// what about the common dictionaries..a two stage serializtiaon - can
// dictionaryize in tuplespace
void serialize_tuple(buffer dest, tuple t)
{
    symbol s;
    void *v;
    // either an immediate string or a tuple
    table_foreach(t, s, v) {
    }
}

static void tuple_format_internal(u64 spaces, tuple t)
{
}

void tuple_format(buffer dest, tuple t)
{
}
