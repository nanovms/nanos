#include <runtime.h>
// synthesize the parser
typedef closure_type(selfparser, parser, parser, character);
typedef closure_type(completion, parser, void *);
typedef closure_type(err_internal, parser, buffer);

typedef table charset;

static charset name_terminal;
static charset value_terminal;
static charset whitespace;
static charset property_sigils;

// find sequence combinator
static boolean member(charset cs, character c)
{
    return table_find(cs, pointer_from_u64((u64)c))?true:false; 
}

// could be variadic, later tables overwrite earlier
static table charset_union(heap h, charset cs, charset c)
{
    table out = allocate_table(h, identity_key, pointer_equal);
    table_foreach(cs, k, v) table_set(out, k, v);
    table_foreach(c, k, v) table_set(out, k, v);
    return out;
}

static charset charset_from_string(heap h, char *elements)
{
    table t = allocate_table(h, identity_key, pointer_equal);
    // utf8 me
    for (char *i = elements; *i; i++) 
        table_set(t, pointer_from_u64((u64)*i), (void *)1);
    return t;
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

static CLOSURE_2_2(quoted_string, parser, completion, buffer, parser, character);
static parser quoted_string(completion c, buffer b, parser self, character in)
{
    // backslash
    if (in == '"') {
        apply(c, b);
        return self;
    }
    return(apply(c, b));
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

static CLOSURE_3_1(value_complete, parser, tuple, symbol, parser, void *);
static parser value_complete(tuple t, symbol name, parser check, void *v)
{
    table_set(t, name, v);
    return check;
}

static CLOSURE_3_1(dispatch_property, parser, heap, parser, err_internal, character);
static parser dispatch_property(heap h, parser pv, err_internal e, character x)
{
    switch(x) {
        //    case '|':
        //    case '/':
        //    case '.':        
    case ':':
        return pv;

    default:
        return apply(e, aprintf(h, "unknown property descriminator %c", x));
        break;
    }
    
}

static CLOSURE_3_1(parse_value, parser, heap, completion, err_internal, character);

static CLOSURE_4_1(name_complete, parser, heap, tuple, parser, err_internal, void *);
static parser name_complete(heap h, tuple t, parser check, err_internal err, void *b)
{
    buffer res = allocate_buffer(h, 20);
    completion vc = closure(h, value_complete, t, intern(b), check);
    parser term = combinate(h, closure(h, terminal, vc, value_terminal, res));
    // not sure why we have to violate typing
    parser pv = (void *)closure(h, parse_value, h, vc, err);
    return ignore_whitespace(h, (void *)closure(h, dispatch_property, h, pv, err));
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
        completion vc = closure(h, value_complete, t, intern_u64(*index), self);
        (*index)++;
        // doesnt handle whitespace before end 
        return apply(ignore_whitespace(h, (void *)closure(h, parse_value, h, vc, e)), in);
    }
    return apply(c, t);
}


static parser parse_value(heap h, completion c, err_internal err, character in)
{
    switch(in) {
    case '"':
        return combinate(h, closure(h, quoted_string, c, allocate_buffer(h, 8)));
    case '(':
        return combinate(h, closure(h, is_end_of_tuple, h, c, allocate_tuple(), err));
    case '[':
        {
            u64 *i= allocate(h, sizeof(u64));
            *i = 0;
            return combinate(h, closure(h, is_end_of_vector, h, c, allocate_tuple(), err, i));
        }
    default:
        return apply(ignore_whitespace(h, combinate(h, closure(h, terminal, c, value_terminal, allocate_buffer(h, 8)))), in);
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
    if (!whitespace) whitespace = charset_from_string(h, " \n\t");
    if (!name_terminal) name_terminal = charset_from_string(h, "()[]");
    value_terminal = charset_union(h, name_terminal, whitespace);    
    if (!property_sigils) property_sigils = charset_from_string(h, ":|/"); // dot should be here
    // variadic
    name_terminal = charset_union(h, charset_union(h, name_terminal, property_sigils), whitespace);    
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
