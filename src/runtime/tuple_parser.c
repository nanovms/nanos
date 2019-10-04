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
// XXX - can recycle closure?
closure_function(2, 1, parser, selfinate,
                 heap, h, selfparser, p,
                 character, in)
{
    parser k = (void *)closure(bound(h), selfinate, bound(h), bound(p));
    return apply(bound(p), k, in);
}

// this also has to be done on the return
static parser combinate(heap h, selfparser p)
{
    return (parser)closure(h, selfinate, h, p);
}


closure_function(1, 2, parser, til_newline,
                 parser, finish,
                 parser, self, character, in)
{
    if (in == '\n') return bound(finish);
    return self;
}

closure_function(2, 2, parser, eat_whitespace,
                 heap, h, parser, finish,
                 parser, self, character, in)
{
    if (in == '#') {
        return combinate(bound(h), closure(bound(h), til_newline, self));
    }

    if (member(whitespace, in)) return self;
    return apply(bound(finish), in);
}

static parser ignore_whitespace(heap h, parser next)
{
    selfparser s = (void *)closure(h, eat_whitespace, h, next);
    return combinate(h, s);
}

closure_function(3, 1, parser, escaped_character,
                 heap, h, buffer, b, parser, next,
                 character, in)
{
    push_character(bound(b), in);
    return bound(next);
}

closure_function(3, 2, parser, quoted_string,
                 heap, h, completion, c, buffer, b,
                 parser, self, character, in)
{
    if (in == '"') {
        return apply(bound(c), bound(b));
    } else if (in == '\\') {
        return (void *)closure(bound(h), escaped_character, bound(h), bound(b), self);
    }
    push_character(bound(b), in);
    return self;
}


closure_function(3, 2, parser, terminal,
                 completion, c, charset, final, buffer, b,
                 parser, self, character, in)
{
    if (member(bound(final), in)) {
        // apply(apply(x)) calls x twice
        parser p = apply(bound(c), bound(b));
        return apply(p, in);
    } else {
        push_character(bound(b), in);
        return self;
    }
}

closure_function(3, 1, parser, value_complete,
                 tuple, t, symbol, name, parser, check,
                 void *, v)
{
    table_set(bound(t), bound(name), v);
    return bound(check);
}

closure_function(3, 1, parser, dispatch_property,
                 heap, h, parser, pv, err_internal, e,
                 character, x)
{
    switch(x) {
        //    case '|':
        //    case '/':
        //    case '.':
    case ':':
        return bound(pv);

    default:
        return apply(bound(e), aprintf(bound(h), "unknown property discriminator %d", x));
        break;
    }

}

closure_function(4, 2, parser, is_end_of_tuple,
                 heap, h, completion, c, tuple, t, err_internal, e,
                 parser, self, character, in);

closure_function(5, 2, parser, is_end_of_vector,
                 heap, h, completion, c, tuple, t, err_internal, e, u64 *, index,
                 parser, self, character, in);

closure_function(3, 1, parser, parse_value_string,
                 heap, h, completion, c, buffer, b,
                 character, in);

closure_function(3, 1, parser, parse_value,
                 heap, h, completion, c, err_internal, err,
                 character, in)
{
    heap h = bound(h);
    completion c = bound(c);
    err_internal err = bound(err);

    switch(in) {
    case '(':
        return ignore_whitespace(h, combinate(h, closure(h, is_end_of_tuple, h, c, allocate_tuple(), err)));
    case '[':
        {
            u64 *i= allocate(h, sizeof(u64));
            *i = 0;
            return ignore_whitespace(h, combinate(h, closure(h, is_end_of_vector, h, c, allocate_tuple(), err, i)));
        }
    default:
        {
            parser p = ignore_whitespace(h, (void *)closure(h, parse_value_string, h, c, allocate_buffer(h, 8)));
            return apply(p, in);
        }
    }
}

closure_function(4, 1, parser, name_complete,
                 heap, h, tuple, t, parser, check, err_internal, err,
                 void *, b)
{
    heap h = bound(h);
    completion vc = closure(h, value_complete, bound(t), intern(b), bound(check));
    // not sure why we have to violate typing
    parser pv = (void *)closure(h, parse_value, h, vc, bound(err));
    return ignore_whitespace(h, (void *)closure(h, dispatch_property, h, pv, bound(err)));
}

closure_function(3, 1, parser, parse_name,
                 heap, h, completion, c, buffer, b,
                 character, in)
{
    heap h = bound(h);
    if (in == '"') {
        return combinate(h, closure(h, quoted_string, h, bound(c), bound(b)));
    }

    parser p = combinate(h, closure(h, terminal, bound(c), name_terminal, bound(b)));
    return apply(p, in);
}

static parser is_end_of_tuple(struct _closure_is_end_of_tuple *__self, parser self, character in)
{
    heap h = bound(h);
    if (in == ')') {
        return apply(bound(c), bound(t));
    }

    parser *p = allocate(h, sizeof(parser));
    parser cew = ignore_whitespace(h, self);
    completion nc = closure(h, name_complete, h, bound(t), cew, bound(e));
    *p = ignore_whitespace(h, (void *)closure(h, parse_name, h, nc, allocate_buffer(h, 100)));
    return apply(*p, in);
}

static parser is_end_of_vector(struct _closure_is_end_of_vector *__self, parser self, character in)
{
    heap h = bound(h);
    // keep index also
    if (in != ']') {
        completion vc = closure(h, value_complete, bound(t), intern_u64(*bound(index)), self);
        (*bound(index))++;
        // doesnt handle whitespace before end
        return apply(ignore_whitespace(h, (void *)closure(h, parse_value, h, vc, bound(e))), in);
    }
    return apply(bound(c), bound(t));
}

static parser parse_value_string(struct _closure_parse_value_string *__self, character in)
{
    heap h = bound(h);

    if (in == '"')
        return combinate(h, closure(h, quoted_string, h, bound(c), bound(b)));

    parser p = combinate(h, closure(h, terminal, bound(c), value_terminal, bound(b)));
    return apply(p, in);
}


closure_function(0, 2, parser, kill,
                 parser, self, character, ig)
{
    return self;
}


closure_function(2, 1, parser, bridge_err,
                 heap, h, parse_error, error,
                 buffer, b)
{
    apply(bound(error), b);
    return combinate(bound(h), closure(bound(h), kill));
}

closure_function(3, 1, parser, bridge_completion,
                 heap, h, parse_finish, c, err_internal, err,
                 void *, v)
{
    heap h = bound(h);
    apply(bound(c), v);
    // another self case
    completion bc = closure(h, bridge_completion, h, bound(c), bound(err));
    return (void *)closure(h, parse_value, h, bc, bound(err));
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
