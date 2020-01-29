#include <runtime.h>
// synthesize the parser
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

closure_function(1, 1, parser, til_newline,
                 parser, finish,
                 character, in)
{
    if (in == '\n') {
        parser f = bound(finish);
        closure_finish();
        return f;
    }
    return (parser)closure_self();
}

// leaky; no finite lifespan
closure_function(2, 1, parser, eat_whitespace,
                 heap, h, parser, finish,
                 character, in)
{
    if (in == '#')
        return (parser)closure(bound(h), til_newline, (parser)closure_self());

    if (member(whitespace, in))
        return (parser)closure_self();

    return apply(bound(finish), in);
}

static parser ignore_whitespace(heap h, parser next)
{
    return (parser)closure(h, eat_whitespace, h, next);
}

closure_function(3, 1, parser, escaped_character,
                 heap, h, buffer, b, parser, next,
                 character, in)
{
    parser n = bound(next);
    push_character(bound(b), in);
    closure_finish();
    return n;
}

closure_function(3, 1, parser, quoted_string,
                 heap, h, completion, c, buffer, b,
                 character, in)
{
    if (in == '"') {
        completion c = bound(c);
        buffer b = bound(b);
        closure_finish();
        return apply(c, b);
    } else if (in == '\\') {
        return (parser)closure(bound(h), escaped_character, bound(h), bound(b), (parser)closure_self());
    }
    push_character(bound(b), in);
    return (parser)closure_self();
}


closure_function(3, 1, parser, terminal,
                 completion, c, charset, final, buffer, b,
                 character, in)
{
    if (member(bound(final), in)) {
        // apply(apply(x)) calls x twice
        parser p = apply(bound(c), bound(b));
        closure_finish();
        return apply(p, in);
    } else {
        push_character(bound(b), in);
        return (parser)closure_self();
    }
}

closure_function(3, 1, parser, value_complete,
                 tuple, t, symbol, name, parser, check,
                 void *, v)
{
    table_set(bound(t), bound(name), v);
    parser c = bound(check);
    closure_finish();
    return c;
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

closure_function(4, 1, parser, is_end_of_tuple,
                 heap, h, completion, c, tuple, t, err_internal, e,
                 character, in);

closure_function(5, 1, parser, is_end_of_vector,
                 heap, h, completion, c, tuple, t, err_internal, e, u64 *, index,
                 character, in);

closure_function(3, 1, parser, parse_value_string,
                 heap, h, completion, c, buffer, b,
                 character, in);

// leaky; no finite lifespan
closure_function(3, 1, parser, parse_value,
                 heap, h, completion, c, err_internal, err,
                 character, in)
{
    heap h = bound(h);
    completion c = bound(c);
    err_internal err = bound(err);
    parser p, q;
    u64 *i;

    switch(in) {
    case '(':
        p = ignore_whitespace(h, (parser)closure(h, is_end_of_tuple, h, c, allocate_tuple(), err));
        break;
    case '[':
        i= allocate(h, sizeof(u64));
        *i = 0;
        p = ignore_whitespace(h, (parser)closure(h, is_end_of_vector, h, c, allocate_tuple(), err, i));
        break;
    default:
        q = ignore_whitespace(h, (parser)closure(h, parse_value_string, h, c, allocate_buffer(h, 8)));
        p = apply(q, in);
    }
    return p;
}

// leaky; no finite lifespan
closure_function(3, 1, parser, parse_tuple,
                 heap, h, completion, c, err_internal, err,
                 character, in)
{
    heap h = bound(h);
    completion c = bound(c);
    err_internal err = bound(err);
    parser p;

    if (in != '(')
        p = apply(bound(err), aprintf(bound(h), "parse_tuple fail, leading char '%c'", in));
    else
        p = ignore_whitespace(h, (parser)closure(h, is_end_of_tuple, h, c, allocate_tuple(), err));
    return p;
}

closure_function(4, 1, parser, name_complete,
                 heap, h, tuple, t, parser, check, err_internal, err,
                 void *, b)
{
    heap h = bound(h);
    completion vc = closure(h, value_complete, bound(t), intern(b), bound(check));
    // not sure why we have to violate typing
    parser pv = (parser)closure(h, parse_value, h, vc, bound(err));
    parser p = ignore_whitespace(h, (parser)closure(h, dispatch_property, h, pv, bound(err)));
    closure_finish();
    return p;
}

closure_function(3, 1, parser, parse_name,
                 heap, h, completion, c, buffer, b,
                 character, in)
{
    heap h = bound(h);
    parser p;
    if (in == '"') {
        p = (parser)closure(h, quoted_string, h, bound(c), bound(b));
    } else {
        parser q = (parser)closure(h, terminal, bound(c), name_terminal, bound(b));
        p = apply(q, in);
    }
    closure_finish();
    return p;
}

static parser is_end_of_tuple(struct _closure_is_end_of_tuple *__self, character in)
{
    heap h = bound(h);
    if (in == ')') {
        parser p = apply(bound(c), bound(t));
        closure_finish();
        return p;
    }

    parser *p = allocate(h, sizeof(parser));
    parser cew = ignore_whitespace(h, (parser)closure_self());
    completion nc = closure(h, name_complete, h, bound(t), cew, bound(e));
    *p = ignore_whitespace(h, (parser)closure(h, parse_name, h, nc, allocate_buffer(h, 100)));
    return apply(*p, in);
}

static parser is_end_of_vector(struct _closure_is_end_of_vector *__self, character in)
{
    heap h = bound(h);
    // keep index also
    if (in != ']') {
        completion vc = closure(h, value_complete, bound(t), intern_u64(*bound(index)), (parser)closure_self());
        (*bound(index))++;
        // doesnt handle whitespace before end
        return apply(ignore_whitespace(h, (parser)closure(h, parse_value, h, vc, bound(e))), in);
    }
    parser p = apply(bound(c), bound(t));
    closure_finish();
    return p;
}

static parser parse_value_string(struct _closure_parse_value_string *__self, character in)
{
    heap h = bound(h);
    if (in == '"')
        return (parser)closure(h, quoted_string, h, bound(c), bound(b));

    return (parser)apply(closure(h, terminal, bound(c), value_terminal, bound(b)), in);
}

// leaks; no end condition to free on
closure_function(0, 1, parser, kill,
                 character, ig)
{
    return (parser)closure_self();
}

closure_function(2, 1, parser, bridge_err,
                 heap, h, parse_error, error,
                 buffer, b)
{
    apply(bound(error), b);
    return (parser)closure(bound(h), kill);
}

closure_function(3, 1, parser, bridge_completion,
                 parse_finish, c, err_internal, err, parser *, start,
                 void *, v)
{
    apply(bound(c), v);
    return *bound(start);
}

static void init_parser(heap h)
{
    if (whitespace)
        return;
    whitespace = charset_from_string(h, " \n\t");
    name_terminal = charset_from_string(h, "()[]");
    value_terminal = charset_union(h, name_terminal, whitespace);
    property_sigils = charset_from_string(h, ":|/"); // dot should be here
    // variadic
    name_terminal = charset_union(h, charset_union(h, name_terminal, property_sigils), whitespace);
}

parser tuple_parser(heap h, parse_finish c, parse_error err)
{
    init_parser(h);
    parser *p = allocate(h, sizeof(parser));
    err_internal k = closure(h, bridge_err, h, err);
    completion bc = closure(h, bridge_completion, c, k, p);
    return (*p = ignore_whitespace(h, (parser)closure(h, parse_tuple, h, bc, k)));
}

parser value_parser(heap h, parse_finish c, parse_error err)
{
    init_parser(h);
    parser *p = allocate(h, sizeof(parser));
    err_internal k = closure(h, bridge_err, h, err);
    completion bc = closure(h, bridge_completion, c, k, p);
    return (*p = ignore_whitespace(h, (parser)closure(h, parse_value, h, bc, k)));
}

parser parser_feed(parser p, buffer b)
{
    string_foreach(i, b) {
        p = apply(p, i);
    }
    return p;
}
