#include <runtime.h>

closure_type(parse_finish_internal, parser, void *v);
closure_type(parse_error_internal, parser, string err);

struct parser_common {
    heap h;
    parse_finish_internal c;
    parse_error_internal e;
};

typedef struct json_string_p {
    struct parser_common p;
    closure_struct(parser, parse);
    string s;
    boolean escape;
} *json_string_p;

typedef struct json_number_p {
    struct parser_common p;
    closure_struct(parser, parse);
    boolean digit_found;
    boolean fractional;
} *json_number_p;

typedef struct json_boolean_p {
    struct parser_common p;
    closure_struct(parser, parse);
    boolean value;
    int char_count;
} *json_boolean_p;

typedef struct json_null_p {
    struct parser_common p;
    closure_struct(parser, parse);
    int char_count;
} *json_null_p;

typedef struct json_value_p {
    struct parser_common p;
    closure_struct(parser, parse);
    closure_struct(parse_finish_internal, c);
    closure_struct(parse_error_internal, e);
} *json_value_p;

typedef struct json_attr_p {
    struct parser_common p;
    closure_struct(parser, parse);
    closure_struct(parse_finish_internal, name_c);
    closure_struct(parse_finish_internal, value_c);
    closure_struct(parse_error_internal, e);
    tuple parent_obj;
    string name;
    enum {
        JSON_ATTR_STATE_NAME,
        JSON_ATTR_STATE_VALUE,
    } state;
} *json_attr_p;

typedef struct json_obj_p {
    struct parser_common p;
    closure_struct(parser, parse);
    closure_struct(parse_finish_internal, c);
    closure_struct(parse_error_internal, e);
    tuple obj;
    enum {
        JSON_OBJ_STATE_ATTR_BEGIN,
        JSON_OBJ_STATE_ATTR_END,
    } state;
} *json_obj_p;

typedef struct json_array_p {
    struct parser_common p;
    closure_struct(parser, parse);
    closure_struct(parse_finish_internal, c);
    closure_struct(parse_error_internal, e);
    enum {
        JSON_ARRAY_STATE_ELEM_BEGIN,
        JSON_ARRAY_STATE_ELEM_END,
    } state;
} *json_array_p;

typedef struct json_p {
    heap h;
    parse_finish finish;
    parse_error err;
    closure_struct(parser, parse);
    closure_struct(parse_finish_internal, c);
    closure_struct(parse_error_internal, e);
} *json_p;

static parser json_obj_parser(heap h, parse_finish_internal c, parse_error_internal e);
static parser json_array_parser(heap h, parse_finish_internal c, parse_error_internal e);

static boolean char_is_whitespace(character in)
{
    return (runtime_strchr(ss(" \n\r\t"), in) != 0);
}

static boolean char_is_numeric(character in)
{
    return (runtime_strchr(ss("1234567890."), in) != 0);
}

static parser parse_literal(parser p, character in, int char_index, const char *literal,
                            int literal_len, parse_finish_internal c, parse_error_internal e)
{
    if (in != literal[char_index]) {
        string err_string = little_stack_buffer(32);
        bprintf(err_string, "unexpected character %c", in);
        return apply(e, err_string);
    }
    if (char_index == literal_len - 1) {
        /* Literal value is discarded. */
        return apply(c, 0);
    }
    return p;
}

closure_func_basic(parser, void *, json_string_parse,
                   character in)
{
    json_string_p p = struct_from_field(closure_self(), json_string_p, parse);
    string s = p->s;
    if (in == CHARACTER_INVALID) {
        parser next = apply(p->p.e, alloca_wrap_cstring("unexpected end of input"));
        deallocate_buffer(s);
        deallocate(p->p.h, p, sizeof(*p));
        return next;
    }
    if (!p->escape) {
        if (in == '\"') {
            parser next = apply(p->p.c, s);
            deallocate(p->p.h, p, sizeof(*p));
            return next;
        }
        if (in == '\\')
            p->escape = true;
        else
            push_character(s, in);
    } else {
        switch (in) {
        case 'n':
            in = '\n';
            break;
        case 't':
            in = '\t';
            break;
        case 'r':
            in = '\r';
            break;
        case 'b':
            in = '\b';
            break;
        case 'f':
            in = '\f';
            break;
        }
        push_character(s, in);
        p->escape = false;
    }
    return (parser)closure_self();
}

static parser json_string_parser(heap h, parse_finish_internal c, parse_error_internal e)
{
    json_string_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->s = allocate_string(8);
    if (p->s == INVALID_ADDRESS) {
        deallocate(h, p, sizeof(*p));
        return INVALID_ADDRESS;
    }
    p->escape = false;
    p->p.h = h;
    p->p.c = c;
    p->p.e = e;
    return init_closure_func(&p->parse, parser, json_string_parse);
}

/* Actual parsing of JSON numbers is not implemented. */
closure_func_basic(parser, void *, json_number_parse,
                   character in)
{
    json_number_p p = struct_from_field(closure_self(), json_number_p, parse);
    string err_string;
    parser next;
    if (!char_is_numeric(in)) {
        if (!p->digit_found) {
            err_string = alloca_wrap_cstring("no digits found");
            goto error;
        }
        parser next = apply(p->p.c, 0);
        deallocate(p->p.h, p, sizeof(*p));
        return apply(next, in);
    }
    if (in == '.') {
        if (!p->fractional) {
            p->fractional = true;
            p->digit_found = false;
        } else {
            err_string = alloca_wrap_cstring("unexpected decimal point");
            goto error;
        }
    } else {
        p->digit_found = true;
    }
    return (parser)closure_self();
  error:
    next = apply(p->p.e, err_string);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

static parser json_number_parser(heap h, character first, parse_finish_internal c,
                                 parse_error_internal e)
{
    json_number_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->digit_found = p->fractional = false;
    p->p.h = h;
    p->p.c = c;
    p->p.e = e;
    parser number_p = init_closure_func(&p->parse, parser, json_number_parse);
    return (first != '-') ? apply(number_p, first) : number_p;
}

closure_func_basic(parser, void *, json_boolean_parse,
                   character in)
{
    json_boolean_p p = struct_from_field(closure_self(), json_boolean_p, parse);
    const char *literal = (p->value ? "true" : "false");
    int len = (p->value ? 4 : 5);
    parser self = (parser)closure_self();
    parser next = parse_literal(self, in, p->char_count, literal, len, p->p.c, p->p.e);
    if (next == self)
        p->char_count++;
    else
        deallocate(p->p.h, p, sizeof(*p));
    return next;
}

static parser json_boolean_parser(heap h, boolean value, parse_finish_internal c,
                                  parse_error_internal e)
{
    json_boolean_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->value = value;
    p->char_count = 1;
    p->p.h = h;
    p->p.c = c;
    p->p.e = e;
    return init_closure_func(&p->parse, parser, json_boolean_parse);
}

closure_func_basic(parser, void *, json_null_parse,
                   character in)
{
    json_null_p p = struct_from_field(closure_self(), json_null_p, parse);
    parser self = (parser)closure_self();
    parser next = parse_literal(self, in, p->char_count, "null", 4, p->p.c, p->p.e);
    if (next == self)
        p->char_count++;
    else
        deallocate(p->p.h, p, sizeof(*p));
    return next;
}

static parser json_null_parser(heap h, parse_finish_internal c, parse_error_internal e)
{
    json_null_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->char_count = 1;
    p->p.h = h;
    p->p.c = c;
    p->p.e = e;
    return init_closure_func(&p->parse, parser, json_null_parse);
}

closure_func_basic(parser, void *, json_value_parse,
                   character in)
{
    if (char_is_whitespace(in))
        return (parser)closure_self();
    json_value_p p = struct_from_field(closure_self(), json_value_p, parse);
    parse_error_internal e = (parse_error_internal)&p->e;
    string err_string;
    if (in == CHARACTER_INVALID) {
        err_string = alloca_wrap_cstring("unexpected end of input");
        goto error;
    }
    heap h = p->p.h;
    parser value_parser;
    parse_finish_internal c = (parse_finish_internal)&p->c;
    if (char_is_numeric(in))
        value_parser = json_number_parser(h, in, c, e);
    else
        switch (in) {
        case '"':
            value_parser = json_string_parser(h, c, e);
            break;
        case '{':
            value_parser = json_obj_parser(h, c, e);
            break;
        case '[':
            value_parser = json_array_parser(h, c, e);
            break;
        case '-':
            value_parser = json_number_parser(h, in, c, e);
            break;
        case 't':
        case 'f':
            value_parser = json_boolean_parser(h, in == 't', c, e);
            break;
        case 'n':
            value_parser = json_null_parser(h, c, e);
            break;
        default:
            err_string = little_stack_buffer(32);
            bprintf(err_string, "unexpected character %c", in);
            goto error;
        }
    if (value_parser != INVALID_ADDRESS)
        return value_parser;
    err_string = alloca_wrap_cstring("failed to allocate value parser");
  error:
    return apply(e, err_string);
}

closure_func_basic(parse_finish_internal, parser, json_value_complete,
                   void *result)
{
    json_value_p p = struct_from_field(closure_self(), json_value_p, c);
    parser next = apply(p->p.c, result);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

closure_func_basic(parse_error_internal, parser, json_value_error,
                   string err)
{
    json_value_p p = struct_from_field(closure_self(), json_value_p, e);
    parser next = apply(p->p.e, err);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

static parser json_value_parser(heap h, parse_finish_internal c, parse_error_internal e)
{
    json_value_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->p.h = h;
    p->p.c = c;
    p->p.e = e;
    init_closure_func(&p->c, parse_finish_internal, json_value_complete);
    init_closure_func(&p->e, parse_error_internal, json_value_error);
    return init_closure_func(&p->parse, parser, json_value_parse);
}

closure_func_basic(parser, void *, json_attr_parse,
                   character in)
{
    json_attr_p p = struct_from_field(closure_self(), json_attr_p, parse);
    parse_error_internal e = (parse_error_internal)&p->e;
    string err_string = 0;
    if (in == CHARACTER_INVALID) {
        err_string = alloca_wrap_cstring("unexpected end of input");
        goto error;
    }
    heap h = p->p.h;
    switch (p->state) {
    case JSON_ATTR_STATE_NAME: {
        parser name_p = json_string_parser(h, (parse_finish_internal)&p->name_c, e);
        if (name_p != INVALID_ADDRESS)
            return apply(name_p, in);
        err_string = alloca_wrap_cstring("failed to allocate attribute name parser");
        break;
    }
    case JSON_ATTR_STATE_VALUE: {
        if (char_is_whitespace(in))
            return (parser)closure_self();
        if (in != ':') {
            err_string = little_stack_buffer(32);
            bprintf(err_string, "unexpected character %c", in);
            break;
        }
        parser value_p = json_value_parser(h, (parse_finish_internal)&p->value_c, e);
        if (value_p != INVALID_ADDRESS)
            return value_p;
        err_string = alloca_wrap_cstring("failed to allocate attribute value parser");
        break;
    }
    }
  error:
    return apply(e, err_string);
}

closure_func_basic(parse_finish_internal, parser, json_attr_name_complete,
                   void *result)
{
    json_attr_p p = struct_from_field(closure_self(), json_attr_p, name_c);
    p->name = result;
    if (buffer_length(p->name) == 0) {
        parse_error_internal e = (parse_error_internal)&p->e;
        return apply(e, alloca_wrap_cstring("empty attribute name"));
    }
    p->state = JSON_ATTR_STATE_VALUE;
    return (parser)&p->parse;
}

closure_func_basic(parse_finish_internal, parser, json_attr_value_complete,
                   void *result)
{
    json_attr_p p = struct_from_field(closure_self(), json_attr_p, value_c);
    if (result)
        set(p->parent_obj, intern(p->name), result);
    deallocate_buffer(p->name);
    parser next = apply(p->p.c, p->parent_obj);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

closure_func_basic(parse_error_internal, parser, json_attr_error,
                   string err)
{
    json_attr_p p = struct_from_field(closure_self(), json_attr_p, e);
    parser next = apply(p->p.e, err);
    if (p->name)
        deallocate_buffer(p->name);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

static parser json_attr_parser(heap h, tuple parent_obj, parse_finish_internal c,
                               parse_error_internal e)
{
    json_attr_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->p.h = h;
    p->p.c = c;
    p->p.e = e;
    p->parent_obj = parent_obj;
    p->name = 0;
    p->state = JSON_ATTR_STATE_NAME;
    init_closure_func(&p->name_c, parse_finish_internal, json_attr_name_complete);
    init_closure_func(&p->value_c, parse_finish_internal, json_attr_value_complete);
    init_closure_func(&p->e, parse_error_internal, json_attr_error);
    return init_closure_func(&p->parse, parser, json_attr_parse);
}

closure_func_basic(parser, void *, json_obj_parse,
                   character in)
{
    if (char_is_whitespace(in))
        return (parser)closure_self();
    json_obj_p p = struct_from_field(closure_self(), json_obj_p, parse);
    string err_string;
    parser next;
    if (in == CHARACTER_INVALID) {
        err_string = alloca_wrap_cstring("unexpected end of input");
        goto error;
    }
    switch (p->state) {
    case JSON_OBJ_STATE_ATTR_BEGIN:
        switch (in) {
        case '"': {
            parser attr_p = json_attr_parser(p->p.h, p->obj, (parse_finish_internal)&p->c,
                                             (parse_error_internal)&p->e);
            if (attr_p != INVALID_ADDRESS)
                return attr_p;
            err_string = alloca_wrap_cstring("failed to allocate attribute parser");
            break;
        }
        case '}':
            goto finish;
        default:
            goto unexpected_in;
        }
    case JSON_OBJ_STATE_ATTR_END:
        switch (in) {
        case ',':
            p->state = JSON_OBJ_STATE_ATTR_BEGIN;
            break;
        case '}':
            goto finish;
        default:
            goto unexpected_in;
        }
        break;
    }
    return (parser)closure_self();
  unexpected_in:
    err_string = little_stack_buffer(32);
    bprintf(err_string, "unexpected character %c", in);
  error:
    destruct_value(p->obj, true);
    next = apply(p->p.e, err_string);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
  finish:
    next = apply(p->p.c, p->obj);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

closure_func_basic(parse_finish_internal, parser, json_obj_attr_complete,
                   void *result)
{
    json_obj_p p = struct_from_field(closure_self(), json_obj_p, c);
    p->state = JSON_OBJ_STATE_ATTR_END;
    return (parser)&p->parse;
}

closure_func_basic(parse_error_internal, parser, json_obj_attr_error,
                   string err)
{
    json_obj_p p = struct_from_field(closure_self(), json_obj_p, e);
    destruct_value(p->obj, true);
    parser next = apply(p->p.e, err);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

static parser json_obj_parser(heap h, parse_finish_internal c, parse_error_internal e)
{
    json_obj_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->obj = allocate_tuple();
    p->p.h = h;
    p->p.c = c;
    p->p.e = e;
    p->state = JSON_OBJ_STATE_ATTR_BEGIN;
    init_closure_func(&p->c, parse_finish_internal, json_obj_attr_complete);
    init_closure_func(&p->e, parse_error_internal, json_obj_attr_error);
    return init_closure_func(&p->parse, parser, json_obj_parse);
}

closure_func_basic(parser, void *, json_array_parse,
                   character in)
{
    json_array_p p = struct_from_field(closure_self(), json_array_p, parse);
    string err_string;
    parser next;
    if (in == CHARACTER_INVALID) {
        err_string = alloca_wrap_cstring("unexpected end of input");
        goto error;
    }
    if (in == ']') {
        /* Array contents are discarded. */
        next = apply(p->p.c, 0);
        deallocate(p->p.h, p, sizeof(*p));
        return next;
    }
    switch (p->state) {
    case JSON_ARRAY_STATE_ELEM_BEGIN:
        next = json_value_parser(p->p.h, (parse_finish_internal)&p->c, (parse_error_internal)&p->e);
        if (next != INVALID_ADDRESS)
            return apply(next, in);
        err_string = alloca_wrap_cstring("failed to allocate array element parser");
        goto error;
    case JSON_ARRAY_STATE_ELEM_END:
        if (in == ',') {
            p->state = JSON_OBJ_STATE_ATTR_BEGIN;
            break;
        }
        err_string = little_stack_buffer(32);
        bprintf(err_string, "unexpected character %c", in);
        goto error;
    }
    return (parser)closure_self();
  error:
    next = apply(p->p.e, err_string);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

closure_func_basic(parse_finish_internal, parser, json_array_elem_complete,
                   void *result)
{
    json_array_p p = struct_from_field(closure_self(), json_array_p, c);
    if (result)
        deallocate_value(result);
    p->state = JSON_ARRAY_STATE_ELEM_END;
    return (parser)&p->parse;
}

closure_func_basic(parse_error_internal, parser, json_array_elem_error,
                   string err)
{
    json_array_p p = struct_from_field(closure_self(), json_array_p, e);
    parser next = apply(p->p.e, err);
    deallocate(p->p.h, p, sizeof(*p));
    return next;
}

static parser json_array_parser(heap h, parse_finish_internal c, parse_error_internal e)
{
    json_array_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->p.h = h;
    p->p.c = c;
    p->p.e = e;
    p->state = JSON_ARRAY_STATE_ELEM_BEGIN;
    init_closure_func(&p->c, parse_finish_internal, json_array_elem_complete);
    init_closure_func(&p->e, parse_error_internal, json_array_elem_error);
    return init_closure_func(&p->parse, parser, json_array_parse);
}

closure_func_basic(parser, void *, json_parse,
                   character in)
{
    if (char_is_whitespace(in) || (in == CHARACTER_INVALID))
        return (parser)closure_self();
    json_p p = struct_from_field(closure_self(), json_p, parse);
    string err_string;
    if (in == '{') {
        parser obj_parser = json_obj_parser(p->h, (parse_finish_internal)&p->c,
                                            (parse_error_internal)&p->e);
        if (obj_parser != INVALID_ADDRESS)
            return obj_parser;
        err_string = alloca_wrap_cstring("failed to allocate object parser");
    } else {
        err_string = little_stack_buffer(32);
        bprintf(err_string, "unexpected character %c", in);
    }
    apply(p->err, err_string);
    return (parser)closure_self();
}

closure_func_basic(parse_finish_internal, parser, json_complete,
                   void *result)
{
    json_p p = struct_from_field(closure_self(), json_p, c);
    apply(p->finish, result);
    return (parser)&p->parse;
}

closure_func_basic(parse_error_internal, parser, json_error,
                   string err)
{
    json_p p = struct_from_field(closure_self(), json_p, e);
    apply(p->err, err);
    return (parser)&p->parse;
}

parser json_parser(heap h, parse_finish c, parse_error err)
{
    json_p p = allocate(h, sizeof(*p));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->h = h;
    p->finish = c;
    p->err = err;
    init_closure_func(&p->c, parse_finish_internal, json_complete);
    init_closure_func(&p->e, parse_error_internal, json_error);
    return init_closure_func(&p->parse, parser, json_parse);
}

void json_parser_free(parser p)
{
    json_p jp = struct_from_field(p, json_p, parse);
    deallocate(jp->h, jp, sizeof(*jp));
}
