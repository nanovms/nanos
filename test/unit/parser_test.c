#include <runtime.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define COUNT_ELM   10

#define test_assert(expr) do { \
if (expr) ; else { \
    msg_err("%s -- failed at %s:%d\n", ss(#expr), file_ss, __LINE__); \
    return false; \
} \
} while (0)

/* s must be a string literal */
#define test_strings_equal(b, s) do {        \
if (buffer_strcmp(b, s) != 0) {                         \
    msg_err("\"%b\" != \"%s\" -- failed at %s:%d\n", b, ss(s), file_ss, __LINE__); \
    return false; \
} \
} while (0)

#define test_no_errors() do { \
    if (errors_count) { \
        msg_err("%d parse error(s), last: %b\n", errors_count, last_error); \
    } \
    test_assert(errors_count == 0); \
} while (0)

#define test_assert_json_incomplete() do {                                  \
    test_assert(errors_count == 1);                                         \
    test_strings_equal(last_error, "unexpected end of input");    \
} while (0)

value root;
closure_function(1, 1, void, finish,
                 heap, h,
                 void *, v)
{
    root = v;
}

int errors_count = 0;
string last_error;

parser tuple_p;
parser json_p;

closure_function(1, 1, void, perr,
                 heap, h,
                 string, s)
{
    errors_count++;
    if (last_error)
        deallocate_buffer(last_error);
    last_error = clone_buffer(bound(h), s);
}

void parse_string(heap h, parser p, sstring str)
{
    root = NULL;
    errors_count = 0;
    if (last_error) {
        deallocate_buffer(last_error);
        last_error = NULL;
    }

    buffer b = alloca_wrap_sstring(str);
    p = parser_feed(p, b);
    apply(p, CHARACTER_INVALID);    /* signal end of input */
}

#define PARSE_TEST(name, p, str) \
    boolean _check_##name(heap h); \
\
    boolean name(heap h) \
    { \
        parse_string(h, p, ss(str)); \
\
        return !_check_##name(h); \
    } \
\
    boolean _check_##name(heap h)

#define TUPLE_PARSE_TEST(name, str) PARSE_TEST(name, tuple_p, str)
#define JSON_PARSE_TEST(name, str) PARSE_TEST(name, json_p, str)

TUPLE_PARSE_TEST(empty_string_test, "")
{
    test_no_errors();
    test_assert(root == NULL);
    return true;
}


TUPLE_PARSE_TEST(empty_tuple_test, "()")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 0);
    test_no_errors();
    return true;
}

TUPLE_PARSE_TEST(empty_tuple_with_whitespaces_test, " ( ) ")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 0);
    return true;
}

TUPLE_PARSE_TEST(empty_vector_test, "[]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 0);
    return true;
}

TUPLE_PARSE_TEST(empty_vector_with_whitespaces_test, " [ ] ")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 0);
    return true;
}

TUPLE_PARSE_TEST(all_is_comment_test, "#[]")
{
    test_no_errors();
    test_assert(root == NULL);
    return true;
}

TUPLE_PARSE_TEST(partial_comment_test, "#[]\n()")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 0);
    return true;
}

TUPLE_PARSE_TEST(tuple_simple_test, "(key:value)")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(tuple_simple_spaced_test, " ( key : value ) ")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(vector_simple_test, "[val1]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 1);

    buffer v1 = get_string(root, integer_key(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "val1");

    return true;
}

TUPLE_PARSE_TEST(tuple_2elements_test, "(key1:value1 key2:value2)")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 2);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("key1")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value1");
    deallocate_buffer(v1);

    buffer v2 = get_string(root, intern(alloca_wrap_cstring("key2")));
    test_assert(v2 != NULL);
    test_strings_equal(v2, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(vector_2elements_test, "[val1 val2]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 2);

    buffer v1 = get_string(root, integer_key(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "val1");

    buffer v2 = get_string(root, integer_key(1));
    test_assert(v2 != NULL);
    test_strings_equal(v2, "val2");

    return true;
}

TUPLE_PARSE_TEST(whitespace_after_last_vector_value_test, "[val ]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 2);

    buffer v1 = get_string(root, integer_key(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "val");

    buffer v2 = get_string(root, integer_key(1));
    test_assert(v2 != NULL);
    test_strings_equal(v2, "");

    return true;
}

TUPLE_PARSE_TEST(tuple_nested_tuple_test, "(key:(key2:value2))")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    tuple v1 = get_tuple(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_assert(tuple_count(v1) == 1);

    buffer v2 = get_string(v1, intern(alloca_wrap_cstring("key2")));
    test_assert(v2 != NULL);
    test_strings_equal(v2, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(vector_nested_tuple_test, "[(key2:value2)]")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 1);

    tuple v1 = get_tuple(root, integer_key(0));
    test_assert(v1 != NULL);
    test_assert(tuple_count(v1) == 1);

    buffer v2 = get_string(v1, intern(alloca_wrap_cstring("key2")));
    test_assert(v2 != NULL);
    test_strings_equal(v2, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(tuple_nested_vector_test, "(key:[value2])")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    value v1 = get(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_assert(is_vector(v1));
    test_assert(vector_length(v1) == 1);

    buffer v2 = get_string(v1, integer_key(0));
    test_assert(v2 != NULL);
    test_strings_equal(v2, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(vector_nested_vector_test, "[[value2]]")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 1);

    value v1 = get(root, integer_key(0));
    test_assert(v1 != NULL);
    test_assert(is_vector(v1));
    test_assert(vector_length(v1) == 1);

    buffer v2 = get_string(v1, integer_key(0));
    test_assert(v2 != NULL);
    test_strings_equal(v2, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(quoted_tuple_value_test, "(key:\"value\")")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_tuple_name_test, "(\"key\":value)")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_tuple_name_value_test, "(\"key\":\"value\")")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(spaced_quoted_tuple_name_value_test, "( \"key\" : \"value\" )")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_spaced_tuple_value_test, "(key:\"hello value\")")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "hello value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_spaced_tuple_name_test, "(\"hello key\":value)")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("hello key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_spaced_tuple_name_value_test, "(\"hello key\":\"hello value\")")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(alloca_wrap_cstring("hello key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "hello value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_vector_value_test, "[\"value\"]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 1);

    buffer v1 = get_string(root, integer_key(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "value");

    return true;
}

TUPLE_PARSE_TEST(quoted_spaced_vector_value_test, "[\"hello value\"]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 1);

    buffer v1 = get_string(root, integer_key(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "hello value");

    return true;
}

TUPLE_PARSE_TEST(quoted_escaped_quote_vector_value_test, "[\"hello \\\"value\\\"\"]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(is_vector(root));
    test_assert(vector_length(root) == 1);

    buffer v1 = get_string(root, integer_key(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1, "hello \"value\"");

    return true;
}

TUPLE_PARSE_TEST(unknown_terminal_test, "(key:value()")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error, "unknown property discriminator 40");

    return true;
}

TUPLE_PARSE_TEST(single_closing_tuple_bracket_test, ")")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error, "unknown property discriminator 40");

    return true;
}

TUPLE_PARSE_TEST(single_closing_vector_bracket_test, "]")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error, "unknown property discriminator 40");

    return true;
}

JSON_PARSE_TEST(json_whitespace_test, " {\n\"\ra\t\" :\n\"\rb\t\" ,\n\"c\":{\r\"d\":\"e\"\t} }\n")
{
    test_no_errors();
    test_assert((root != NULL) && (tuple_count(root) == 2));

    string s = get_string(root, sym_this("\ra\t"));
    test_assert(s != NULL);
    test_strings_equal(s, "\rb\t");

    tuple t = get_tuple(root, sym_this("c"));
    test_assert((t != NULL) && (tuple_count(t) == 1));
    s = get_string(t, sym_this("d"));
    test_assert(s != NULL);
    test_strings_equal(s, "e");

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_invalid_objstart_test, "a")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error, "unexpected character a");
    return true;
}

JSON_PARSE_TEST(json_incomplete_obj_test, "{")
{
    test_assert_json_incomplete();
    return true;
}

JSON_PARSE_TEST(json_incomplete_name_test, "{\"")
{
    test_assert_json_incomplete();
    return true;
}

JSON_PARSE_TEST(json_incomplete_name_test1, "{\"a")
{
    test_assert_json_incomplete();
    return true;
}

JSON_PARSE_TEST(json_missing_value_test, "{\"a\":")
{
    test_assert_json_incomplete();
    return true;
}

JSON_PARSE_TEST(json_invalid_separator_test, "{\"a\";{}}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_invalid_separator_test1, "{\"a\":{};\"b\":{}}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_incomplete_stringvalue_test, "{\"a\":\"")
{
    test_assert_json_incomplete();
    return true;
}

JSON_PARSE_TEST(json_incomplete_stringvalue_test1, "{\"a\":\"b")
{
    test_assert_json_incomplete();
    return true;
}

JSON_PARSE_TEST(json_incomplete_numbervalue_test, "{\"a\":-")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error, "no digits found");
    return true;
}

JSON_PARSE_TEST(json_incomplete_numbervalue_test1, "{\"a\":0.")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error, "no digits found");
    return true;
}

JSON_PARSE_TEST(json_invalid_numbervalue_test, "{\"a\":0..}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_invalid_booleanvalue_test, "{\"a\":truu}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_incomplete_array_test, "{\"a\":[")
{
    test_assert_json_incomplete();
    return true;
}

JSON_PARSE_TEST(json_invalid_array_test, "{\"a\":[{}b]}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_invalid_arrayelem_test, "{\"a\":[b]}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_incomplete_objvalue_test, "{\"a\":{")
{
    test_assert_json_incomplete();
    return true;
}

JSON_PARSE_TEST(json_longstring_test, "{\"abcdefghijklmnopqrstuvwxyz0123456789\":"
                                      "\"0123456789abcdefghijklmnopqrstuvwxyz\"}")
{
    test_no_errors();
    test_assert((root != NULL) && (tuple_count(root) == 1));

    string s = get_string(root, sym_this("abcdefghijklmnopqrstuvwxyz0123456789"));
    test_assert(s != NULL);
    test_strings_equal(s, "0123456789abcdefghijklmnopqrstuvwxyz");

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_invalid_name_test, "{a:{}}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_empty_name_test, "{\"\":{}}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_invalid_value_test, "{\"a\":}}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_invalid_last_attr_test, "{\"a\":{\"b\":\"c\"},\"d\":\"e\",\"f\"}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_invalid_last_separator_test, "{\"a\":{\"b\":\"c\"},\"d\":\"e\"-\"f\":{}}")
{
    test_assert(errors_count > 0);
    return true;
}

JSON_PARSE_TEST(json_empty_obj_test, "{}")
{
    test_no_errors();
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_numbervalue_test, "{\"a\":1}")
{
    test_no_errors();
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_numbervalue_test1, "{\"a\":1.2}")
{
    test_no_errors();
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_numbervalue_test2, "{\"a\":-2.3}")
{
    test_no_errors();
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_booleanvalue_test, "{\"a\":true}")
{
    test_no_errors();
    /* the parser discards boolean-valued attributes */
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_booleanvalue_test1, "{\"a\":false}")
{
    test_no_errors();
    /* the parser discards boolean-valued attributes */
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_booleanvalue_test2, "{\"a\":[true,false]}")
{
    test_no_errors();
    /* the parser discards array-valued attributes */
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_nullvalue_test, "{\"a\":null}")
{
    test_no_errors();
    /* the parser discards null-valued attributes */
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_empty_array_test, "{\"a\":[]}")
{
    test_no_errors();
    /* the parser discards boolean-valued attributes */
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_array_test, "{\"a\":[\"b\",{\"c\":{}},0]}")
{
    test_no_errors();
    /* the parser discards array-valued attributes */
    test_assert((root != NULL) && (tuple_count(root) == 0));

    destruct_value(root, true);
    return true;
}

JSON_PARSE_TEST(json_nested_test, "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{}}}}}}}}\n")
{
    test_no_errors();
    tuple t = root;
    char attr = 'a';
    sstring attr_name = isstring(&attr, sizeof(attr));
    for (int i = 0; i < 7; i++) {
        test_assert((t != NULL) && (tuple_count(t) == 1));
        t = get_tuple(t, sym_sstring(attr_name));
        attr = attr + 1;
    }
    test_assert((t != NULL) && (tuple_count(t) == 0));

    destruct_value(root, true);
    return true;
}

void init (heap h)
{
    tuple_p = value_parser(h, closure(h, finish, h), closure(h, perr, h));
    json_p = json_parser(h, closure(h, finish, h), closure(h, perr, h));
}

typedef boolean (*test_func)(heap h);

test_func TESTS[] = {
    empty_string_test,
    empty_tuple_test,
    empty_tuple_with_whitespaces_test,
    empty_vector_test,
    empty_vector_with_whitespaces_test,
    all_is_comment_test,
    partial_comment_test,
    tuple_simple_test,
    tuple_simple_spaced_test,
    vector_simple_test,
    tuple_2elements_test,
    vector_2elements_test,
    whitespace_after_last_vector_value_test,
    tuple_nested_tuple_test,
    vector_nested_tuple_test,
    tuple_nested_vector_test,
    vector_nested_vector_test,

    quoted_tuple_value_test,
    quoted_tuple_name_test,
    quoted_tuple_name_value_test,
    spaced_quoted_tuple_name_value_test,
    quoted_spaced_tuple_value_test,
    quoted_spaced_tuple_name_test,
    quoted_spaced_tuple_name_value_test,

    quoted_vector_value_test,
    quoted_spaced_vector_value_test,
    quoted_escaped_quote_vector_value_test,

    unknown_terminal_test,

    //crashing tests
    /* single_closing_tuple_bracket_test, */
    /* single_closing_vector_bracket_test, */

    json_whitespace_test,
    json_invalid_objstart_test,
    json_incomplete_obj_test,
    json_incomplete_name_test,
    json_incomplete_name_test1,
    json_missing_value_test,
    json_invalid_separator_test,
    json_invalid_separator_test1,
    json_incomplete_stringvalue_test,
    json_incomplete_stringvalue_test1,
    json_incomplete_numbervalue_test,
    json_incomplete_numbervalue_test1,
    json_invalid_numbervalue_test,
    json_invalid_booleanvalue_test,
    json_incomplete_array_test,
    json_invalid_array_test,
    json_invalid_arrayelem_test,
    json_incomplete_objvalue_test,
    json_longstring_test,
    json_invalid_name_test,
    json_empty_name_test,
    json_invalid_value_test,
    json_invalid_last_attr_test,
    json_invalid_last_separator_test,
    json_empty_obj_test,
    json_numbervalue_test,
    json_numbervalue_test1,
    json_numbervalue_test2,
    json_booleanvalue_test,
    json_booleanvalue_test1,
    json_booleanvalue_test2,
    json_nullvalue_test,
    json_empty_array_test,
    json_array_test,
    json_nested_test,

    NULL
};

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    init(h);

    boolean failure = false;

    for (int i = 0; TESTS[i]; ++i) {
        failure |= TESTS[i](h);
    }

    if (failure) {
        msg_err("Test failed\n"); exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
