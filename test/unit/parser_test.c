#include <runtime.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define COUNT_ELM   10

#define test_assert(expr) do { \
if (expr) ; else { \
    msg_err("%s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
    return false; \
} \
} while (0)

/* s2 must be null-terminated */
#define test_strings_equal(s1, s2) do {        \
if (strncmp(s1, s2, strlen(s2)) != 0) {                         \
    msg_err("\"%s\" != \"%s\" -- failed at %s:%d\n", s1, s2, __FILE__, __LINE__); \
    return false; \
} \
} while (0)

#define test_no_errors() do { \
    if (errors_count) { \
        msg_err("%d parse error(s), last: %b\n", errors_count, last_error); \
    } \
    test_assert(errors_count == 0); \
} while (0)

tuple root;
closure_function(1, 1, void, finish,
                 heap, h,
                 void *, v)
{
    root = v;
}

int errors_count = 0;
string last_error;

parser tuple_p;

closure_function(1, 1, void, perr,
                 heap, h,
                 string, s)
{
    errors_count++;
    if (last_error)
        deallocate_buffer(last_error);
    last_error = clone_buffer(bound(h), s);
}

void parse_string(heap h, parser p, char *str)
{
    root = NULL;
    errors_count = 0;
    if (last_error) {
        deallocate_buffer(last_error);
        last_error = NULL;
    }

    buffer b = wrap_buffer_cstring(h, str);
    parser_feed(p, b);
    /* deallocate_buffer(b); */
}

#define PARSE_TEST(name, p, str) \
    boolean _check_##name(heap h); \
\
    boolean name(heap h) \
    { \
        parse_string(h, p, str); \
\
        return !_check_##name(h); \
    } \
\
    boolean _check_##name(heap h)

#define TUPLE_PARSE_TEST(name, str) PARSE_TEST(name, tuple_p, str)

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
    test_assert(tuple_count(root) == 0);
    return true;
}

TUPLE_PARSE_TEST(empty_vector_with_whitespaces_test, " [ ] ")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 0);
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

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(tuple_simple_spaced_test, " ( key : value ) ")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(vector_simple_test, "[val1]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern_u64(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "val1");

    return true;
}

TUPLE_PARSE_TEST(tuple_2elements_test, "(key1:value1 key2:value2)")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 2);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "key1")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value1");
    deallocate_buffer(v1);

    buffer v2 = get_string(root, intern(wrap_buffer_cstring(h, "key2")));
    test_assert(v2 != NULL);
    test_strings_equal(v2->contents, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(vector_2elements_test, "[val1 val2]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 2);

    buffer v1 = get_string(root, intern_u64(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "val1");

    buffer v2 = get_string(root, intern_u64(1));
    test_assert(v2 != NULL);
    test_strings_equal(v2->contents, "val2");

    return true;
}

TUPLE_PARSE_TEST(whitespace_after_last_vector_value_test, "[val ]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 2);

    buffer v1 = get_string(root, intern_u64(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "val");

    buffer v2 = get_string(root, intern_u64(1));
    test_assert(v2 != NULL);
    test_strings_equal(v2->contents, "");

    return true;
}

TUPLE_PARSE_TEST(tuple_nested_tuple_test, "(key:(key2:value2))")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    tuple v1 = get_tuple(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_assert(tuple_count(v1) == 1);

    buffer v2 = get_string(v1, intern(wrap_buffer_cstring(h, "key2")));
    test_assert(v2 != NULL);
    test_strings_equal(v2->contents, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(vector_nested_tuple_test, "[(key2:value2)]")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    tuple v1 = get_tuple(root, intern_u64(0));
    test_assert(v1 != NULL);
    test_assert(tuple_count(v1) == 1);

    buffer v2 = get_string(v1, intern(wrap_buffer_cstring(h, "key2")));
    test_assert(v2 != NULL);
    test_strings_equal(v2->contents, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(tuple_nested_vector_test, "(key:[value2])")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    tuple v1 = get_tuple(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_assert(tuple_count(v1) == 1);

    buffer v2 = get_string(v1, intern_u64(0));
    test_assert(v2 != NULL);
    test_strings_equal(v2->contents, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(vector_nested_vector_test, "[[value2]]")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    tuple v1 = get_tuple(root, intern_u64(0));
    test_assert(v1 != NULL);
    test_assert(tuple_count(v1) == 1);

    buffer v2 = get_string(v1, intern_u64(0));
    test_assert(v2 != NULL);
    test_strings_equal(v2->contents, "value2");
    deallocate_buffer(v2);

    return true;
}

TUPLE_PARSE_TEST(quoted_tuple_value_test, "(key:\"value\")")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_tuple_name_test, "(\"key\":value)")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_tuple_name_value_test, "(\"key\":\"value\")")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(spaced_quoted_tuple_name_value_test, "( \"key\" : \"value\" )")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_spaced_tuple_value_test, "(key:\"hello value\")")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "hello value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_spaced_tuple_name_test, "(\"hello key\":value)")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "hello key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_spaced_tuple_name_value_test, "(\"hello key\":\"hello value\")")
{
    test_no_errors();

    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern(wrap_buffer_cstring(h, "hello key")));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "hello value");
    deallocate_buffer(v1);

    return true;
}

TUPLE_PARSE_TEST(quoted_vector_value_test, "[\"value\"]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern_u64(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "value");

    return true;
}

TUPLE_PARSE_TEST(quoted_spaced_vector_value_test, "[\"hello value\"]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern_u64(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "hello value");

    return true;
}

TUPLE_PARSE_TEST(quoted_escaped_quote_vector_value_test, "[\"hello \\\"value\\\"\"]")
{
    test_no_errors();
    test_assert(root != NULL);
    test_assert(tuple_count(root) == 1);

    buffer v1 = get_string(root, intern_u64(0));
    test_assert(v1 != NULL);
    test_strings_equal(v1->contents, "hello \"value\"");

    return true;
}

TUPLE_PARSE_TEST(unknown_terminal_test, "(key:value()")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error->contents, "unknown property discriminator 40");

    return true;
}

TUPLE_PARSE_TEST(single_closing_tuple_bracket_test, ")")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error->contents, "unknown property discriminator 40");

    return true;
}

TUPLE_PARSE_TEST(single_closing_vector_bracket_test, "]")
{
    test_assert(errors_count == 1);
    test_strings_equal(last_error->contents, "unknown property discriminator 40");

    return true;
}

void init (heap h)
{
    tuple_p = value_parser(h, closure(h, finish, h), closure(h, perr, h));
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
