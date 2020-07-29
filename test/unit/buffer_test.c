/* XXX TODO
*/

//#define ENABLE_MSG_DEBUG
#include <runtime.h>
#include <string.h>
#include <stdlib.h>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define test_assert(expr) do { \
if (expr) ; else { \
	msg_err("%s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
	goto fail; \
} \
} while (0)


boolean basic_tests(heap h)
{
    boolean failure = true;
    buffer wb = (buffer)0;
    u32 test_int;
    char test_str[] =  "This is a test string";
    buffer b = allocate_buffer(h, 10);
    /*
     * Validate buffer initialized correct, and some 
     * length is correct after write/read
     */
    test_assert(buffer_length(b) == 0);
    buffer_write_byte(b, 0xee);
    test_assert(buffer_length(b) == 1);
    test_assert(buffer_read_byte(b) == 0xee);
    test_assert(buffer_length(b) == 0);
    for (u8 i = 0; i < 3; i++) {
        push_u8(b, i);
    }
    for (u8 i = 0; i < 3; i++) {
        test_assert(pop_u8(b) == i);
    }
    buffer_write_le32(b, 0xdeadbeef);
    test_int = 0xdeadbeef - 1;
    test_assert(buffer_memcmp(b, &test_int, sizeof(test_int)) > 0);
    test_int = 0xdeadbeef + 1;
    test_assert(buffer_memcmp(b, &test_int, sizeof(test_int)) < 0);
    test_assert(buffer_read_le32(b) == 0xdeadbeef);
    push_varint(b, 0xdeadbeef);
    test_assert(pop_varint(b) == 0xdeadbeef);
    test_assert(buffer_length(b) == 0);
    test_assert(buffer_memcmp(b, test_str, 0) == 0);
    test_assert(buffer_strchr(b, '0') < 0);

    /* Buffer capacity */
    buffer_write_cstring(b, test_str);
    test_assert(buffer_set_capacity(b, 1) >= strlen(test_str));
    test_assert(buffer_set_capacity(b, b->length) == b->length);
    buffer_set_capacity(b, 3 * b->length);
    test_assert(buffer_compare_with_cstring(b, test_str));

    test_assert(buffer_strcmp(b, test_str) == 0);
    test_assert(buffer_memcmp(b, test_str, sizeof(test_str)) < 0);
    test_assert(buffer_strchr(b, 't') == 10);
    test_assert(buffer_strchr(b, 'u') < 0);

    /* Create and then deallocate a wrapped buffer. */
    deallocate_buffer(wrap_buffer_cstring(h, test_str));

    /*
     * Validate wrap_buffer_cstring initialization, and contents
     */
    wb = wrap_buffer_cstring(h, test_str);
    // Note, compiler adds a '\0' to array so sizeof array will be 1 more than string
    test_assert(buffer_length(wb) == (sizeof(test_str) - 1));
    test_assert(strcmp(buffer_ref(wb,0),test_str) == 0);
    failure = false;
  fail:
    if (wb) unwrap_buffer(h, wb);
    deallocate_buffer(b);
    return failure;
}

boolean byteorder_tests(heap h)
{
    boolean failure = true;
    buffer b = allocate_buffer(h, 10);
    test_assert(buffer_length(b) == 0);

    // Validate le/be intrfaces
    buffer_write_le64(b, 0x11223344deadbeef);
    test_assert(buffer_length(b) == 8);
    test_assert(buffer_read_le32(b) == 0xdeadbeef);
    test_assert(buffer_read_le32(b) == 0x11223344);
    // write value after convering to be
    buffer_write_be64(b, 0x11223344deadbeef);
    test_assert(buffer_length(b) == 8);
    // Read back 32-bits in LE and compare
    test_assert(buffer_read_le32(b) == 0x44332211);
    // Read back 32-bits in BE and compare
    test_assert(buffer_read_be32(b) == 0xdeadbeef);
    failure = false;
  fail:
    deallocate_buffer(b);
    return failure;
}

boolean concat_tests(heap h)
{
    int seed_size = 0x4000;
    boolean failure = true;
    buffer wb = (buffer)0;
    buffer b = allocate_buffer(h, 10);

    // Allocating and initializing a buffer with random data as source data
    buffer seed_buffer = allocate_buffer(h, seed_size);
    test_assert(seed_buffer->length == seed_size);
    // getrandom() uses buffer_length() to determine how much data to fill. We are
    // using buffer_produce() to set the amount of data in buffer, so getrandom() will 
    // initialize/fill the allocated size
    buffer_produce(seed_buffer, seed_size);
    test_assert(random_buffer(seed_buffer) == seed_size);
    test_assert(seed_buffer->length == seed_size);

    // append small chucks of source buffer to test buffer and validate buffer_length()
    buffer_append(b, buffer_ref(seed_buffer,0), 4);
    test_assert(buffer_length(b) == 4);
    buffer_append(b, buffer_ref(seed_buffer,4), 4);
    test_assert(buffer_length(b) == 8);

    // validate sub_buffer functionality by creating a sub-buffer of the small portion
    // of source buffer we just wrote to test buffer
    wb = sub_buffer(h, seed_buffer, 0, 8);
    // validate buffer_compare() by comparing these 2 buffers
    test_assert(buffer_compare(b, wb) == true);

    // corrupt source-buffer/sub-buffer
    char *tmpp = (char *)buffer_ref(seed_buffer,3);
    char tmp = *tmpp;
    *tmpp = ~tmp;
    // validate same buffers DO NOT compare
    test_assert(buffer_compare(b, wb) == false);
    // uncorrupt source-buffer/sub-buffer
    *tmpp = tmp;

    unwrap_buffer(h, wb);
    wb = (buffer)0;
    deallocate_buffer(b);

    // initialize a very small buffer so we can be certain buffer will
    // extend when we write.
    b = allocate_buffer(h, 1);
    int offset = 0;
    int size;
    // write into buffer with various sized chunks from source-buffer
    // keep track of offset into source-buffer, and make sure we don't 
    // read beyond source-buffer
    for (size = 1, offset = 0; offset < seed_size; size <<= 1) {
	
	    int current_length = buffer_length(b);
	    if (current_length + size > seed_size)
		    size = seed_size - current_length;

        //void * prev = buffer_ref(b, current_length);;

	    buffer_write(b, buffer_ref(seed_buffer, offset), size);
    	test_assert(buffer_length(b) == (size + current_length));
    	wb = sub_buffer(h, seed_buffer, 0,  offset + size);
    	test_assert(buffer_compare(b, wb) == true);
	    unwrap_buffer(h, wb);
	    wb = (buffer)0;

	    offset += size;
  }
  // end result in a round about way, all of source-buffer has been written to test-buffer
  // validate they match
  test_assert(buffer_compare(b, seed_buffer) == true);
  failure = false;
  fail:
    if (wb) unwrap_buffer(h, wb);
    deallocate_buffer(b);
    deallocate_buffer(seed_buffer);
    return failure;
}

#define VBPRINTF_TEST(b, orig, fmt, ...)                                                 \
    do {                                                                                 \
        buffer_clear(b);                                                                 \
        bbprintf(b, alloca_wrap_buffer(fmt, runtime_strlen(fmt)), ##__VA_ARGS__);        \
        test_assert(buffer_compare(b, alloca_wrap_buffer(orig, runtime_strlen(orig))));  \
    } while (0)

boolean vbprintf_tests(heap h)
{
    boolean failure = true;
    buffer b = allocate_buffer(h, 10);

    // %s
    VBPRINTF_TEST(b, "hello, world", "%s", "hello, world");
    VBPRINTF_TEST(b, "(null)", "%s", "(null)");

    // %p
    void *p = (void *) 0x123456780000;
    VBPRINTF_TEST(b, "0x0000123456780000", "%p", p);

    // System V AMD64 ABI calling convention:
    // the first six integer or pointer arguments are passed in registers
    //
    // first two arguments of bbprintf() are buffer and format
    // so add 4 more dummy arguments to test va_arg() stack arguments

    // %c
    VBPRINTF_TEST(b, "xxxxab", "%c%c%c%c%c%c", 'x', 'x', 'x', 'x', 'a', 'b');

    // %d
    u8 x = 12;
    u16 y = 3456;
    int z = 7890;
    VBPRINTF_TEST(b, "0 0 0 0 12 3456 7890", "%d %d %d %d %d %d %d", 0, 0, 0, 0, x, y, z);
    VBPRINTF_TEST(b, "0 0 0 0 1234 -42", "%d %d %d %d %ld %d", 0, 0, 0, 0, 1234l, -42);

    // %x
    u64 w = 0x1122334455667788;
    VBPRINTF_TEST(b, "0 0 0 0 1234 0x1122334455667788 0xffffffff", "%x %x %x %x %x 0x%lx 0x%x", 0, 0, 0, 0, 0x1234, w, -1);

    // invalid format
    VBPRINTF_TEST(b, "[invalid format %y]", "%y", 0);
    VBPRINTF_TEST(b, "[invalid format %ls]", "%ls", 0);

    failure = false;

fail:
    deallocate_buffer(b);
    return failure;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    int failure = 0;

    failure |= basic_tests(h);
    failure |= byteorder_tests(h);
    failure |= concat_tests(h);
    failure |= vbprintf_tests(h);

    if (failure) {
        msg_err("Test failed\n");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
