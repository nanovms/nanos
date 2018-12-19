/* XXX TODO
*/

//#define ENABLE_MSG_DEBUG
#include <runtime.h>
//#include <stdlib.h>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define nanovm_assert(expr) do { \
if (expr) ; else { \
	msg_err("%s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
	goto fail; \
} \
} while (0)


boolean basic_tests(heap h)
{
    boolean failure = true;
    static buffer wb = (buffer)0;
    buffer b = allocate_buffer(h, 10);
    nanovm_assert(buffer_length(b) == 0);
    buffer_write_byte(b, 0xee);
    nanovm_assert(buffer_length(b) == 1);
    nanovm_assert(buffer_read_byte(b) == 0xee);
    nanovm_assert(buffer_length(b) == 0);
    wb = wrap_buffer_cstring(h, "This is a test string");
    nanovm_assert(buffer_length(wb) == runtime_strlen("This is a test string"));
    nanovm_assert(strcmp(buffer_ref(wb,0),"This is a test string") == 0);
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
    nanovm_assert(buffer_length(b) == 0);

    buffer_write_le64(b, 0x11223344deadbeef);
    nanovm_assert(buffer_length(b) == 8);
    nanovm_assert(buffer_read_le32(b) == 0xdeadbeef);
    nanovm_assert(buffer_read_le32(b) == 0x11223344);
    buffer_write_be64(b, 0x11223344deadbeef);
    nanovm_assert(buffer_length(b) == 8);
    nanovm_assert(buffer_read_le32(b) == 0x44332211);
    nanovm_assert(buffer_read_be32(b) == 0xdeadbeef);
    failure = false;
  fail:
    deallocate_buffer(b);
    return failure;
}

boolean concat_tests(heap h)
{
    
    int seed_size = 0x4000;
    boolean failure = true;
    static buffer wb = (buffer)0;
    buffer b = allocate_buffer(h, 10);

    buffer seed_buffer = allocate_buffer(h, seed_size);
    nanovm_assert(seed_buffer->length == seed_size);
    buffer_produce(seed_buffer, seed_size);
    nanovm_assert(do_getrandom(seed_buffer, seed_size) == seed_size);
    nanovm_assert(seed_buffer->length == seed_size);

    buffer_append(b, buffer_ref(seed_buffer,0), 4);
    nanovm_assert(buffer_length(b) == 4);
    buffer_append(b, buffer_ref(seed_buffer,4), 4);
    nanovm_assert(buffer_length(b) == 8);

    wb = sub_buffer(h, seed_buffer, 0, 8);
    nanovm_assert(buffer_compare(b, wb) == true);

    char *tmpp = (char *)buffer_ref(seed_buffer,3);
    char tmp = *tmpp;
    *tmpp = ~tmp;
    nanovm_assert(buffer_compare(b, wb) == false);
    *tmpp = tmp;

    unwrap_buffer(h, wb);
    wb = (buffer)0;
    deallocate_buffer(b);
    b = allocate_buffer(h, 1);
    int offset = 0;
    int size;
    for (size = 1, offset = 0; offset < seed_size; size <<= 1) {
	
	int current_length = buffer_length(b);
	if (current_length + size > seed_size)
		size = seed_size - current_length;

        void * prev = buffer_ref(b, current_length);;

	buffer_write(b, buffer_ref(seed_buffer, offset), size);
    	nanovm_assert(buffer_length(b) == (size + current_length));
    	wb = sub_buffer(h, seed_buffer, 0,  offset + size);
    	nanovm_assert(buffer_compare(b, wb) == true);
	unwrap_buffer(h, wb);
	wb = (buffer)0;

	offset += size;
  }
  nanovm_assert(buffer_compare(b, seed_buffer) == true);
  failure = false;
  fail:
    if (wb) unwrap_buffer(h, wb);
    deallocate_buffer(b);
    deallocate_buffer(seed_buffer);
    return failure;
}


int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    int failure = 0;

    failure |= basic_tests(h);
    failure |= byteorder_tests(h);
    failure |= concat_tests(h);

    if (failure) {
        msg_err("Test failed\n");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
