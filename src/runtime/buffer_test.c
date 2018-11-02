#include <runtime_test.h>

boolean test_buffer() {
    const char *dest = "bla";
    buffer b = alloca_wrap_buffer(dest, runtime_strlen(dest));
    if (buffer_length(b) != 3){
        halt("test_bitmap:buffer_length != 3\n");
    }
    console("PASSED:test_buffer\n");
    return true;
}

boolean test_pqueue(){
    return true;
}
