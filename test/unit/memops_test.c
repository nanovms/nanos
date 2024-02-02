#include <runtime.h>

#include "../test_utils.h"

#define MEM_BUF_SIZE    512

static void test_memcpy(long *buf1, long *buf2, unsigned long buf_size)
{
    for (long i = 0; i < buf_size; i++) {
        buf1[i] = buf_size - i;
    }

    runtime_memcpy(buf2, buf1, sizeof(long) - 1);
    test_assert(runtime_memcmp(buf1, buf2, sizeof(long) - 1) == 0);

    runtime_memcpy(buf2 + 1, buf1, sizeof(long));
    test_assert(runtime_memcmp(buf1, buf2 + 1, sizeof(long)) == 0);

    runtime_memcpy((u8 *)(buf2 + 2) + 1, buf1, sizeof(long));
    test_assert(runtime_memcmp(buf1, (u8 *)(buf2 + 2) + 1, sizeof(long)) == 0);

    for (long i = 0; i < sizeof(long); i++) {
        for (long j = 0; j < sizeof(long); j++) {
            runtime_memcpy((u8 *)buf2 + i, (u8 *)buf1 + j,
                    (buf_size - 1) * sizeof(long));
            test_assert(runtime_memcmp((u8 *)buf1 + j, (u8 *)buf2 + i,
                    (buf_size - 1) * sizeof(long)) == 0);
        }
    }
}

static void test_memcpy_overlap(long *buf, unsigned long buf_size)
{
    for (long i = 0; i < buf_size; i++) {
        buf[i] = i;
    }

    runtime_memcpy(buf, buf + 1, (buf_size - 1) * sizeof(long));
    for (long i = 0; i < buf_size - 1; i++) {
        test_assert(buf[i] == i + 1);
    }

    long first_word = 0, last_word = 0;
    for (int i = 0; i < sizeof(first_word); i++) {
        *((u8 *)&first_word + i) = *((u8 *)buf + 1 + i);
    }
    for (int i = 0; i < sizeof(last_word) - 1; i++) {
        *((u8 *)&last_word + i) =
                *((u8 *)buf + (buf_size - 1) * sizeof(long) + 1 + i);
    }
    *((u8 *)&last_word + sizeof(last_word) - 1) =
            *((u8 *)buf + buf_size * sizeof(long) - 1);
    runtime_memcpy(buf, (u8 *)buf + 1, buf_size * sizeof(long) - 1);
    test_assert(buf[0] == first_word);
    test_assert(buf[buf_size - 1] == last_word);

    *((u8 *)&first_word) = *((u8 *)buf);
    for (int i = 1; i < sizeof(first_word); i++) {
        *((u8 *)&first_word + i) = *((u8 *)buf + i - 1);
    }
    for (int i = 0; i < sizeof(last_word); i++) {
        *((u8 *)&last_word + i) =
                *((u8 *)buf + (buf_size - 1) * sizeof(long) + i - 1);
    }
    runtime_memcpy((u8 *)buf + 1, buf, buf_size * sizeof(long) - 1);
    test_assert(buf[0] == first_word);
    test_assert(buf[buf_size - 1] == last_word);
}

static void test_memset(long *buf, unsigned long buf_size)
{
    runtime_memset((u8 *)buf, 0xAA, sizeof(long) - 1);
    for (int i = 0; i < sizeof(long) - 1; i++) {
        test_assert(*((u8 *)buf + i) == 0xAA);
    }

    runtime_memset((u8 *)buf + 1, 0xBB, sizeof(long));
    for (int i = 0; i < sizeof(long); i++) {
        test_assert(*((u8 *)buf + 1 + i) == 0xBB);
    }

    runtime_memset((u8 *)buf + 3, 0xCC, (buf_size - 1) * sizeof(long));
    for (int i = 0; i < (buf_size - 1) * sizeof(long); i++) {
        test_assert(*((u8 *)buf + 3 + i) == 0xCC);
    }
}

static void test_memcmp(long *buf, unsigned long buf_size)
{
    for (long i = 0; i < buf_size; i++) {
        buf[i] = i;
    }
    test_assert(runtime_memcmp(buf, buf, sizeof(long) - 1) == 0);
    test_assert(runtime_memcmp(buf, buf + 1, sizeof(long) - 1) != 0);
    test_assert(runtime_memcmp(buf, (u8 *)buf + 1, sizeof(long)) != 0);
    test_assert(runtime_memcmp((u8 *)buf + 1, buf, sizeof(long)) != 0);
    test_assert(runtime_memcmp((u8 *)buf + 1, (u8 *)buf + 3,
            sizeof(long)) != 0);
    test_assert(runtime_memcmp((u8 *)buf + 3, (u8 *)buf + 1,
            sizeof(long)) != 0);
    test_assert(runtime_memcmp(buf, buf + 1, sizeof(long)) != 0);
    test_assert(runtime_memcmp(buf, buf, buf_size * sizeof(long)) == 0);
}

int main(int argc, char *argv[])
{
    long buf1[MEM_BUF_SIZE], buf2[MEM_BUF_SIZE];

    init_process_runtime();
    test_memcpy(buf1, buf2, MEM_BUF_SIZE);
    test_memcpy(buf2, buf1, MEM_BUF_SIZE);
    test_memcpy_overlap(buf1, MEM_BUF_SIZE);
    test_memset(buf1, MEM_BUF_SIZE);
    test_memcmp(buf1, MEM_BUF_SIZE);
    return 0;
}
