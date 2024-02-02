#ifndef _TEST_UTILS_H_
#define _TEST_UTILS_H_

#include <stdio.h>
#include <stdlib.h>

#define FAULT_ADDR  ((void *)0xBADF0000)

#define test_assert(expr) do {                                                          \
    if (!(expr)) {                                                                      \
        fprintf(stderr, "Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__);   \
        exit(EXIT_FAILURE);                                                             \
    }                                                                                   \
} while (0)

#define test_error(msg, ...) do {                                                       \
    fprintf(stderr, "Error at %s:%d: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__);    \
    exit(EXIT_FAILURE);                                                                 \
} while (0)

#define test_perror(msg, ...) do {                                                      \
    fprintf(stderr, "Error at %s:%d: " msg ": " , __FILE__, __LINE__, ##__VA_ARGS__);   \
    perror(NULL);                                                                       \
    exit(EXIT_FAILURE);                                                                 \
} while (0)

#endif
