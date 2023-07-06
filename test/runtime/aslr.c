#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    volatile int stack_variable;
    void *heap_pointer = malloc(64);
    printf("{ 'main':%p, 'library':%p, 'heap':%p, 'stack':%p }\n", main, malloc, heap_pointer, &stack_variable);
    return 0;
}
