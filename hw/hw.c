#include <stdio.h>
#include <unistd.h>

void main(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
        printf("hello world! %s\n", argv[i]);
}

