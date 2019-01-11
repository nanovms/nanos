#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    printf("hello world!\n");
    printf("args:\n"); 
    for (int i = 0; i < argc; i++) printf ("   %s\n", argv[i]);
    return 0;
}

