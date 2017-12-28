#include <unistd.h>
#include <stdio.h>

int main()
{
    char hello_world[] = "Hello World!\n";
    write (1, hello_world, sizeof(hello_world)-1);
    printf ("me too!\n");
    return 0;
}
