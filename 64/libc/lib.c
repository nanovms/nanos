#include <unistd.h>
#include <runtime.h>

extern void main();
    
void write(int fd, void *source, size_t length)
{
    unsigned char *s = source;
    for (int i = 0; i< length; i++) {
        serial_out(s[i]);
    }
}
