#include <runtime.h>

char *
runtime_strchr (const char *string, int _c)
{
    char c = _c;

    for (;;) 
        if (*string == c)
            return (char *) string;
        else if (*string == '\0')
            return 0;
        else
            string ++;
}
    
char *
strtok_r (char *s, const char *delimiters, char **save_ptr)
{
    char *token;

    if (s == 0)
        s = *save_ptr;

    while (runtime_strchr(delimiters, *s) != 0) {
        if (*s == '\0') {
            *save_ptr = s;
            return 0;
        }

        s ++;
    }

    token = s;
    while (runtime_strchr(delimiters, *s) == 0)
        s ++;

    if (*s != '\0') {
        *s = '\0';
        *save_ptr = s + 1;
    } else 
        *save_ptr = s;

    return token;
}
