#include <runtime.h>

static heap stringheap;

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
runtime_strstr(const char *haystack, const char *needle)
{
    const char *haystack_p = haystack;
    const char *needle_p = needle;
    while (*haystack_p && *needle_p) {
        if (*needle_p == *haystack_p) {
            needle_p++;
            haystack_p++;
        } else {
            needle_p = needle;
            haystack_p = ++haystack;
        }
    }
    if (!*needle_p)
        return (char *)haystack;
    else
        return 0;
}

char *
runtime_strtok_r (char *s, const char *delimiters, char **save_ptr)
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

int
runtime_strcmp (const char *string1, const char *string2)
{
    while (*string1 && *string1 == *string2) {
        string1++;
        string2++;
    }

    return *(const unsigned char *)string1 - *(const unsigned char *)string2;
}

string wrap_string(void *body, bytes length)
{
    string new = allocate(stringheap, sizeof(struct buffer));
    if (new == INVALID_ADDRESS)
        return new;
    new->contents = body;
    new->start = 0;
    new->h = stringheap;
    new->end = length;
    new->length = length;
    new->wrapped = true;
    return new;
}

string allocate_string(bytes size)
{
    return allocate_buffer(stringheap, size);
}

void init_strings(heap h, heap init)
{
    stringheap = h;
}
