#include <runtime.h>

static heap stringheap;

char *runtime_strchr(sstring s, int c)
{
    sstring_foreach(i, si, s)
        if (si == c)
            return s.ptr + i;
    return 0;
}

char *runtime_strrchr(sstring s, int c)
{
    for (bytes i = s.len; i > 0; i--) {
        char *p = s.ptr + i - 1;
        if (*p == c)
            return p;
    }
    return 0;
}

char *runtime_strstr(sstring haystack, sstring needle)
{
    if (needle.len > haystack.len)
        return 0;
    bytes limit = haystack.len - needle.len;
    for (bytes i = 0; i <= limit; i++)
        if (!runtime_memcmp(haystack.ptr + i, needle.ptr, needle.len))
            return (haystack.ptr + i);
    return 0;
}

sstring runtime_strtok_r(sstring *str, sstring delim, sstring *saveptr)
{
    if (str != 0)
        *saveptr = *str;

    bytes offset = 0;
    while ((offset < saveptr->len) && (runtime_strchr(delim, saveptr->ptr[offset]) != 0))
        offset++;
    if (offset == saveptr->len)
        return sstring_null();

    sstring token = {
        .ptr = saveptr->ptr + offset,
    };
    while ((offset < saveptr->len) && (runtime_strchr(delim, saveptr->ptr[offset]) == 0))
        offset++;
    token.len = offset - (token.ptr - saveptr->ptr);
    saveptr->ptr += offset;
    saveptr->len -= offset;

    return token;
}

int runtime_strcmp(sstring string1, sstring string2)
{
    if (string1.len != string2.len)
        return (string1.len - string2.len);

    return runtime_memcmp(string1.ptr, string2.ptr, string1.len);
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
