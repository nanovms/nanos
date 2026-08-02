char *runtime_strchr(sstring s, int c);
char *runtime_strrchr(sstring s, int c);
char *runtime_strstr(sstring haystack, sstring needle);
sstring runtime_strtok_r(sstring *str, sstring delim, sstring *saveptr);
int runtime_strcmp(sstring string1, sstring string2);

string wrap_string(void *body, bytes length);
string allocate_string(bytes size);
void init_strings(heap h, heap init);

#define deallocate_string deallocate_buffer

static inline string string_from_buf(void *x, bytes len)
{
    string s = allocate_string(len);
    buffer_assert(s != INVALID_ADDRESS);
    buffer_assert(buffer_append(s, x, len));
    return s;
}

static inline string wrap_string_sstring(sstring s)
{
    return string_from_buf(s.ptr, s.len);
}

#define wrap_string_cstring(x)  wrap_string_sstring(ss(x))

static inline boolean sstring_allocate(heap h, bytes len, sstring *s)
{
    s->ptr = allocate(h, len);
    if (s->ptr == INVALID_ADDRESS)
        return false;
    s->len = len;
    return true;
}

static inline void sstring_deallocate(heap h, sstring s)
{
    deallocate(h, s.ptr, s.len);
}
