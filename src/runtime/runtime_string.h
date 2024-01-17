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
