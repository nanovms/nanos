char *runtime_strchr(const char *, int);
char *runtime_strstr(const char *haystack, const char *needle);
char *runtime_strtok_r(char *, const char *, char **);
int runtime_strcmp(const char *, const char *);

string wrap_string(void *body, bytes length);
string allocate_string(bytes size);
void init_strings(heap h, heap init);

#define deallocate_string deallocate_buffer

static inline buffer wrap_string_cstring(char *x)
{
    return wrap_string(x, runtime_strlen(x));
}

static inline string string_from_cstring(const char *x)
{
    int len = runtime_strlen(x);
    string s = allocate_string(len);
    buffer_assert(s != INVALID_ADDRESS);
    buffer_assert(buffer_append(s, x, len));
    return s;
}
