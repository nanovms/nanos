#include <runtime.h>
#include <log.h>

buffer allocate_buffer(heap h, bytes s)
{
    buffer b = allocate(h, sizeof(struct buffer));
    if (b == INVALID_ADDRESS)
        return b;
    void *contents = allocate(h, s);
    if (contents == INVALID_ADDRESS) {
        deallocate(h, b, sizeof(struct buffer));
        return INVALID_ADDRESS;
    }
    init_buffer(b, s, false, h, contents);
    return b;
}

bytes buffer_set_capacity(buffer b, bytes len)
{
    bytes old_len = b->length;
    if (buffer_is_wrapped(b))   /* wrapped buffers can't be resized */
        return old_len;
    bytes content_len = b->end - b->start;
    if (len < content_len)
        len = content_len;
    if (len != old_len) {
        void *new = allocate(b->h, len);
        if (new == INVALID_ADDRESS)
            return old_len;
        if (old_len) {
            runtime_memcpy(new, b->contents + b->start, content_len);
            deallocate(b->h, b->contents, old_len);
        }
        b->length = len;
        b->end = content_len;
        b->start = 0;
        b->contents = new;
    }
    return len;
}

boolean buffer_append(buffer b,
                     const void *body,
                     bytes length)
{
    if (!buffer_extend(b, length))
        return false;
    return buffer_write(b, body, length);
}

/* The string in the buffer may or may not be null-terminated. */
int buffer_compare_with_sstring(buffer b, sstring str)
{
    int res = buffer_memcmp(b, str.ptr, str.len);
    if (res)
        return res;
    bytes len = buffer_length(b);
    if ((len > str.len + 1) || ((len == str.len + 1) && (byte(b, str.len) != '\0')))
        return 1;
    return 0;
}

/* The string in the buffer may or may not be null-terminated. */
int buffer_compare_with_sstring_ci(buffer b, sstring str)
{
    bytes len = MIN(buffer_length(b), str.len);
    for (bytes i = 0; i < len; i++) {
        int res = tolower(byte(b, i)) - tolower(str.ptr[i]);
        if (res)
            return res;
    }
    len = buffer_length(b);
    if (len < str.len)
        return -1;
    if ((len > str.len + 1) || ((len == str.len + 1) && (byte(b, str.len) != '\0')))
        return 1;
    return 0;
}

int buffer_strstr(buffer b, sstring str) {
    for (int i = 0; b->start + i + str.len <= b->end; i++) {
        if (!runtime_memcmp(buffer_ref(b, i), str.ptr, str.len))
            return i;
    }
    return -1;
}

void buffer_print(buffer b)
{
    console_write(buffer_ref(b, 0), buffer_length(b));
    klog_write(buffer_ref(b, 0), buffer_length(b));
}
