#include <runtime.h>

buffer allocate_buffer(heap h, bytes s)
{
    buffer b = allocate(h, sizeof(struct buffer));
    if (b == INVALID_ADDRESS)
        return b;
    b->start = 0;
    b->end = 0;
    b->length = s;
    b->wrapped = false;
    b->h = h;
    b->contents = allocate(h, s);
    if (b->contents == INVALID_ADDRESS) {
        deallocate(h, b, sizeof(struct buffer));
        return INVALID_ADDRESS;
    }
    return b;
}
KLIB_EXPORT(allocate_buffer);

boolean kern_buffer_write(buffer b, const void *source, bytes length)
{
    return buffer_write(b, source, length);
}
KLIB_EXPORT_RENAME(kern_buffer_write, buffer_write);

boolean kern_buffer_read(buffer b, void *dest, bytes length)
{
    return buffer_read(b, dest, length);
}
KLIB_EXPORT_RENAME(kern_buffer_read, buffer_read);

boolean buffer_append(buffer b,
                     const void *body,
                     bytes length)
{
    if (!buffer_extend(b, length))
        return false;
    return buffer_write(b, body, length);
}

int buffer_strstr(buffer b, const char *str) {
    int len = runtime_strlen(str);
    for (int i = 0; b->start + i + len <= b->end; i++) {
        if (!runtime_memcmp(buffer_ref(b, i), str, len))
            return i;
    }
    return -1;
}
KLIB_EXPORT(buffer_strstr);
