#include <runtime.h>

#include "xml.h"

boolean xml_get_elem(buffer b, sstring name, xml_elem elem)
{
    bytes initial_buf_start = b->start;
    boolean success = false;
    int index;
    while (1) {
        index = buffer_strchr(b, '<');
        if (index < 0)
            goto done;
        buffer_consume(b, index + 1);
        if (buffer_memcmp(b, name.ptr, name.len))
            continue;
        buffer_consume(b, name.len);
        if (buffer_length(b) == 0)
            goto done;
        char c = byte(b, 0);
        if ((c != '>') && (c != ' '))
            continue;
        elem->start = b->start - initial_buf_start;
        index = buffer_strchr(b, '>');
        if (index < 0)
            goto done;
        buffer_consume(b, index + 1);
        elem->data_start = b->start - initial_buf_start;
        break;
    }
    while (1) {
        index = buffer_strstr(b, ss("</"));
        if (index < 0)
            goto done;
        buffer_consume(b, index + sizeof("</") - 1);
        if (!buffer_memcmp(b, name.ptr, name.len) && (buffer_length(b) > name.len) &&
            (byte(b, name.len) == '>')) {
            elem->data_len = b->start - (sizeof("</") - 1) - initial_buf_start - elem->data_start;
            elem->len = b->start + name.len + 1 - initial_buf_start - elem->start;
            success = true;
            break;
        }
    }
  done:
    b->start = initial_buf_start;
    return success;
}

boolean xml_elem_get_attr(buffer b, xml_elem elem, sstring name, bytes *start, bytes *len)
{
    bytes initial_buf_start = b->start;
    boolean success = false;
    buffer_consume(b, elem->start); /* elem->start points to the end of the element name */
    while (true) {
        if (pop_u8(b) != ' ')
            goto done;
        int name_len = buffer_strchr(b, '=');
        if ((name_len < 0) || (b->start + name_len >= initial_buf_start + elem->data_start))
            goto done;
        if ((name_len != name.len) || buffer_memcmp(b, name.ptr, name.len))
            continue;
        buffer_consume(b, name.len + 1);
        break;
    }
    if (pop_u8(b) != '"')
        goto done;
    int value_len = buffer_strchr(b, '"');
    if ((value_len < 0) || (b->start + value_len >= initial_buf_start + elem->data_start))
        goto done;
    *start = b->start - initial_buf_start;
    *len = value_len;
    success = true;
  done:
    b->start = initial_buf_start;
    return success;
}
