#ifndef XML_H_
#define XML_H_

typedef struct xml_elem {
    bytes start, len;
    bytes data_start, data_len;
} *xml_elem;

boolean xml_get_elem(buffer b, sstring name, xml_elem elem);
boolean xml_elem_get_attr(buffer b, xml_elem elem, sstring name, bytes *start, bytes *len);

#endif
