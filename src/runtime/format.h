#pragma once
extern void vbprintf(buffer s, buffer fmt, vlist *ap);

extern void log_vprintf(char * prefix, char * log_format, vlist *a);
extern void log_printf(char * prefix, char * log_format, ...);

// make sure its safe to read more than one format char ala %02x
// if we parameterize newline we can do some nicer formatting tricks
typedef void (*formatter)(buffer dest, buffer fmt, vlist *ap);
void register_format(character c, formatter f);
// indent?

buffer aprintf(heap h, char *fmt, ...);
void bbprintf(buffer b, buffer fmt, ...);
void bprintf(buffer b, char *fmt, ...);
void rprintf(char *format, ...);


