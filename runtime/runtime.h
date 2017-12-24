typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
typedef u8 boolean;

extern void console(char *x);

extern void serial_out(char c);

void print_u64(u64 s);

/*
 * WARNING: these inserts seem to be very fragile wrt actually
 *          referring to the correct value by the right register
 */
#define mov_to_cr(__x, __y) __asm__("mov %0,%%"__x: :"r"(__y):);
#define mov_from_cr(__x, __y) __asm__("mov %%"__x", %0":"=r"(__y):);

#define pad(__x, __s) ((((__x) - 1) & (~((__s) - 1))) + (__s))

#include <io.h>
