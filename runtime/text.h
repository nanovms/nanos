// would like to call this string.h, but unix programs
// are pretty stubborn, in this case lwip

typedef buffer string;

static inline s8 digit_of(character x)
{
    if ((x <= 'f') && (x >= 'a')) return(x - 'a' + 10);
    if ((x <= 'F') && (x >= 'A')) return(x - 'A' + 10);
    if ((x <= '9') && (x >= '0')) return(x - '0');
    return(-1);
}


static inline bytes utf8_length(unsigned char x)
{
    if (~x & 0x80) return 1;
    if ((x & 0xe0) == 0xc0) return 2;
    if ((x & 0xf0) == 0xe0) return 3;
    if ((x & 0xf8) == 0xf0) return 4;
    // help
    return(1);
}

// this is not the most effective implementation
static int inline string_character_length(char *s) {
    int i = 0, j= 0;
    while (s[i]) {
        if ((s[i] & 0xC0) != 0x80)
            j++;
        i++;
    }
    return (j);
}

// specialized bytewise memcpy, since this is between 1 and 4

#define string_foreach(__i, __s)                                    \
    for (u32 __x = 0, *__t, __q, __i, __limit = buffer_length(__s);       \
         __i = 0, __t = (u32 *)buffer_ref(__s, __x), __q = utf8_length(*__t),   \
             runtime_memcpy(&__i, __t, __q),                              \
             __i = __builtin_bswap32(__i),                                \
             __i = __i >> 8 * (4 - __q),                                  \
             __x<__limit;                                                 \
         __x += __q)


static inline character utf8_decode(u8 *x, int *count)
{
    if ((x[0] & 0xf0) == 0xf0) {
        *count = 4;
        return ((x[0] & 0xf) << 18)
            | ((x[1]&0x3f)<< 12)
            | ((x[2]&0x3f)<< 6)
            | (x[3]&0x3f);
    }
    
    if ((x[0] & 0xe0) == 0xe0) {
        *count = 3;
        return ((x[0] & 0x1f) << 12)
            | ((x[1]&0x3f)<< 6)
            | (x[2]&0x3f);
    }
    
    if ((x[0] & 0xc0) == 0xc0) {
        *count = 2;
        return ((x[0] & 0x3f) << 6)
            | (x[1]&0x3f);
    }
    
    *count = 1;
    return *x;
}


static inline void push_character(string s, character c)
{
    if (c<0x80) {
        buffer_write_byte(s, c);
    } else if (c<0x800) {
        buffer_write_byte(s, 0xc0 | (c>>6));
        buffer_write_byte(s, 0x80 | (c&0x3f));
    } else if (c<0x10000) {
        buffer_write_byte(s, 0xe0 | (c>>12));
        buffer_write_byte(s, 0x80 | ((c>>6) & 0x3f));
        buffer_write_byte(s, 0x80 | (c&0x3f));
    } else if (c<0x110000) {
        buffer_write_byte(s, 0xf0 | (c>>18));
        buffer_write_byte(s, 0x80 | ((c>>12)&0x3f));
        buffer_write_byte(s, 0x80 | ((c>>6)&0x3f));
        buffer_write_byte(s, 0x80 | (c&0x3f));
    }
}

// xxx - check
#define CHARACTER_INVALID 0xfffffffful

// duplicate work for length
static inline character pop_character(buffer b)
{
    if (buffer_length(b) == 0) return CHARACTER_INVALID;
    bytes len = utf8_length(*(u8 *)buffer_ref(b, 0));
    if (buffer_length(b) < len) return CHARACTER_INVALID;
    int z;
    character c = utf8_decode(buffer_ref(b, 0), &z);
    b->start += len;
    return c;
}


// status
static inline boolean parse_int(buffer b, u32 base, u64 *result)
{
  int hexValue;
  int st = false;
  *result = 0;

  while (buffer_length(b)) {
      s8 v = digit_of(*(u8 *)buffer_ref(b, 0));
      if (v >= 0) {
          pop_u8(b);
          st = true;
          *result = (*result * base) + v;
      } else break;
  }
  return st;
}
